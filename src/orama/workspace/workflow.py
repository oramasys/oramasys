"""Bounded offline artifact chain; no provider, network, or filesystem effects."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import uuid
from datetime import datetime, timezone
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from orama.workspace.verify import verify_artifact

Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=12000)]
ShortText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=500)]
SourceId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")]
Privacy = Literal["local", "sources", "redacted", "open"]
Kind = Literal["primary", "secondary", "unverified"]
COLUMNS = ("claim", "source_id", "source_title", "quote")
PRIVACY_PROFILES = {
    "local": "No external disclosure",
    "sources": "Public source queries only; never private document text",
    "redacted": "Only user-reviewed redacted excerpts",
    "open": "User permits full selected task inputs",
}
LIMITATIONS = [
    "Exact extractive attribution only; no real-world fact checking or semantic entailment.",
    "Source quality is declared by the user, not independently authenticated.",
    "No model, web retrieval, external sharing, durable replay, or server retention.",
    "Receipt hashes are unsigned integrity checks, not proof of authorship.",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Source(StrictModel):
    id: SourceId
    title: ShortText
    passage: Text
    kind: Kind = "unverified"


class Record(StrictModel):
    claim: Text
    source_id: SourceId
    quote: Text


def safe_cell(value: str) -> bool:
    """Reject formula-capable leading cells, including whitespace prefixes."""
    return not value.lstrip().startswith(("=", "+", "-", "@")) and "\x00" not in value


class WorkspaceTask(StrictModel):
    task: ShortText
    privacy: Privacy = "local"
    sources: list[Source] = Field(min_length=1, max_length=32)
    records: list[Record] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def grounded_records(self):
        sources = {source.id: source for source in self.sources}
        if len(sources) != len(self.sources):
            raise ValueError("duplicate_source_id")
        for record in self.records:
            source = sources.get(record.source_id)
            if source is None or record.quote not in source.passage:
                raise ValueError("unsupported_quote")
            if record.claim != record.quote:
                raise ValueError("extractive_claim_required")
            if not all(safe_cell(cell) for cell in
                       (record.claim, record.source_id, source.title, record.quote)):
                raise ValueError("unsafe_spreadsheet_cell")
        return self


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def run_task(task: WorkspaceTask) -> dict:
    """Materialize and separately reparse a bounded CSV entirely in memory."""
    source_map = {source.id: source for source in task.sources}
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(COLUMNS)
    for record in task.records:
        writer.writerow((record.claim, record.source_id,
                         source_map[record.source_id].title, record.quote))
    csv_text = output.getvalue()
    run_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    ranks = {"primary": 1, "secondary": 2, "unverified": 3}
    sources = [
        {**source.model_dump(), "rank": ranks[source.kind],
         "passage_sha256": digest(source.passage)}
        for source in sorted(task.sources, key=lambda source: ranks[source.kind])
    ]
    receipt = {
        "schema_version": "workspace-artifact-v1",
        "implementation": "oramasys/offline-poc-1",
        "run_id": run_id, "created_at": created_at,
        "task": task.task, "privacy": task.privacy,
        "requested_disclosure": PRIVACY_PROFILES[task.privacy],
        "actual_disclosure": "none", "execution": "offline-deterministic",
        "sources": sources, "records": [record.model_dump() for record in task.records],
        "input_sha256": digest(canonical_json(task.model_dump())),
        "artifact_sha256": digest(csv_text), "row_count": len(task.records),
        "limitations": LIMITATIONS,
    }
    verified = verify_artifact(csv_text, receipt)
    if not verified["passed"]:
        raise ValueError("artifact_verification_failed")
    receipt["checks"] = verified["checks"]
    receipt_json = canonical_json(receipt)
    # Same observation-only OpenClaw message envelope as the PT Periscope adapter.
    # No emitter is called: privacy defaults cannot be overridden by global telemetry flags.
    observation = {
        "type": "message", "id": run_id, "timestamp": created_at,
        "message": {"role": "assistant", "timestamp": created_at,
                    "content": [{"type": "text", "text": canonical_json({
                        "run_id": run_id, "status": "verified",
                        "row_count": len(task.records),
                        "artifact_sha256": receipt["artifact_sha256"],
                    })}]},
    }
    return {
        "run_id": run_id, "status": "verified", "privacy": task.privacy,
        "execution": "offline-deterministic", "artifact_name": "evidence.csv",
        "csv": csv_text, "artifact_sha256": receipt["artifact_sha256"],
        "receipt": receipt, "receipt_json": receipt_json,
        "receipt_sha256": digest(receipt_json), "observation": observation,
    }


def capabilities() -> dict:
    return {
        "default_privacy": "local", "privacy_profiles": PRIVACY_PROFILES,
        "execution": "offline-deterministic", "models": [],
        "network_enabled": False, "formats": ["csv"],
        "verification": "exact-extractive-attribution",
        "retention": "request-memory-only", "limitations": LIMITATIONS,
    }
