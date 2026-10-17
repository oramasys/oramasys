"""Independent CSV readback verifier. Never trusts the writer's success flag."""
from __future__ import annotations

import csv
import hashlib
import io
import json


LEGACY_SCHEMA = "workspace-artifact-v1"
SCHEMAS = (LEGACY_SCHEMA, "workspace-artifact-v2")


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def verify_artifact(csv_text: str, receipt: dict) -> dict:
    """Check artifact bytes, CSV shape, and direct source support without effects."""
    checks = []
    notes: list[str] = []

    def check(name: str, passed: bool):
        checks.append({"name": name, "passed": bool(passed)})

    try:
        check("artifact_sha256", _sha(csv_text) == receipt["artifact_sha256"])
        reader = csv.DictReader(io.StringIO(csv_text, newline=""), strict=True)
        check("csv_schema", reader.fieldnames == ["claim", "source_id", "source_title", "quote"])
        rows = list(reader)
        records = receipt["records"]
        sources = {source["id"]: source for source in receipt["sources"]}
        check("unique_sources", len(sources) == len(receipt["sources"]))
        check("source_integrity", all(_sha(source["passage"]) == source["passage_sha256"]
                                      for source in sources.values()))
        check("row_count", 0 < len(rows) == receipt["row_count"] == len(records))
        supported = True
        safe = True
        for row, record in zip(rows, records, strict=True):
            source = sources.get(row["source_id"])
            supported = supported and (
                source is not None
                and row["source_title"] == source["title"]
                and row["claim"] == row["quote"] == record["claim"] == record["quote"]
                and row["source_id"] == record["source_id"]
                and bool(row["quote"])
                and row["quote"] in source["passage"]
            )
            safe = safe and all(
                isinstance(cell, str) and "\x00" not in cell
                and not cell.lstrip().startswith(("=", "+", "-", "@"))
                for cell in row.values()
            )
        check("exact_source_support", supported)
        check("spreadsheet_safety", safe)
        by_id = {source["id"]: source for source in receipt["sources"]}
        rebuilt = None if receipt["schema_version"] == LEGACY_SCHEMA else {
            "task": receipt["task"], "privacy": receipt["privacy"],
            "sources": [{key: by_id[source_id][key] for key in ("id", "title", "passage", "kind")}
                        for source_id in receipt["source_order"]],
            "records": [{key: record[key] for key in ("claim", "source_id", "quote")}
                        for record in records],
        }
        version = receipt["schema_version"]
        check("receipt_schema", version in SCHEMAS)
        if version == LEGACY_SCHEMA:
            notes.append("legacy v1 receipt: the hashed input cannot be rebuilt without "
                         "source_order, so input_sha256 was not independently checked")
        else:
            check("input_sha256", len(receipt["source_order"]) == len(sources)
                  and _sha(canonical_json(rebuilt)) == receipt["input_sha256"])
    except (KeyError, TypeError, ValueError, AttributeError, csv.Error):
        check("parseable_evidence", False)
    return {"passed": bool(checks) and all(item["passed"] for item in checks),
            "checks": checks, "notes": notes}
