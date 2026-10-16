"""Independent CSV readback verifier. Never trusts the writer's success flag."""
from __future__ import annotations

import csv
import hashlib
import io


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def verify_artifact(csv_text: str, receipt: dict) -> dict:
    """Check artifact bytes, CSV shape, and direct source support without effects."""
    checks = []

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
        check("receipt_schema", receipt["schema_version"] == "workspace-artifact-v1")
    except (KeyError, TypeError, ValueError, AttributeError, csv.Error):
        check("parseable_evidence", False)
    return {"passed": bool(checks) and all(item["passed"] for item in checks),
            "checks": checks}
