"""Refuse a final cell with absent tests, inactive setup, failed tests or skips."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Mapping
import xml.etree.ElementTree as ET


def check_collection(packet: Mapping, nodes: object, environment: Mapping[str, str]) -> list[str]:
    """Check actual collected node IDs against the reviewed final-cell coverage."""
    if not isinstance(nodes, list) or not nodes or not all(isinstance(n, str) and n for n in nodes):
        return ["collection is empty or malformed"]
    problems = []
    if len(set(nodes)) != len(nodes):
        problems.append("duplicate collected node IDs")
    modules = {n.split("::", 1)[0].replace("\\", "/") for n in nodes}
    required = set(packet["required_modules"])
    historical = set(packet.get("historical_only_modules", []))
    for name in sorted(required - modules):
        problems.append(f"required module not collected: {name}")
    for name in sorted(historical & modules):
        problems.append(f"historical-only module collected in final cell: {name}")
    for name in packet["required_environment"]:
        if environment.get(name) != "1":
            problems.append(f"required gate inactive: {name}")
    for name in packet.get("required_setup_inputs", []):
        if not environment.get(name, "").strip():
            problems.append(f"required setup input missing: {name}")
    return problems


def check_count_agreement(nodes: list[str], junit_total: int) -> list[str]:
    """Every collected node must be reported once, so a silent subset cannot pass."""
    if len(nodes) == junit_total:
        return []
    return [f"collected {len(nodes)} nodes but junit {junit_total} tests ran"]


def check_execution(collected: list[str], executed: object) -> list[str]:
    """Require the tests that ran to be exactly the tests that were collected."""
    if not isinstance(executed, list) or not all(isinstance(n, str) and n for n in executed):
        return ["executed node ids are malformed"]
    problems = []
    if len(set(executed)) != len(executed):
        problems.append("duplicate executed node IDs")
    missing = sorted(set(collected) - set(executed))
    unexpected = sorted(set(executed) - set(collected))
    if missing:
        problems.append(f"collected but not executed: {len(missing)} missing")
    if unexpected:
        problems.append(f"executed but not collected: {len(unexpected)} unexpected")
    return problems


def check_results(xml: str) -> int:
    """Return the passed count only for a nonempty successful zero-skip report."""
    try:
        root = ET.fromstring(xml)
        suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
        totals = dict.fromkeys(("tests", "errors", "failures", "skipped"), 0)
        if not suites:
            raise ValueError("no testsuite")
        for suite in suites:
            for field in totals:
                raw = suite.get(field, "0")
                if not raw.isascii() or not raw.isdigit():
                    raise ValueError("invalid JUnit count")
                totals[field] += int(raw)
        if totals["tests"] == 0 or any(totals[k] for k in ("errors", "failures", "skipped")):
            raise ValueError("final cell is empty, failed or skipped")
        return totals["tests"]
    except ET.ParseError as exc:
        raise ValueError("invalid JUnit report") from exc


def main() -> int:
    """Validate the collection and test reports without modifying them."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("junit")
    parser.add_argument("packet")
    parser.add_argument("collection")
    args = parser.parse_args()
    try:
        packet = json.loads(Path(args.packet).read_text())
        report = json.loads(Path(args.collection).read_text())
        if report.get("schema") != 1:
            raise ValueError("unsupported collection report")
        problems = check_collection(packet, report.get("node_ids"), os.environ)
        passed = check_results(Path(args.junit).read_text())
        if not problems:
            problems = check_count_agreement(report["node_ids"], passed)
        if not problems:
            problems = check_execution(report["node_ids"], report["executed_node_ids"])
        if problems:
            raise ValueError("; ".join(problems))
        print(json.dumps({"schema": 1, "passed": passed, "skipped": 0,
                          "required_modules": len(packet["required_modules"])}))
        return 0
    except (OSError, ValueError, TypeError, AttributeError, KeyError) as exc:
        print(f"collection-refused: {type(exc).__name__}")
        print(f"collection-refused: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
