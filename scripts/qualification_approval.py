"""Publish or verify a digest-bound qualification approval.

``authenticate`` is the only write-capable setup path.  It creates an isolated
GitHub CLI configuration, performs GitHub's device/web login, and records a
short-lived local marker.  ``approve`` refuses normal GH token environment
variables and requires that marker.  The marker proves this local procedure was
followed; a later GitHub API read can prove account-owned comment evidence, but
cannot independently prove a human's device/MFA interaction.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Mapping
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
TOKEN_ENVIRONMENT = ("GH_TOKEN", "GITHUB_TOKEN", "GITHUB_PERSONAL_ACCESS_TOKEN", "GITHUB_COPILOT_PAT")
MARKER_NAME = "qualification-fresh-auth.v1.json"
MAX_MARKER_AGE_SECONDS = 15 * 60
COMMENT_REF = re.compile(
    r"^https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/(?:issues|pull)/(\d+)#issuecomment-(\d+)$"
)


def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                                     allow_nan=False).encode()).hexdigest()


def strict_load(path: Path) -> object:
    def reject_constant(name: str) -> None:
        raise ValueError(f"non-finite number {name} is not allowed")
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key}")
            result[key] = value
        return result
    return json.loads(path.read_text(encoding="utf-8"), parse_constant=reject_constant, object_pairs_hook=unique)


def approvers(path: Path) -> tuple[str, ...]:
    value = strict_load(path)
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise ValueError("unsupported approver allowlist")
    accounts = value.get("accounts")
    if not isinstance(accounts, list) or not accounts or any(not isinstance(a, str) or not a for a in accounts):
        raise ValueError("invalid approver allowlist")
    if len(set(accounts)) != len(accounts):
        raise ValueError("duplicate approver")
    return tuple(accounts)


def approval_body(repository: str, pull_request: int, consumer: str, manifest: object,
                  coverage: object, allowlist: Path) -> str:
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None or pull_request < 1:
        raise ValueError("invalid repository or pull request")
    if re.fullmatch(r"[0-9a-f]{40}", consumer) is None:
        raise ValueError("consumer must be a full commit SHA")
    allowed = approvers(allowlist)
    return "\n".join((
        "oramasys-qualification-approval: v1", f"repository: {repository}",
        f"pull_request: {pull_request}", f"consumer_commit: {consumer}",
        f"manifest_digest: {digest(manifest)}", f"coverage_digest: {digest(coverage)}",
        f"allowlist_digest: {digest(list(allowed))}",
    )) + "\n"


def parse_reference(reference: str) -> tuple[str, int, int]:
    matched = COMMENT_REF.fullmatch(reference)
    if matched is None:
        raise ValueError("approval reference must be a GitHub issue or pull-request comment URL")
    pull_request, comment_id = int(matched.group(2)), int(matched.group(3))
    if pull_request < 1 or comment_id < 1:
        raise ValueError("approval reference has an invalid pull request or comment ID")
    return matched.group(1), pull_request, comment_id


def verify_comment(comment: Mapping[str, object], reference: str, expected_body: str,
                   allowed: tuple[str, ...]) -> None:
    _, _, comment_id = parse_reference(reference)
    if comment.get("id") != comment_id or comment.get("html_url") != reference:
        raise ValueError("approval comment reference mismatch")
    user = comment.get("user")
    if not isinstance(user, Mapping) or user.get("login") not in allowed:
        raise ValueError("approval author is not allowlisted")
    if comment.get("body") != expected_body:
        raise ValueError("approval comment body mismatch")
    if comment.get("created_at") != comment.get("updated_at"):
        raise ValueError("edited approval comment refused")


def isolated_environment(config_dir: Path) -> dict[str, str]:
    if not config_dir.is_absolute() or not config_dir.is_dir():
        raise ValueError("GH_CONFIG_DIR must name an existing absolute directory")
    if any(os.environ.get(name) for name in TOKEN_ENVIRONMENT):
        raise ValueError("token environment variables are forbidden")
    environment = os.environ.copy()
    for name in TOKEN_ENVIRONMENT:
        environment.pop(name, None)
    environment["GH_CONFIG_DIR"] = str(config_dir)
    return environment


def authenticated_login(config_dir: Path) -> str:
    environment = isolated_environment(config_dir)
    result = subprocess.run(["gh", "api", "user", "--jq", ".login"], env=environment,
                            check=True, capture_output=True, text=True)
    login = result.stdout.strip()
    if not login:
        raise ValueError("GitHub authentication did not identify an account")
    return login


def marker_path(config_dir: Path) -> Path:
    return config_dir / MARKER_NAME


def require_fresh_marker(config_dir: Path, login: str) -> None:
    marker = strict_load(marker_path(config_dir))
    if not isinstance(marker, dict) or marker.get("schema") != 1 or marker.get("account") != login:
        raise ValueError("fresh-auth marker does not bind the active account")
    issued_at = marker.get("issued_at")
    if type(issued_at) not in (int, float) or time.time() - issued_at > MAX_MARKER_AGE_SECONDS or issued_at > time.time():
        raise ValueError("fresh-auth marker is expired or invalid")


def github_comment(repository: str, comment_id: int, token: str) -> dict[str, object]:
    request = Request(f"https://api.github.com/repos/{repository}/issues/comments/{comment_id}", headers={
        "Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28"})
    with urlopen(request, timeout=20) as response:  # nosec B310: fixed GitHub API origin
        value = json.loads(response.read().decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("GitHub returned a non-object comment")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="action", required=True)
    auth = subcommands.add_parser("authenticate")
    auth.add_argument("--config-dir", type=Path, required=True)
    approve = subcommands.add_parser("approve")
    verify = subcommands.add_parser("verify")
    for command in (approve, verify):
        command.add_argument("manifest", type=Path)
        command.add_argument("coverage", type=Path)
        command.add_argument("--consumer", required=True)
        command.add_argument("--repository", required=True)
        command.add_argument("--pull-request", required=True, type=int)
        command.add_argument("--record", type=Path, required=True)
        command.add_argument("--allowlist", type=Path, default=ROOT / "requirements/qualification-approvers.v1.json")
    approve.add_argument("--config-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == "authenticate":
            if not args.config_dir.is_absolute() or args.config_dir.exists():
                raise ValueError("fresh GH_CONFIG_DIR must be a new absolute directory")
            args.config_dir.mkdir(mode=0o700, parents=True)
            environment = isolated_environment(args.config_dir)
            subprocess.run(["gh", "auth", "login", "--web", "--hostname", "github.com", "--git-protocol", "https"],
                           env=environment, check=True)
            login = authenticated_login(args.config_dir)
            marker_path(args.config_dir).write_text(json.dumps({"schema": 1, "account": login,
                "issued_at": time.time()}, sort_keys=True) + "\n", encoding="utf-8")
            os.chmod(marker_path(args.config_dir), 0o600)
        else:
            manifest, coverage = strict_load(args.manifest), strict_load(args.coverage)
            allowed = approvers(args.allowlist)
            body = approval_body(args.repository, args.pull_request, args.consumer, manifest, coverage, args.allowlist)
            if args.action == "approve":
                login = authenticated_login(args.config_dir)
                require_fresh_marker(args.config_dir, login)
                if login not in allowed:
                    raise ValueError("active account is not allowlisted")
                # The marker is a one-time capability: spend it before use so a
                # failed or interrupted post can never be retried with the same
                # login. A new config directory and a new login are required.
                marker_path(args.config_dir).unlink()
                try:
                    result = subprocess.run(["gh", "api", "--method", "POST", f"repos/{args.repository}/issues/{args.pull_request}/comments",
                        "-f", f"body={body}"], env=isolated_environment(args.config_dir), check=True,
                        capture_output=True, text=True)
                except subprocess.CalledProcessError as error:
                    raise ValueError(
                        "approval comment was not posted; the one-time login marker is spent, "
                        "so re-authenticate in a new config directory and run approve again"
                    ) from error
                comment = json.loads(result.stdout)
                reference = comment.get("html_url") if isinstance(comment, dict) else None
                if not isinstance(reference, str):
                    raise ValueError("GitHub did not return an approval comment URL")
                record = {"schema": 1, "status": "approved", "approval_ref": reference,
                          "consumer_commit": args.consumer, "manifest_digest": digest(manifest), "coverage_digest": digest(coverage)}
                args.record.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            else:
                record = strict_load(args.record)
                if not isinstance(record, dict) or record.get("approval_ref") is None:
                    raise ValueError("approval reference required")
                reference = record["approval_ref"]
                if not isinstance(reference, str):
                    raise ValueError("approval reference required")
                repo, pr, comment_id = parse_reference(reference)
                if repo != args.repository or pr != args.pull_request:
                    raise ValueError("approval reference targets another pull request")
                token = os.environ.get("GITHUB_TOKEN")
                if not token:
                    raise ValueError("GITHUB_TOKEN is required for remote verification")
                verify_comment(github_comment(repo, comment_id, token), reference, body, allowed)
        return 0
    except (OSError, ValueError, TypeError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        print(f"approval-refused: {type(error).__name__}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
