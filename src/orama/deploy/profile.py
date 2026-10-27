"""Per-installation serving deployment profile (H09 work package 1).

A single ``config/serving-profile.yml`` is shared by every node of an
installation; each node picks out its own entry. The profile only describes
*topology*: it never enables serving. Serving needs all three of a server role,
``ORAMA_GRANT_SERVING`` and a matching D6 approval record (see
:func:`serving_permitted`).

Fail-safe: no profile, an unreadable profile, or no matching node all yield the
``client`` role with serving ``not-applicable``. A profile that exists but is
malformed is an error (CLI exit code 2), never a silent client.

Nothing here creates accounts, sets ACLs or executes anything; ``plan`` only
prints.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import platform
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Literal, Mapping

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

ENV_PROFILE = "ORAMA_SERVING_PROFILE"
ENV_NODE_ID = "ORAMA_NODE_ID"
ENV_NODE_ROLE = "ORAMA_NODE_ROLE"
ENV_GRANT_SERVING = "ORAMA_GRANT_SERVING"

Role = Literal["primary-server", "secondary-server", "client", "off"]
SERVER_ROLES = ("primary-server", "secondary-server")
# Lower rank = fewer privileges. The override may only move to a lower rank.
_ROLE_RANK = {"off": 0, "client": 1, "secondary-server": 2, "primary-server": 2}

_OS_BY_PLATFORM = {"darwin": "macos", "linux": "linux", "win32": "windows"}

_FORBIDDEN_PRINCIPAL_NAMES = {
    "root", "system", "localservice", "networkservice", "administrators",
}
_FORBIDDEN_SIDS = {"s-1-5-18", "s-1-5-19", "s-1-5-20", "s-1-5-32-544"}


class ProfileError(Exception):
    """The profile or environment is invalid; callers must fail closed."""


class StartupRefused(ProfileError):
    """Serving was requested on a node whose effective role forbids it."""


def default_profile_path() -> Path:
    """Return the default profile location, ``config/serving-profile.yml``."""
    return Path(__file__).resolve().parents[3] / "config" / "serving-profile.yml"


def running_os() -> str:
    """Map ``sys.platform`` to ``macos``, ``linux`` or ``windows``."""
    for prefix, name in _OS_BY_PLATFORM.items():
        if sys.platform.startswith(prefix):
            return name
    return sys.platform


def _hostname() -> str:
    """Return this host's name (a seam for tests)."""
    return platform.node()


def _norm_account(value: str) -> str:
    """Normalise an account name for comparison (case, domain, spaces)."""
    return value.strip().replace("/", "\\").split("\\")[-1].replace(" ", "").casefold()


def _is_forbidden_principal(value: str | int) -> bool:
    """Return True for uid 0, SYSTEM, LocalService, NetworkService, Administrators."""
    text = str(value).strip()
    if text == "0" or text.casefold() in _FORBIDDEN_SIDS:
        return True
    return _norm_account(text) in _FORBIDDEN_PRINCIPAL_NAMES


def _state_root_problem(path: str) -> str | None:
    """Return why ``path`` is not an absolute local path, or None if it is fine."""
    if path.startswith("\\\\") or path.startswith("//"):
        return "UNC/network paths are not allowed"
    if re.match(r"^/mnt/[A-Za-z](/|$)", path):
        return "WSL /mnt/<drive> paths are not allowed"
    if path.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", path):
        return None
    return "must be an absolute path"


class Identity(BaseModel):
    """Service and signer identities for a server node."""

    model_config = ConfigDict(extra="forbid")

    server_account: str | None = None
    signer_account: str | None = None
    expected_principal: str | int | None = None

    @model_validator(mode="after")
    def _check(self) -> "Identity":
        """Refuse shared server/signer accounts and privileged principals."""
        if (
            self.server_account
            and self.signer_account
            and _norm_account(self.server_account) == _norm_account(self.signer_account)
        ):
            raise ValueError("server_account must differ from signer_account")
        if self.expected_principal is not None and _is_forbidden_principal(
            self.expected_principal
        ):
            raise ValueError(
                "expected_principal must not be uid 0, SYSTEM, LocalService, "
                "NetworkService or Administrators"
            )
        return self


class Node(BaseModel):
    """One node of the installation."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    os: Literal["macos", "linux", "windows"]
    role: Role = "client"
    serves: list[Literal["verify"]] = Field(default_factory=lambda: ["verify"])
    endpoint: str | None = None
    identity: Identity | None = None
    state_root: str | None = None
    public_state: Literal["local", "signed-publication"] = "local"

    @model_validator(mode="after")
    def _check(self) -> "Node":
        """Per-node rules: servers need an endpoint; state_root absolute+local."""
        if self.role in SERVER_ROLES and not self.endpoint:
            raise ValueError(f"node {self.id!r}: servers need an endpoint")
        if self.endpoint is not None and (
            re.search(r"\s", self.endpoint) or "://" in self.endpoint
        ):
            raise ValueError(f"node {self.id!r}: endpoint must be host:port")
        if self.role == "secondary-server" and self.public_state != "signed-publication":
            raise ValueError(
                f"node {self.id!r}: a secondary-server requires "
                "public_state: signed-publication"
            )
        if self.state_root is not None:
            problem = _state_root_problem(self.state_root)
            if problem:
                raise ValueError(f"node {self.id!r}: state_root {problem}")
        return self


class ServingProfile(BaseModel):
    """The whole profile document (``version: 1``)."""

    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    installation: str | None = None
    nodes: list[Node]

    @model_validator(mode="after")
    def _check(self) -> "ServingProfile":
        """Cross-node rules: unique ids, at most one primary, secondary needs one."""
        ids = [n.id for n in self.nodes]
        dup = sorted({i for i in ids if ids.count(i) > 1})
        if dup:
            raise ValueError(f"duplicate node ids: {dup}")
        primaries = [n for n in self.nodes if n.role == "primary-server"]
        if len(primaries) > 1:
            raise ValueError("more than one primary-server")
        if not primaries and any(n.role == "secondary-server" for n in self.nodes):
            raise ValueError("secondary-server without a primary-server")
        return self


@dataclass
class EffectiveNode:
    """The role this node actually runs with, and why."""

    node_id: str | None
    os: str
    role: str
    serving: str  # "applicable" or "not-applicable"
    source: str  # profile | no-profile | unreadable-profile | no-matching-node
    profile_path: str | None = None
    profile_sha256: str | None = None
    profile_role: str | None = None
    override_ignored: str | None = None
    endpoint: str | None = None
    primary_endpoint: str | None = None
    state_root: str | None = None
    public_state: str | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Return a JSON-ready dict."""
        return asdict(self)


ApprovalMatcher = Callable[[EffectiveNode], bool]


def no_approval(effective: EffectiveNode) -> bool:
    """Default D6 matcher: no approval record is ever found (records come later)."""
    return False


def _fallback(source: str, path: Path | None, note: str, os_name: str) -> EffectiveNode:
    """Build the fail-safe client result."""
    return EffectiveNode(
        node_id=None, os=os_name, role="client", serving="not-applicable",
        source=source, profile_path=str(path) if path else None, notes=[note],
    )


def parse_profile(text: str) -> ServingProfile:
    """Parse and validate profile YAML; raise :class:`ProfileError` if malformed."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ProfileError(f"profile is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ProfileError("profile must be a YAML mapping")
    try:
        return ServingProfile.model_validate(data)
    except ValidationError as exc:
        parts = [
            f"{'.'.join(str(p) for p in e['loc']) or '<root>'}: {e['msg']}"
            for e in exc.errors()
        ]
        raise ProfileError("invalid profile: " + "; ".join(parts)) from exc


def resolve_node(
    profile: ServingProfile,
    env: Mapping[str, str],
    path: Path | None = None,
    sha256: str | None = None,
) -> EffectiveNode:
    """Select this node, check the OS, and apply the downgrade-only override."""
    os_name = running_os()
    wanted = (env.get(ENV_NODE_ID) or _hostname()).strip()
    keys = {wanted.casefold(), wanted.split(".")[0].casefold()}
    node = next((n for n in profile.nodes if n.id.casefold() in keys), None)
    if node is None:
        eff = _fallback("no-matching-node", path, f"no node matches {wanted!r}", os_name)
        eff.profile_sha256 = sha256
    else:
        if node.os != os_name:
            raise ProfileError(
                f"node {node.id!r} declares os {node.os!r} but this host is {os_name!r}"
            )
        primary = next((n for n in profile.nodes if n.role == "primary-server"), None)
        eff = EffectiveNode(
            node_id=node.id, os=os_name, role=node.role, serving="not-applicable",
            source="profile", profile_path=str(path) if path else None,
            profile_sha256=sha256, profile_role=node.role, endpoint=node.endpoint,
            primary_endpoint=primary.endpoint if primary else None,
            state_root=node.state_root, public_state=node.public_state,
        )
    override = (env.get(ENV_NODE_ROLE) or "").strip()
    if override:
        if override not in _ROLE_RANK:
            raise ProfileError(f"{ENV_NODE_ROLE}={override!r} is not a valid role")
        if _ROLE_RANK[override] < _ROLE_RANK[eff.role]:
            eff.notes.append(f"role lowered {eff.role} -> {override} by {ENV_NODE_ROLE}")
            eff.role = override
        elif override != eff.role:
            eff.override_ignored = (
                f"{ENV_NODE_ROLE}={override} would promote {eff.role}; ignored "
                "(the override can only downgrade)"
            )
    eff.serving = "applicable" if eff.role in SERVER_ROLES else "not-applicable"
    return eff


def load_effective(env: Mapping[str, str] | None = None) -> EffectiveNode:
    """Load the profile and return this node's effective role.

    Missing or unreadable profile => client/not-applicable. Malformed => error.
    """
    env = os.environ if env is None else env
    path = Path(env.get(ENV_PROFILE) or default_profile_path())
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return _fallback("no-profile", path, "no profile file", running_os())
    except OSError as exc:
        return _fallback(
            "unreadable-profile", path,
            f"profile unreadable: {exc.__class__.__name__}", running_os(),
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProfileError("profile is not valid UTF-8") from exc
    profile = parse_profile(text)
    return resolve_node(profile, env, path, hashlib.sha256(raw).hexdigest())


def serving_permitted(
    effective: EffectiveNode,
    env: Mapping[str, str],
    approval_matcher: ApprovalMatcher = no_approval,
) -> bool:
    """Master switch: True only for a server role AND ORAMA_GRANT_SERVING AND approval.

    ``approval_matcher`` is injectable because D6 approval records do not exist
    yet; the default never matches, so this is False until they are built.
    The profile alone never permits serving.
    """
    if effective.role not in SERVER_ROLES:
        return False
    if not env.get(ENV_GRANT_SERVING):
        return False
    return bool(approval_matcher(effective))


def check_startup(effective: EffectiveNode, env: Mapping[str, str]) -> None:
    """Refuse (raise) if ORAMA_GRANT_SERVING is set on a client or off node."""
    if env.get(ENV_GRANT_SERVING) and effective.role not in SERVER_ROLES:
        raise StartupRefused(
            f"{ENV_GRANT_SERVING} is set but the effective role is "
            f"{effective.role!r}; refusing to start"
        )


_SERVER_STEPS = {
    "linux": [
        "Create the system user orama-serve (systemd User=, NoNewPrivileges) and the signer user orama-signer.",
        "Create the state root owned by orama-serve, mode 0700.",
    ],
    "macos": [
        "Create the hidden service user _orama-serve (UID < 500, launchd UserName) and the signer user _orama-signer.",
        "Create the state root owned by _orama-serve, mode 0700.",
    ],
    "windows": [
        "Install pywin32 into the serving venv (serving refuses to run without it; there is no icacls fallback).",
        r"Use the virtual service account NT SERVICE\OramaServe (privileges stripped, restricted SID type) and a standard local user orama-signer with deny-logon rights.",
        "Create the state root with a protected DACL.",
    ],
}
_SERVER_COMMON = [
    "Record the numeric uid/SID of the server account as identity.expected_principal in the profile.",
    "Obtain a D6 approval record under docs/v2/activation/ for this node.",
    "Only after approval, the operator sets the serving master switch and starts the service.",
]


def plan(effective: EffectiveNode, fmt: str = "text") -> str:
    """Return what this node should set up for its role and OS (print only)."""
    is_server = effective.role in SERVER_ROLES
    if fmt == "env":
        lines = [
            f"ORAMA_NODE_ID={effective.node_id or ''}",
            f"ORAMA_NODE_ROLE={effective.role}",
        ]
        endpoint = effective.endpoint if is_server else effective.primary_endpoint
        lines.append(f"ORAMA_SERVING_ENDPOINT={endpoint or ''}")
        if is_server and effective.state_root:
            lines.append(f"ORAMA_STATE_ROOT={effective.state_root}")
        return "\n".join(lines) + "\n"
    out = [
        f"node: {effective.node_id or '(none)'}  os: {effective.os}  role: {effective.role}",
    ]
    if is_server:
        out.append(f"endpoint: {effective.endpoint}")
        if effective.state_root:
            out.append(f"state_root: {effective.state_root}")
        out.append("Operator-only steps (this tool prints them and executes nothing):")
        steps = _SERVER_STEPS.get(effective.os, []) + _SERVER_COMMON
        out.extend(f"  {i}. {s}" for i, s in enumerate(steps, 1))
    elif effective.role == "client":
        out.append(
            f"serving endpoint record: {effective.primary_endpoint or '(none published)'}"
        )
    else:
        out.append("role off: nothing to set up")
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: ``show``, ``plan`` and ``validate``; exit 0 or 2."""
    parser = argparse.ArgumentParser(prog="python -m orama.deploy.profile")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("show", help="print the effective node as JSON")
    p_plan = sub.add_parser("plan", help="print what this node should set up")
    p_plan.add_argument("--format", choices=["text", "env"], default="text")
    sub.add_parser("validate", help="exit 0 if valid, 2 otherwise")
    args = parser.parse_args(argv)
    try:
        eff = load_effective()
        check_startup(eff, os.environ)
    except ProfileError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.cmd == "show":
        print(json.dumps(eff.to_dict(), indent=2, sort_keys=True))
    elif args.cmd == "plan":
        sys.stdout.write(plan(eff, args.format))
    else:
        print(
            f"ok: role={eff.role} serving={eff.serving} source={eff.source}"
            + (f" ({'; '.join(eff.notes)})" if eff.notes else "")
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
