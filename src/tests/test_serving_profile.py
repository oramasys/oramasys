"""Deployment profile: loading, fail-closed validation, master switch and CLI."""
from __future__ import annotations

import json
import io
import re
import shlex
from pathlib import Path

import pytest

from orama.deploy import profile as prof
from orama.deploy.profile import ProfileError, StartupRefused

EXAMPLE = Path(__file__).resolve().parents[2] / "config" / "serving-profile.example.yml"
OS_BY_PLATFORM = {"linux": "linux", "darwin": "macos", "win32": "windows"}


@pytest.mark.parametrize("text", ["? [a]\n: 1\n", "? {a: b}\n: 1\n"])
def test_complex_yaml_keys_refuse_cleanly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, text: str,
) -> None:
    """Complex keys are malformed profiles, not uncaught hashing errors."""
    _env(monkeypatch, tmp_path, text)
    with pytest.raises(ProfileError):
        prof.load_effective()
    assert prof.main(["validate"]) == 2


@pytest.mark.parametrize("field", ["server_account", "signer_account", "expected_principal"])
@pytest.mark.parametrize("name", ["root", "Administrator", "SYSTEM", "S-1-5-18\n", "501\n"])
def test_all_identity_fields_reject_privileged_or_control_values(field: str, name: str) -> None:
    """Account aliases and trailing control characters cannot bypass identity validation."""
    with pytest.raises(ProfileError):
        prof.parse_profile(BASE.replace("    endpoint: srv.example:8443", "    endpoint: srv.example:8443\n    identity:\n      " + field + ": " + json.dumps(name)))


def test_endpoint_trailing_newline_refuses() -> None:
    """A newline is not part of a valid endpoint or safe environment assignment."""
    with pytest.raises(ProfileError):
        prof.parse_profile(BASE.replace("srv.example:8443", '"srv.example:8443\\n"'))


@pytest.mark.parametrize("override", ["off", "invalid"])
def test_missing_profile_still_applies_role_override(tmp_path: Path, override: str) -> None:
    """Fallback clients can be disabled but do not silently accept invalid overrides."""
    env = {prof.ENV_PROFILE: str(tmp_path / "missing"), prof.ENV_NODE_ROLE: override}
    if override == "invalid":
        with pytest.raises(ProfileError):
            prof.load_effective(env)
    else:
        assert prof.load_effective(env).role == "off"


@pytest.mark.parametrize("root", ["/Library/Application Support/Oramasys", r"C:\ProgramData\Oramasys"])
def test_env_plan_preserves_spaced_and_windows_paths(root: str) -> None:
    """The documented POSIX assignment format preserves literal values on either OS."""
    effective = prof.EffectiveNode("srv", "macos", "primary-server", "not-applicable", "profile", state_root=root)
    assignments = dict(shlex.split(line)[0].split("=", 1) for line in prof.plan(effective, "env").splitlines())
    assert assignments["ORAMA_STATE_ROOT"] == root


def test_plan_retains_configured_account_names(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The plan does not replace explicitly configured nonprivileged identities with defaults."""
    text = BASE.replace("    endpoint: srv.example:8443", "    endpoint: srv.example:8443\n    identity:\n      server_account: custom-serve\n      signer_account: custom-signer")
    _env(monkeypatch, tmp_path, text)
    output = prof.plan(prof.load_effective())
    assert "custom-serve" in output and "custom-signer" in output


def test_profile_read_is_bounded_before_allocation(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The loader requests at most the size ceiling plus one byte before rejecting."""
    path = _env(monkeypatch, tmp_path, BASE)
    original = Path.open

    class BoundedReader(io.BytesIO):
        """Refuse an unbounded read while representing an oversized input."""

        def read(self, size: int = -1) -> bytes:
            """Prove the read bound without allocating an arbitrarily large file."""
            assert size == prof.MAX_PROFILE_BYTES + 1
            return b"x" * size

    def open_profile(candidate: Path, *args: object, **kwargs: object):
        """Replace only this profile file with the bounded-read witness."""
        return BoundedReader() if candidate == path else original(candidate, *args, **kwargs)

    monkeypatch.setattr(Path, "open", open_profile)
    with pytest.raises(ProfileError, match="size limit"):
        prof.load_effective()

BASE = """
version: 1
nodes:
  - id: srv
    os: linux
    role: primary-server
    endpoint: srv.example:8443
  - id: cli
    os: linux
    role: client
"""


def _env(monkeypatch, tmp_path, text, node="srv", platform="linux", **extra):
    """Write a profile, point the loader at it, and fake platform/node."""
    path = tmp_path / "p.yml"
    if path.exists():
        path.unlink()
    if text is not None:
        path.write_text(text, encoding="utf-8")
    for key in list(prof.os.environ):
        if key.startswith("ORAMA_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("ORAMA_SERVING_PROFILE", str(path))
    if node is not None:
        monkeypatch.setenv("ORAMA_NODE_ID", node)
    monkeypatch.setattr(prof.sys, "platform", platform)
    for k, v in extra.items():
        monkeypatch.setenv(k, v)
    return path


def _node(extra: str, role="primary-server") -> str:
    """Build a one-node profile with extra node-level YAML lines."""
    return (
        "version: 1\nnodes:\n  - id: srv\n    os: linux\n"
        f"    role: {role}\n    endpoint: srv.example:8443\n" + extra
    )


def test_no_profile_is_client(monkeypatch, tmp_path):
    """Check: no profile is client."""
    _env(monkeypatch, tmp_path, None)
    eff = prof.load_effective()
    assert (eff.role, eff.serving, eff.source) == ("client", "not-applicable", "no-profile")


def test_unreadable_profile_is_client(monkeypatch, tmp_path):
    """Check: unreadable profile is client."""
    path = _env(monkeypatch, tmp_path, BASE)
    real = Path.open

    def boom(self: Path, *args: object, **kwargs: object):
        """Check: boom."""
        if self == path:
            raise PermissionError("denied")
        return real(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", boom)
    eff = prof.load_effective()
    assert (eff.role, eff.source) == ("client", "unreadable-profile")


@pytest.mark.parametrize("text", ["", "- a\n- b\n", "version: [", "version: 2\nnodes: []\n"])
def test_malformed_profile_is_error(monkeypatch, tmp_path, text):
    """Check: malformed profile is error."""
    _env(monkeypatch, tmp_path, text)
    with pytest.raises(ProfileError):
        prof.load_effective()


def test_no_matching_node_is_client(monkeypatch, tmp_path):
    """Check: no matching node is client."""
    _env(monkeypatch, tmp_path, BASE, node="other")
    eff = prof.load_effective()
    assert (eff.role, eff.source) == ("client", "no-matching-node")


def test_server_selected_and_hashed(monkeypatch, tmp_path):
    """Check: server selected and hashed."""
    _env(monkeypatch, tmp_path, BASE)
    eff = prof.load_effective()
    assert (eff.role, eff.serving) == ("primary-server", "applicable")
    assert len(eff.profile_sha256) == 64


def test_override_can_only_downgrade(monkeypatch, tmp_path):
    """Check: override can only downgrade."""
    _env(monkeypatch, tmp_path, BASE, ORAMA_NODE_ROLE="client")
    eff = prof.load_effective()
    assert (eff.role, eff.serving) == ("client", "not-applicable")
    _env(monkeypatch, tmp_path, BASE, ORAMA_NODE_ROLE="off")
    assert prof.load_effective().role == "off"
    _env(monkeypatch, tmp_path, BASE, node="cli", ORAMA_NODE_ROLE="primary-server")
    eff = prof.load_effective()
    assert eff.role == "client"
    assert "would promote" in eff.override_ignored
    _env(monkeypatch, tmp_path, BASE, node="cli", ORAMA_NODE_ROLE="bogus")
    with pytest.raises(ProfileError):
        prof.load_effective()


def test_os_mismatch_refused_for_selected_node_only(monkeypatch, tmp_path):
    """Check: os mismatch refused for selected node only."""
    _env(monkeypatch, tmp_path, BASE, platform="darwin")
    with pytest.raises(ProfileError, match="os"):
        prof.load_effective()
    mixed = BASE.replace("id: cli\n    os: linux", "id: cli\n    os: windows")
    _env(monkeypatch, tmp_path, mixed)  # the other node's OS is irrelevant
    assert prof.load_effective().role == "primary-server"


@pytest.mark.parametrize(
    "platform,name", [("darwin", "macos"), ("linux", "linux"), ("win32", "windows")]
)
def test_running_os_mapping(monkeypatch, platform, name):
    """Check: running os mapping."""
    monkeypatch.setattr(prof.sys, "platform", platform)
    assert prof.running_os() == name


def test_two_primaries(monkeypatch, tmp_path):
    """Check: two primaries."""
    text = BASE.replace(
        "id: cli\n    os: linux\n    role: client",
        "id: cli\n    os: linux\n    role: primary-server\n    endpoint: b.example:1",
    )
    _env(monkeypatch, tmp_path, text)
    with pytest.raises(ProfileError, match="more than one"):
        prof.load_effective()


def test_duplicate_ids(monkeypatch, tmp_path):
    """Check: duplicate ids."""
    _env(monkeypatch, tmp_path, BASE.replace("id: cli", "id: srv"))
    with pytest.raises(ProfileError, match="duplicate"):
        prof.load_effective()


SECONDARY = """
version: 1
nodes:
  - id: srv
    os: linux
    role: secondary-server
    endpoint: srv.example:8443
    public_state: signed-publication
"""


def test_secondary_without_primary(monkeypatch, tmp_path):
    """Check: secondary without primary."""
    _env(monkeypatch, tmp_path, SECONDARY)
    with pytest.raises(ProfileError, match="without a primary"):
        prof.load_effective()


def test_secondary_local_state_rejected(monkeypatch, tmp_path):
    """Check: secondary local state rejected."""
    text = (
        BASE + "  - id: sec\n    os: linux\n    role: secondary-server\n"
        "    endpoint: sec.example:8443\n"
    )
    _env(monkeypatch, tmp_path, text, node="sec")
    with pytest.raises(ProfileError, match="signed-publication"):
        prof.load_effective()
    ok = text + "    public_state: signed-publication\n"
    _env(monkeypatch, tmp_path, ok, node="sec")
    assert prof.load_effective().role == "secondary-server"


@pytest.mark.parametrize(
    "principal",
    ["0", "root", "SYSTEM", "NT AUTHORITY\\SYSTEM", "S-1-5-18", "S-1-5-19",
     "S-1-5-20", "S-1-5-32-544", "Administrators", "BUILTIN\\Administrators",
     "LocalService", "NetworkService"],
)
def test_privileged_principal_refused(monkeypatch, tmp_path, principal):
    """Check: privileged principal refused."""
    extra = f"    identity:\n      expected_principal: '{principal}'\n"
    _env(monkeypatch, tmp_path, _node(extra))
    with pytest.raises(ProfileError, match="expected_principal"):
        prof.load_effective()


def test_uid_zero_integer_refused(monkeypatch, tmp_path):
    """Check: uid zero integer refused."""
    _env(monkeypatch, tmp_path, _node("    identity:\n      expected_principal: 0\n"))
    with pytest.raises(ProfileError):
        prof.load_effective()


def test_unprivileged_principal_accepted(monkeypatch, tmp_path):
    """Check: unprivileged principal accepted."""
    _env(monkeypatch, tmp_path, _node("    identity:\n      expected_principal: 501\n"))
    assert prof.load_effective().role == "primary-server"


def test_same_server_and_signer_refused(monkeypatch, tmp_path):
    """Check: same server and signer refused."""
    extra = "    identity:\n      server_account: Svc\n      signer_account: svc\n"
    _env(monkeypatch, tmp_path, _node(extra))
    with pytest.raises(ProfileError, match="differ"):
        prof.load_effective()


@pytest.mark.parametrize(
    "root",
    ["\\\\\\\\server\\\\share", "//server/share", "/mnt/c/data", "/mnt/D", "relative/path"],
)
def test_bad_state_root_refused(monkeypatch, tmp_path, root):
    """Check: bad state root refused."""
    _env(monkeypatch, tmp_path, _node(f'    state_root: "{root}"\n'))
    with pytest.raises(ProfileError, match="state_root"):
        prof.load_effective()


def test_good_state_roots(monkeypatch, tmp_path):
    """Check: good state roots."""
    for root in ["/var/lib/orama", "C:\\\\ProgramData\\\\Oramasys", "/mnt/data"]:
        _env(monkeypatch, tmp_path, _node(f'    state_root: "{root}"\n'))
        assert prof.load_effective().state_root


def test_server_needs_endpoint(monkeypatch, tmp_path):
    """Check: server needs endpoint."""
    text = "version: 1\nnodes:\n  - id: srv\n    os: linux\n    role: primary-server\n"
    _env(monkeypatch, tmp_path, text)
    with pytest.raises(ProfileError, match="endpoint"):
        prof.load_effective()


@pytest.mark.parametrize("extra", ["    bogus: 1\n", "    identity:\n      bogus: 1\n"])
def test_unknown_node_keys_refused(monkeypatch, tmp_path, extra):
    """Check: unknown node keys refused."""
    _env(monkeypatch, tmp_path, _node(extra))
    with pytest.raises(ProfileError):
        prof.load_effective()


def test_unknown_top_level_key_refused(monkeypatch, tmp_path):
    """Check: unknown top level key refused."""
    _env(monkeypatch, tmp_path, BASE + "extra: 1\n")
    with pytest.raises(ProfileError):
        prof.load_effective()


def test_serves_other_than_verify_refused(monkeypatch, tmp_path):
    """Check: serves other than verify refused."""
    _env(monkeypatch, tmp_path, _node("    serves: [verify, sign]\n"))
    with pytest.raises(ProfileError):
        prof.load_effective()


def test_check_startup_refuses_grant_on_client(monkeypatch, tmp_path):
    """Check: check startup refuses grant on client."""
    _env(monkeypatch, tmp_path, BASE, node="cli")
    eff = prof.load_effective()
    with pytest.raises(StartupRefused):
        prof.check_startup(eff, {"ORAMA_GRANT_SERVING": "enabled"})
    prof.check_startup(eff, {})
    server = prof.EffectiveNode("s", "linux", "primary-server", "applicable", "profile")
    prof.check_startup(server, {"ORAMA_GRANT_SERVING": "enabled"})


def test_serving_permitted_needs_all_three(monkeypatch, tmp_path):
    """Check: serving permitted needs all three."""
    _env(monkeypatch, tmp_path, BASE)
    eff = prof.load_effective()

    def approved(effective):
        """Stand-in D6 matcher that always approves."""
        return True

    on = {"ORAMA_GRANT_SERVING": "enabled"}
    assert prof.serving_permitted(eff, {}) is False  # profile alone
    assert prof.serving_permitted(eff, {}, approved) is False  # no env var
    assert prof.serving_permitted(eff, on) is False  # no approval (default)
    assert prof.serving_permitted(eff, on, approved) is True
    client = prof.EffectiveNode("c", "linux", "client", "not-applicable", "profile")
    assert prof.serving_permitted(client, on, approved) is False


def test_serving_permitted_requires_the_literal_true_approval(monkeypatch, tmp_path):
    """A truthy matcher result cannot activate serving."""
    _env(monkeypatch, tmp_path, BASE)
    effective = prof.load_effective()
    enabled = {"ORAMA_GRANT_SERVING": "enabled"}
    assert prof.serving_permitted(effective, enabled, lambda _: 1) is False


def _alternatives() -> dict[str, str]:
    """Extract the commented alternative profiles from the example file."""
    out, cur, name = {}, None, None
    for line in EXAMPLE.read_text(encoding="utf-8").splitlines():
        if line.startswith("#@alt-start"):
            name, cur = line.split()[1], []
        elif line.startswith("#@alt-end"):
            out[name] = "\n".join(cur) + "\n"
            cur = None
        elif cur is not None:
            cur.append(re.sub(r"^# ?", "", line))
    return out


def _example_cases():
    """Return (profile text, node id, platform, expected role) per example."""
    text = EXAMPLE.read_text(encoding="utf-8")
    alts = _alternatives()
    return [
        (text, "mac-studio", "darwin", "primary-server"),
        (text, "win-node", "win32", "client"),
        (text, "win-5080", "win32", "client"),
        (alts["windows-only"], "win-node", "win32", "primary-server"),
        (alts["linux-only"], "lnx-1", "linux", "primary-server"),
        (alts["windows-primary-mac-client"], "win-node", "win32", "primary-server"),
        (alts["windows-primary-mac-client"], "mac-studio", "darwin", "client"),
    ]


def test_example_profiles_validate(monkeypatch, tmp_path):
    """Check: example profiles validate."""
    assert len(_alternatives()) == 3
    for text, node, platform, role in _example_cases():
        _env(monkeypatch, tmp_path, text, node=node, platform=platform)
        assert prof.load_effective().role == role, (node, platform)


def test_example_is_ip_free():
    """Check: example is ip free."""
    assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", EXAMPLE.read_text(encoding="utf-8"))


def _cli(monkeypatch, tmp_path, text, args, **kw):
    """Run the CLI with a faked environment; return the exit code."""
    _env(monkeypatch, tmp_path, text, **kw)
    return prof.main(args)


def test_cli_exit_codes(monkeypatch, tmp_path, capsys):
    """Check: cli exit codes."""
    assert _cli(monkeypatch, tmp_path, BASE, ["validate"]) == 0
    assert _cli(monkeypatch, tmp_path, None, ["validate"]) == 0
    assert "not-applicable" in capsys.readouterr().out
    assert _cli(monkeypatch, tmp_path, "version: [", ["validate"]) == 2
    assert _cli(monkeypatch, tmp_path, BASE, ["validate"], platform="darwin") == 2
    assert _cli(monkeypatch, tmp_path, BASE, ["validate"], node="cli",
                ORAMA_GRANT_SERVING="enabled") == 2
    capsys.readouterr()
    assert _cli(monkeypatch, tmp_path, BASE, ["show"]) == 0
    assert json.loads(capsys.readouterr().out)["role"] == "primary-server"


def test_plan_server_text_and_env(monkeypatch, tmp_path, capsys):
    """Check: plan server text and env."""
    for platform, marker in [("linux", "orama-serve"), ("darwin", "_orama-serve"),
                             ("win32", "pywin32")]:
        text = BASE.replace("os: linux", f"os: {OS_BY_PLATFORM[platform]}")
        assert _cli(monkeypatch, tmp_path, text, ["plan"], platform=platform) == 0
        out = capsys.readouterr().out
        assert marker in out and "Operator-only" in out
        assert not re.search(r"password|token|secret|private key", out, re.I)
    assert _cli(monkeypatch, tmp_path, BASE, ["plan", "--format", "env"]) == 0
    env_out = capsys.readouterr().out
    assert "ORAMA_NODE_ROLE=primary-server" in env_out
    assert "GRANT_SERVING" not in env_out


def test_plan_client_has_endpoint_only(monkeypatch, tmp_path, capsys):
    """Check: plan client has endpoint only."""
    assert _cli(monkeypatch, tmp_path, BASE, ["plan"], node="cli") == 0
    out = capsys.readouterr().out
    assert "srv.example:8443" in out
    assert not re.search(r"useradd|dscl|New-LocalUser|sc\.exe|pywin32|account|Operator", out)
    assert _cli(monkeypatch, tmp_path, BASE, ["plan", "--format", "env"], node="cli") == 0
    assert "ORAMA_SERVING_ENDPOINT=srv.example:8443" in capsys.readouterr().out



def _hosts(monkeypatch, tmp_path, ids, wanted, **kw):
    """Load a profile of client nodes `ids` with ORAMA_NODE_ID=wanted."""
    nodes = "".join(f"  - id: {i}\n    os: linux\n" for i in ids)
    _env(monkeypatch, tmp_path, "version: 1\nnodes:\n" + nodes, node=wanted, **kw)
    return prof.load_effective()


def test_selection_is_exact_not_prefix(monkeypatch, tmp_path):
    """Check: srv and srv.lab are distinct nodes."""
    eff = _hosts(monkeypatch, tmp_path, ["srv", "srv.lab"], "SRV.lab")
    assert eff.node_id == "srv.lab"


@pytest.mark.parametrize("host", ["srv.home", "SRV.local", "srv.", "mac.evil", "\u017frv"])
def test_hostname_must_equal_an_id(monkeypatch, tmp_path, host):
    """Check: near-miss hostnames select nothing."""
    _env(monkeypatch, tmp_path, BASE, node=None)
    monkeypatch.setattr(prof, "_hostname", lambda: host)
    eff = prof.load_effective()
    assert (eff.role, eff.source) == ("client", "no-matching-node")


def test_hostname_exact_match_and_env_wins(monkeypatch, tmp_path):
    """Check: an exact hostname selects; ORAMA_NODE_ID takes priority."""
    _env(monkeypatch, tmp_path, BASE, node=None)
    monkeypatch.setattr(prof, "_hostname", lambda: "SRV")
    assert prof.load_effective().node_id == "srv"
    monkeypatch.setenv("ORAMA_NODE_ID", "cli")
    assert prof.load_effective().node_id == "cli"


def test_non_ascii_blank_and_colliding_ids_refused(monkeypatch, tmp_path):
    """Check: non-ASCII, blank and colliding ids are errors."""
    for ids in (["\u017frv"], ["' '"], ["A", "a"], ["a", "'a '"]):
        with pytest.raises(ProfileError):
            _hosts(monkeypatch, tmp_path, ids, "a")


@pytest.mark.parametrize(
    "text",
    [
        "version: 1\nnodes:\n  - id: s\n    os: linux\n    role: client\n    role: off\n",
        "version: 1\nnodes:\n  - id: s\n    os: linux\n    role: off\n    role: client\n",
        "version: 1\nversion: 1\nnodes: []\n",
    ],
)
def test_duplicate_yaml_keys_refused(monkeypatch, tmp_path, text):
    """Check: duplicate mapping keys are errors at any level."""
    _env(monkeypatch, tmp_path, text, node="s")
    with pytest.raises(ProfileError, match="duplicate"):
        prof.load_effective()


@pytest.mark.parametrize("value", ["0", "false", " ", "yes", "true", "2"])
def test_grant_flag_must_be_exactly_one(monkeypatch, tmp_path, value):
    """Check: any non-empty value other than 1 refuses."""
    _env(monkeypatch, tmp_path, BASE)
    eff = prof.load_effective()
    with pytest.raises(ProfileError):
        prof.serving_permitted(eff, {"ORAMA_GRANT_SERVING": value})
    with pytest.raises(ProfileError):
        prof.check_startup(eff, {"ORAMA_GRANT_SERVING": value})


def test_grant_flag_empty_is_unset(monkeypatch, tmp_path):
    """Check: empty ORAMA_GRANT_SERVING counts as unset."""
    _env(monkeypatch, tmp_path, BASE, node="cli")
    eff = prof.load_effective()
    prof.check_startup(eff, {"ORAMA_GRANT_SERVING": ""})
    assert prof.serving_permitted(eff, {"ORAMA_GRANT_SERVING": ""}) is False


def test_missing_pyyaml_is_clear_error(monkeypatch, tmp_path, capsys):
    """Check: a missing PyYAML exits 2 with a clear message."""
    _env(monkeypatch, tmp_path, BASE)
    monkeypatch.setitem(prof.sys.modules, "yaml", None)
    with pytest.raises(ProfileError, match="PyYAML"):
        prof.load_effective()
    assert prof.main(["validate"]) == 2
    assert "PyYAML" in capsys.readouterr().err


@pytest.mark.parametrize(
    "principal",
    ["00", "-1", "+0", "0x0", "0.0", "S-1-5-21-1-2-3-500", "S-1-5-21-1-2-3-512",
     "S-1-5-80-0", "S-1-5-", "s-1-5-18", "ro\u200bot", "r\u00f6ot", "root ", "",
     "S-1-5-21-1-2-3-500 ", "S-1-5-018", "S-1-5-21-1-2-3-0500", "S-1-5-21-１"],
)
def test_principal_strictness(monkeypatch, tmp_path, principal):
    """Check: malformed or privileged principals are refused."""
    extra = f'    identity:\n      expected_principal: "{principal}"\n'
    _env(monkeypatch, tmp_path, _node(extra))
    with pytest.raises(ProfileError):
        prof.load_effective()


@pytest.mark.parametrize(
    "principal", ["501", "S-1-5-21-1-2-3-1001", "_orama-serve", "NT SERVICE\\\\OramaServe"]
)
def test_principal_accepted(monkeypatch, tmp_path, principal):
    """Check: ordinary principals are accepted."""
    extra = f'    identity:\n      expected_principal: "{principal}"\n'
    _env(monkeypatch, tmp_path, _node(extra))
    assert prof.load_effective().role == "primary-server"


@pytest.mark.parametrize(
    "root",
    ["/var/../etc", "C:\\\\x\\\\..\\\\y", "/var/lib\\u0000x", "/mnt/wsl/x",
     "/run/desktop/mnt/host/c", "/a\\nb"],
)
def test_state_root_extra_refusals(monkeypatch, tmp_path, root):
    """Check: dot-dot, control chars and WSL/Docker mounts are refused."""
    _env(monkeypatch, tmp_path, _node(f'    state_root: "{root}"\n'))
    with pytest.raises(ProfileError, match="state_root"):
        prof.load_effective()


@pytest.mark.parametrize(
    "endpoint", ["srv", "srv:0", "srv:65536", "srv:x", "http://srv:1", "a b:1", ":80"]
)
def test_endpoint_must_be_host_port(monkeypatch, tmp_path, endpoint):
    """Check: malformed endpoints are refused."""
    text = (
        "version: 1\nnodes:\n  - id: s\n    os: linux\n    role: primary-server\n"
        f"    endpoint: '{endpoint}'\n"
    )
    _env(monkeypatch, tmp_path, text, node="s")
    with pytest.raises(ProfileError):
        prof.load_effective()


def test_size_cap(monkeypatch, tmp_path):
    """Check: a profile over 256 KiB is an error."""
    _env(monkeypatch, tmp_path, BASE + "#" + "x" * (256 * 1024) + "\n")
    with pytest.raises(ProfileError, match="size"):
        prof.load_effective()


@pytest.mark.parametrize("version", ["true", "1.0", "'1'", "2"])
def test_version_strict(monkeypatch, tmp_path, version):
    """Check: only the integer 1 is a valid version."""
    _env(monkeypatch, tmp_path, BASE.replace("version: 1", f"version: {version}"))
    with pytest.raises(ProfileError):
        prof.load_effective()


def test_grant_flag_one_is_refused_only_enabled_accepted():
    """"1" is not the contract value; only exact "enabled" counts (matches serve script)."""
    with pytest.raises(prof.ProfileError):
        prof._grant_flag({"ORAMA_GRANT_SERVING": "1"})
    assert prof._grant_flag({"ORAMA_GRANT_SERVING": "enabled"}) is True


def test_deeply_nested_yaml_is_profile_error(monkeypatch, tmp_path):
    """A 3,000-level flow sequence is a ProfileError (exit 2), not RecursionError."""
    _env(monkeypatch, tmp_path, "[" * 3000)
    with pytest.raises(ProfileError):
        prof.load_effective()
    assert prof.main(["validate"]) == 2


def test_node_id_with_surrounding_whitespace_refused():
    """'a ' and ' a' are refused rather than silently stripped."""
    for bad in ("a ", " a"):
        text = BASE.replace("id: srv", "id: '" + bad + "'")
        with pytest.raises(ProfileError):
            prof.parse_profile(text)


def test_enable_value_matches_serve_script():
    """The profile's switch value equals the literal in serve_with_phylax_grants.py."""
    import ast

    script = Path(__file__).resolve().parents[2] / "scripts" / "serve_with_phylax_grants.py"
    tree = ast.parse(script.read_text(encoding="utf-8"))
    found = {
        t.id: ast.literal_eval(n.value)
        for n in tree.body
        if isinstance(n, ast.Assign)
        for t in n.targets
        if isinstance(t, ast.Name) and t.id in ("ENABLE_VARIABLE", "ENABLED")
    }
    assert found["ENABLED"] == prof.GRANT_SERVING_ENABLED
    assert found["ENABLE_VARIABLE"] == prof.ENV_GRANT_SERVING


def test_unreadable_profile_on_value_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Check: ValueError while opening or reading profile falls back safely."""
    _env(monkeypatch, tmp_path, BASE)

    def boom(self: Path, *args: object, **kwargs: object) -> object:
        """Simulate ValueError during file access."""
        raise ValueError("stream corrupted")

    monkeypatch.setattr(Path, "open", boom)
    eff = prof.load_effective()
    assert (eff.role, eff.source) == ("client", "unreadable-profile")


@pytest.mark.parametrize(
    "account",
    ["root", "Administrator", "SYSTEM", "LocalSystem", "NT AUTHORITY\\SYSTEM",
     "BUILTIN\\Administrators", "S-1-5-18"],
)
def test_privileged_server_account_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, account: str
) -> None:
    """Check: privileged accounts in identity.server_account are refused."""
    extra = f"    identity:\n      server_account: '{account}'\n      signer_account: safe-signer\n"
    _env(monkeypatch, tmp_path, _node(extra))
    with pytest.raises(ProfileError, match="server_account"):
        prof.load_effective()


@pytest.mark.parametrize(
    "account",
    ["root", "Administrator", "SYSTEM", "LocalSystem", "NT AUTHORITY\\SYSTEM",
     "BUILTIN\\Administrators", "S-1-5-18"],
)
def test_privileged_signer_account_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, account: str
) -> None:
    """Check: privileged accounts in identity.signer_account are refused."""
    extra = f"    identity:\n      server_account: safe-srv\n      signer_account: '{account}'\n"
    _env(monkeypatch, tmp_path, _node(extra))
    with pytest.raises(ProfileError, match="signer_account"):
        prof.load_effective()


@pytest.mark.parametrize(
    "raw_path",
    ["/Library/Application Support/Oramasys", "C:\\ProgramData\\Oramasys"],
)
def test_plan_env_format_quotes_and_roundtrips(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str], raw_path: str
) -> None:
    """Check: plan --format env quotes values safely for POSIX shell round-trip."""
    import shlex

    extra = f"    state_root: '{raw_path}'\n"
    text = _node(extra)
    assert _cli(monkeypatch, tmp_path, text, ["plan", "--format", "env"]) == 0
    env_out = capsys.readouterr().out
    assignments: dict[str, str] = {}
    for line in env_out.splitlines():
        if line.strip():
            k, v = line.split("=", 1)
            tokens = shlex.split(v, posix=True)
            assert len(tokens) == 1, f"Expected 1 token for {v}, got {tokens}"
            assignments[k] = tokens[0]
    assert assignments["ORAMA_STATE_ROOT"] == raw_path
    assert assignments["ORAMA_NODE_ROLE"] == "primary-server"
    assert assignments["ORAMA_NODE_ID"] == "srv"
    assert assignments["ORAMA_SERVING_ENDPOINT"] == "srv.example:8443"
