"""Composition-root contract for fail-closed, verify-only grant serving."""
from __future__ import annotations

import ast
import importlib.util
import sqlite3
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from orama.api.authz import AUTHENTICATED_CONTROL_PLANE_PRINCIPAL
from orama.api.server import create_app
from orama.graph.execution_guard import StepLedger
from orama.graph.grant_verifier import AdjustmentGrantConsumer, AdjustmentGrantRefused
from tests.test_adjustment_grant_consumer import StubVerifier, grant, unknown_hold, wire_for

SCRIPT = Path(__file__).parents[2] / "scripts" / "serve_with_phylax_grants.py"
TOKEN = "test-control-plane-token-32b"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture(autouse=True)
def configured_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """Configure the shared bearer that protects grant consumption."""
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", TOKEN)
    monkeypatch.delenv("ORAMA_INSECURE_DEV", raising=False)


@pytest.fixture
def serving_module() -> ModuleType:
    """Load the executable composition root without importing Phylax in unit tests."""
    name = "test_serve_with_phylax_grants"
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


async def health(app: Any) -> dict[str, str]:
    """Return the public health payload from an ASGI application."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/health")
    assert response.status_code == 200
    return response.json()


async def adjustment(app: Any, payload: str) -> Any:
    """Submit one authenticated adjustment to an ASGI application."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        return await client.post("/adjustments", json={"grant": payload}, headers=AUTH)


async def test_default_and_whitespace_activation_leave_grants_disabled(
    serving_module: ModuleType, tmp_path: Path
) -> None:
    """Only the exact activation value may request verifier and ledger composition."""
    called = False

    def opener(_environ: dict[str, str]) -> tuple[StubVerifier, object]:
        nonlocal called
        called = True
        raise AssertionError("disabled composition called the verifier opener")

    ledger = tmp_path / "ledger.sqlite3"
    for value in (None, " enabled ", "true"):
        environ = {"ORAMA_LEDGER_PATH": str(ledger)}
        if value is not None:
            environ[serving_module.ENABLE_VARIABLE] = value
        app = serving_module.build_app(environ, open_verifier=opener)
        assert (await health(app))["grants"] == "disabled"
    assert called is False
    assert not ledger.exists()


def test_requested_composition_names_only_missing_variables(serving_module: ModuleType) -> None:
    """An enabled process refuses incomplete configuration without leaking values."""
    with pytest.raises(SystemExit, match="ORAMA_LEDGER_PATH, PHYLAX_STATE_DIR"):
        serving_module.build_app({serving_module.ENABLE_VARIABLE: serving_module.ENABLED})


@pytest.mark.parametrize(
    "failure",
    [ImportError(), OSError(), RuntimeError(), ValueError()],
)
async def test_failed_verifier_open_is_unavailable_and_never_constructs_a_ledger(
    serving_module: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: Exception
) -> None:
    """Open failures keep ordinary service alive and leave the adjustment store untouched."""
    constructed = False

    def no_ledger(_path: Path) -> None:
        nonlocal constructed
        constructed = True
        raise AssertionError("unavailable verifier constructed a ledger")

    def opener(_environ: dict[str, str]) -> tuple[StubVerifier, object]:
        raise failure

    monkeypatch.setattr(serving_module, "StepLedger", no_ledger)
    ledger = tmp_path / "existing-or-new.sqlite3"
    app = serving_module.build_app(
        {
            serving_module.ENABLE_VARIABLE: serving_module.ENABLED,
            "ORAMA_LEDGER_PATH": str(ledger),
            "PHYLAX_STATE_DIR": str(tmp_path / "phylax-state"),
        },
        open_verifier=opener,
    )

    assert (await health(app))["grants"] == "unavailable"
    response = await adjustment(app, "{}")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "deny.verifier_unavailable"
    assert constructed is False
    assert not ledger.exists()


async def test_ready_composition_spends_a_verified_grant_and_closes_on_shutdown(
    serving_module: ModuleType, tmp_path: Path
) -> None:
    """A managed verifier is consumed only through the existing adjustment boundary."""
    ledger_path = tmp_path / "ledger.sqlite3"
    ledger = StepLedger(ledger_path)
    epoch, hold = unknown_hold(ledger)
    verified = grant(
        ledger,
        hold,
        epoch,
        principal=AUTHENTICATED_CONTROL_PLANE_PRINCIPAL,
    )
    closed = 0

    def close() -> None:
        nonlocal closed
        closed += 1

    def opener(_environ: dict[str, str]) -> tuple[StubVerifier, object]:
        return StubVerifier(result=verified), close

    app = serving_module.build_app(
        {
            serving_module.ENABLE_VARIABLE: serving_module.ENABLED,
            "ORAMA_LEDGER_PATH": str(ledger_path),
            "PHYLAX_STATE_DIR": str(tmp_path / "phylax-state"),
        },
        open_verifier=opener,
    )

    assert (await health(app))["grants"] == "ready"
    response = await adjustment(app, wire_for(verified).decode())
    assert response.status_code == 200
    async with app.router.lifespan_context(app):
        pass
    assert closed == 1


async def test_ready_capability_stays_ready_when_one_grant_is_refused(
    serving_module: ModuleType, tmp_path: Path
) -> None:
    """A per-request verifier result is not a global readiness transition."""
    def opener(_environ: dict[str, str]) -> tuple[StubVerifier, object]:
        return StubVerifier(error=AdjustmentGrantRefused("grant.expired")), lambda: None

    app = serving_module.build_app(
        {
            serving_module.ENABLE_VARIABLE: serving_module.ENABLED,
            "ORAMA_LEDGER_PATH": str(tmp_path / "ledger.sqlite3"),
            "PHYLAX_STATE_DIR": str(tmp_path / "phylax-state"),
        },
        open_verifier=opener,
    )

    response = await adjustment(app, "{}")
    assert response.status_code == 400  # a verification refusal: its public deny code, never a conflict
    assert response.json()["error"]["code"] == "deny.malformed_grant"
    assert (await health(app))["grants"] == "ready"


def test_resource_cleanup_releases_the_ledger_when_verifier_close_fails(
    serving_module: ModuleType, tmp_path: Path
) -> None:
    """A shutdown error cannot leave the composition-created ledger connection open."""
    ledger = StepLedger(tmp_path / "ledger.sqlite3")

    def fail() -> None:
        raise RuntimeError("verifier shutdown failed")

    with pytest.raises(RuntimeError, match="verifier shutdown failed"):
        serving_module.close_resources(fail, ledger)
    with pytest.raises(sqlite3.ProgrammingError):
        ledger._db.execute("SELECT 1")


def test_verifier_cleanup_warning_includes_only_a_sanitized_cause(
    serving_module: ModuleType, caplog: pytest.LogCaptureFixture
) -> None:
    """Cleanup diagnostics identify the failure class without retaining exception text."""
    def fail() -> None:
        raise OSError("private state detail")

    with caplog.at_level("WARNING", logger="orama.serve"):
        serving_module._release_verifier(fail)  # noqa: SLF001 - exercise cleanup boundary

    assert any(
        getattr(record, "reason", None) == "OSError"
        and record.getMessage() == "verifier cleanup failed: OSError"
        for record in caplog.records
    )
    assert "private state detail" not in caplog.text


def test_create_app_rejects_empty_or_contradictory_capability_values(tmp_path: Path) -> None:
    """Only a ready app may carry a grant consumer, and empty is not a state."""
    with pytest.raises(ValueError, match="unknown grant capability"):
        create_app(grant_capability="")
    with pytest.raises(ValueError, match="requires exactly a wired consumer"):
        create_app(grant_capability="ready")
    with pytest.raises(ValueError, match="requires exactly a wired consumer"):
        create_app(
            adjustment_consumer=AdjustmentGrantConsumer(StepLedger(tmp_path / "ledger.sqlite3")),
            grant_capability="disabled",
        )


def test_composition_uses_no_issuer_import_or_secret_configuration_symbol() -> None:
    """The process imports the verifier only and exposes no issuer configuration."""
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "phylax"
        for alias in node.names
    }
    literals = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert {"GrantAuthorityConfig", "open_grant_authority"}.isdisjoint(imported)
    assert not {"PHYLAX_SEED_ROOT", "PHYLAX_KEY_ID", "PHYLAX_SEED_REF", "PHYLAX_P5_SECRET_REF"} & literals


def _enabled_environ(serving_module: ModuleType, tmp_path: Path) -> dict[str, str]:
    """Return a complete enabled configuration pointing at temporary paths."""
    return {
        serving_module.ENABLE_VARIABLE: serving_module.ENABLED,
        "ORAMA_LEDGER_PATH": str(tmp_path / "ledger.sqlite3"),
        "PHYLAX_STATE_DIR": str(tmp_path / "phylax-state"),
    }


async def test_a_ledger_open_failure_closes_the_verifier_and_is_unavailable(
    serving_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The verifier must not leak, and the capability must not crash startup."""
    closed = 0

    def close() -> None:
        nonlocal closed
        closed += 1

    def broken_ledger(_path: Path) -> None:
        raise OSError("ledger path is unusable")

    monkeypatch.setattr(serving_module, "StepLedger", broken_ledger)
    with caplog.at_level("WARNING", logger="orama.serve"):
        app = serving_module.build_app(
            _enabled_environ(serving_module, tmp_path),
            open_verifier=lambda _environ: (StubVerifier(), close),
        )
    assert (await health(app))["grants"] == "unavailable"
    assert closed == 1
    assert any(
        getattr(record, "reason", None) == "OSError"
        and record.getMessage() == "grant ledger unavailable: OSError"
        for record in caplog.records
    )
    response = await adjustment(app, "{}")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "deny.verifier_unavailable"


async def test_a_failing_verifier_cleanup_still_closes_the_ledger_through_the_app(
    serving_module: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Shutdown errors surface, and the composition-created ledger is released regardless."""
    created: list[StepLedger] = []

    def tracking_ledger(path: Path) -> StepLedger:
        created.append(StepLedger(path))
        return created[-1]

    def fail() -> None:
        raise RuntimeError("verifier shutdown failed")

    monkeypatch.setattr(serving_module, "StepLedger", tracking_ledger)
    app = serving_module.build_app(
        _enabled_environ(serving_module, tmp_path),
        open_verifier=lambda _environ: (StubVerifier(), fail),
    )
    with pytest.raises(RuntimeError, match="verifier shutdown failed"):
        async with app.router.lifespan_context(app):
            pass
    assert len(created) == 1
    with pytest.raises(sqlite3.ProgrammingError):
        created[0]._db.execute("SELECT 1")


def test_the_default_opener_builds_only_a_verifier_config_and_needs_lifecycle_cleanup(
    serving_module: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The real opener passes state_dir and verifier_id only, and refuses a verifier with no close."""
    seen: dict[str, Any] = {}

    class FakeConfig:
        def __init__(self, **kwargs: Any) -> None:
            seen["config"] = kwargs

    class WithClose:
        def __init__(self) -> None:
            self.closed = 0

        def close(self) -> None:
            self.closed += 1

    class WithoutClose:
        pass

    module = ModuleType("phylax")
    module.GrantVerifierConfig = FakeConfig  # type: ignore[attr-defined]
    module.open_grant_verifier = lambda config: seen.setdefault("verifier", WithClose())  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "phylax", module)

    environ = {"PHYLAX_STATE_DIR": str(tmp_path / "state"), "PHYLAX_VERIFIER_ID": "consumer-7"}
    verifier, close = serving_module.open_phylax_verifier(environ)
    assert set(seen["config"]) == {"state_dir", "verifier_id"}
    assert seen["config"]["verifier_id"] == "consumer-7"
    close()
    assert verifier.closed == 1

    module.open_grant_verifier = lambda config: WithoutClose()  # type: ignore[attr-defined]
    with pytest.raises(RuntimeError, match="lifecycle cleanup"):
        serving_module.open_phylax_verifier(environ)


def test_the_composition_never_names_issuer_authority_in_code() -> None:
    """No import, name or attribute in the script refers to the issuer side."""
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    forbidden = {
        "open_grant_authority", "GrantAuthorityConfig", "FileSeedProvider", "verifier_adapter",
    }
    used = {
        node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
    } | {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    } | {
        alias.name for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert forbidden.isdisjoint(used)
    bare = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Import) and any(a.name.split(".")[0] == "phylax" for a in node.names)
    ]
    assert bare == [], "import the verifier names explicitly, never the whole package"
