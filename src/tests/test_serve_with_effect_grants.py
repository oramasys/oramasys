"""Inert-effect composition root: ORAMA_INERT_EFFECTS alone never wires a sender (fail closed)."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest
from httpx import ASGITransport, AsyncClient

from orama.api.authz import AUTHENTICATED_CONTROL_PLANE_PRINCIPAL
from orama.api.capabilities import CapabilityConfig, StartupRefused
from orama.graph.effect_grant_composition import FinalBoundaryPorts
from tests.test_capabilities import BIN, CFG, Signer, make_record, signed
from tests.test_dispatch_attempts import ATTEMPT, ISSUER, NOW, FakeRevocations
from tests.test_effect_grant_composition import FixedVerifier, bound_harness, untouched
from tests.test_final_boundary import Approvals

SCRIPT = Path(__file__).parents[2] / "scripts" / "serve_with_effect_grants.py"
TOKEN = "test-control-plane-token-32b"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture(autouse=True)
def configured_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """Configure the shared bearer that protects the inert route."""
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", TOKEN)
    monkeypatch.delenv("ORAMA_INSECURE_DEV", raising=False)


@pytest.fixture
def module() -> ModuleType:
    """Load the composition root from its file without importing Phylax."""
    name = "test_serve_with_effect_grants_script"
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    assert spec is not None and spec.loader is not None
    loaded = importlib.util.module_from_spec(spec)
    sys.modules[name] = loaded
    spec.loader.exec_module(loaded)
    return loaded


class Opener:
    """Verifier opener double that records whether composition tried to open authority state."""

    def __init__(self, verifier=None) -> None:
        """Hold the verifier to hand out (None refuses to be called at all)."""
        self.verifier, self.calls, self.closed = verifier, [], 0

    def __call__(self, state_dir: Path):
        """Record the call and return a closable verifier, or fail when none was expected."""
        self.calls.append(state_dir)
        if self.verifier is None:
            raise AssertionError("composition opened the verifier without an effective effects bit")
        opener = self

        class Closable:
            """Wrap the effect-grant verifier double with the close the composition root calls."""

            def verify(self, wire: bytes):
                """Delegate verification to the wrapped double."""
                return opener.verifier.verify(wire)

            def close(self) -> None:
                """Count the release of the verifier."""
                opener.closed += 1

        return Closable()


async def post(app, body) -> object:
    """POST an authenticated inert send, running the app lifespan around it."""
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            return await client.post("/effects/inert", json=body, headers=AUTH)


def environ(tmp_path: Path, store: Path | None = None, **extra: str) -> dict[str, str]:
    """Return a composition environment that requests inert effects."""
    values = {
        "ORAMA_INERT_EFFECTS": "enabled",
        "PHYLAX_STATE_DIR": str(tmp_path / "phylax"),
        "ORAMA_EFFECT_STORE": str(store or tmp_path / "missing.sqlite"),
    }
    values.update(extra)
    return values


def dark(response) -> None:
    """Assert the contract's 404 for a route that is not exposed."""
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "serving.route_not_exposed"


async def test_requesting_inert_effects_without_an_effective_effects_bit_wires_no_sender(
    module: ModuleType, tmp_path: Path
) -> None:
    """ORAMA_INERT_EFFECTS=enabled with no capability record: no sender, 404, no dispatch."""
    b = bound_harness(tmp_path, principal=AUTHENTICATED_CONTROL_PLANE_PRINCIPAL)
    try:
        opener = Opener()
        app = module.build_app(environ(tmp_path, b.h.path), open_verifier=opener)
        dark(await post(app, {"attempt_id": ATTEMPT}))
        assert opener.calls == []
        untouched(b)
    finally:
        b.h.store.close()


async def test_an_all_false_capability_record_also_wires_no_sender(
    module: ModuleType, tmp_path: Path
) -> None:
    """A valid record whose effects bit is false keeps the route dark and opens nothing."""
    record = tmp_path / "capability.json"
    record.write_text(json.dumps(make_record()), encoding="utf-8")
    opener = Opener()
    app = module.build_app(
        environ(
            tmp_path, ORAMA_CAPABILITY_RECORD=str(record),
            ORAMA_EXPECTED_BINARY_DIGEST=BIN, ORAMA_EXPECTED_CONFIG_DIGEST=CFG,
        ),
        open_verifier=opener,
    )
    dark(await post(app, {"attempt_id": ATTEMPT}))
    assert opener.calls == []


@pytest.mark.parametrize("value", [None, " enabled ", "true", "ENABLED"])
async def test_only_the_exact_request_value_is_a_request(
    module: ModuleType, tmp_path: Path, value: str | None
) -> None:
    """Anything but the exact value leaves composition untouched and the route dark."""
    values = environ(tmp_path)
    values.pop("ORAMA_INERT_EFFECTS")
    if value is not None:
        values["ORAMA_INERT_EFFECTS"] = value
    opener = Opener()
    dark(await post(module.build_app(values, open_verifier=opener), {"attempt_id": ATTEMPT}))
    assert opener.calls == []


def test_an_unsigned_effects_record_refuses_at_startup(module: ModuleType, tmp_path: Path) -> None:
    """A true effects bit without a verified operator signature fails closed before composition."""
    record = tmp_path / "capability.json"
    record.write_text(json.dumps(make_record(effects=True)), encoding="utf-8")
    opener = Opener()
    with pytest.raises(StartupRefused, match="capability.unsigned_enablement"):
        module.build_app(
            environ(
                tmp_path, ORAMA_CAPABILITY_RECORD=str(record),
                ORAMA_EXPECTED_BINARY_DIGEST=BIN, ORAMA_EXPECTED_CONFIG_DIGEST=CFG,
            ),
            open_verifier=opener,
        )
    assert opener.calls == []


def effective() -> CapabilityConfig:
    """An effective effects bit under a test signature verifier (no real one exists in R0-2)."""
    return CapabilityConfig(
        record=signed(effects=True), expected_binary_digest=BIN, expected_config_digest=CFG,
        signature_verifier=Signer(), permit_verifier=object(),
    )


def test_effective_effects_without_final_boundary_ports_refuse_at_startup(
    module: ModuleType, tmp_path: Path
) -> None:
    """Even an effective bit cannot wire a sender without the final-boundary ports."""
    opener = Opener()
    with pytest.raises(StartupRefused, match="startup.effects_without_permit_verifier"):
        module.build_app(environ(tmp_path), capability_config=effective(), open_verifier=opener)
    assert opener.calls == []


async def test_effective_effects_with_ports_send_only_through_the_final_boundary(
    module: ModuleType, tmp_path: Path
) -> None:
    """The fully composed root wires the canonical sender; the send passes the final boundary."""
    b = bound_harness(tmp_path, principal=AUTHENTICATED_CONTROL_PLANE_PRINCIPAL)
    b.h.store.close()
    approvals = Approvals()
    opener = Opener(FixedVerifier(b.verifier.projection))
    app = module.build_app(
        environ(tmp_path, b.h.path), capability_config=effective(), open_verifier=opener,
        final_boundary=FinalBoundaryPorts(approvals, FakeRevocations(), ISSUER), clock=lambda: NOW,
    )
    response = await post(app, {"attempt_id": ATTEMPT})
    assert response.status_code == 200 and response.json()["receipt"]["outcome"] == "confirmed"
    assert len(approvals.seen) == 1 and opener.closed == 1
