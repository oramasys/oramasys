"""File-backed Phylax issue -> read-only verify -> Oramasys consume, through the real opener.

Nothing is stubbed on the Phylax side: a real authority issues and revokes grants against a
private state directory, and the serving composition opens only the read-only verifier from
that directory with its default opener.
"""
from __future__ import annotations

import importlib.util
import sqlite3
import sys
from pathlib import Path
from types import ModuleType

import pytest
from httpx import ASGITransport, AsyncClient

from orama.api.authz import AUTHENTICATED_CONTROL_PLANE_PRINCIPAL
from orama.graph.execution_guard import StepLedger
from tests.test_adjustment_grant_consumer import RUN, unknown_hold

from phylax import (
    AdjustmentGrantRequest,
    GrantAuthorityConfig,
    open_grant_authority,
)
from phylax.grant_composition import FileSeedProvider

SCRIPT = Path(__file__).parents[3] / "scripts" / "serve_with_phylax_grants.py"
TOKEN = "interop-control-plane-token-32b"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
SEED_HEX = "11" * 32
P5_HEX = "22" * 32


@pytest.fixture(autouse=True)
def configured_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """Configure the shared bearer that protects grant consumption."""
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", TOKEN)
    monkeypatch.delenv("ORAMA_INSECURE_DEV", raising=False)


@pytest.fixture
def serving_module() -> ModuleType:
    """Load the executable composition root."""
    name = "interop_serve_with_phylax_grants"
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class World:
    """One issuer, one ledger, and the environment that composes them."""

    def __init__(self, root: Path) -> None:
        self.root = root
        seeds = root / "seeds"
        seeds.mkdir(mode=0o700)
        for name, value in (("issuer-1", SEED_HEX), ("p5-secret", P5_HEX)):
            path = seeds / name
            path.write_text(value + "\n", encoding="ascii")
            path.chmod(0o600)
        self.state = root / "state"
        self.authority = open_grant_authority(
            GrantAuthorityConfig(
                state_dir=self.state, seed_root=seeds, key_id="issuer-1",
                seed_ref="issuer-1", p5_secret_ref="p5-secret",
            )
        )
        self.ledger_path = root / "ledger.sqlite3"
        self.ledger = StepLedger(self.ledger_path)
        self._attempt = 0

    def grant_for_new_hold(self) -> tuple[object, str]:
        """Open a fresh UNKNOWN hold on the ledger and issue a grant that releases it."""
        self._attempt += 1
        attempt = f"node::interop::{self._attempt}"
        epoch, hold = unknown_hold(self.ledger, units=3, attempt=attempt)
        request = AdjustmentGrantRequest(
            principal=AUTHENTICATED_CONTROL_PLANE_PRINCIPAL, run_id=RUN, hold_id=hold.hold_id,
            kind="release", units=3, units_basis="steps",
            ledger_cost_basis=self.ledger.LEGACY_COST_BASIS, evidence_digest="a" * 64,
            hold_fence_epoch=hold.fence_epoch, consumer_lease_epoch=epoch,
            ledger_store_id=self.ledger.store_id, issuer_ref="phylax-primary",
            revocation_ref="phylax://revocations/v1",
        )
        grant = self.authority.issue(
            request, authenticated_principal="local-operator",
            operator_evidence_ref="trusted-ui://approval/1",
        )
        return grant, attempt

    def environ(self, state: Path | None = None) -> dict[str, str]:
        """Return the exact-activation environment for the composition root."""
        return {
            "ORAMA_GRANT_SERVING": "enabled",
            "ORAMA_LEDGER_PATH": str(self.ledger_path),
            "PHYLAX_STATE_DIR": str(state or self.state),
        }


@pytest.fixture
def world(tmp_path: Path) -> World:
    """Return an issuer and ledger under a private temporary root."""
    root = tmp_path / "world"
    root.mkdir(mode=0o700)
    return World(root)


async def request(app: object, method: str, path: str, **kwargs: object):
    """Send one request through an ASGI application."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        return await client.request(method, path, **kwargs)


async def test_a_grant_issued_by_phylax_is_spent_through_the_read_only_verifier(
    serving_module: ModuleType, world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ready composition verifies from files with no seed read, and an exact retry replays."""
    grant, attempt = world.grant_for_new_hold()

    def forbidden(*_a: object, **_k: object) -> bytes:
        raise AssertionError("the serving process read a signing seed")

    monkeypatch.setattr(FileSeedProvider, "load_seed", forbidden)
    app = serving_module.build_app(world.environ())

    health = await request(app, "GET", "/health")
    assert health.json()["grants"] == "ready"
    body = {"grant": grant.to_wire().decode()}
    first = await request(app, "POST", "/adjustments", json=body, headers=AUTH)
    assert first.status_code == 200
    assert world.ledger.hold_state(RUN, attempt) == "released"
    second = await request(app, "POST", "/adjustments", json=body, headers=AUTH)
    assert second.status_code == 200 and second.json() == first.json()


async def test_a_revocation_after_open_is_refused_and_readiness_does_not_change(
    serving_module: ModuleType, world: World
) -> None:
    """The retained connection, already used once, sees a later revocation exactly."""
    first, first_attempt = world.grant_for_new_hold()
    app = serving_module.build_app(world.environ())
    assert (await request(app, "GET", "/health")).json()["grants"] == "ready"

    spent = await request(
        app, "POST", "/adjustments", json={"grant": first.to_wire().decode()}, headers=AUTH
    )
    assert spent.status_code == 200  # the connection has served a read before the revoke
    # A grant issued AFTER the connection opened is visible too; then it is revoked.
    second, second_attempt = world.grant_for_new_hold()
    world.authority.revoke(second.grant_id)
    response = await request(
        app, "POST", "/adjustments", json={"grant": second.to_wire().decode()}, headers=AUTH
    )
    assert response.status_code == 503  # verification refusals are 503, never a 409 conflict
    assert response.json()["detail"]["code"] == "grant.revoked"
    assert world.ledger.hold_state(RUN, first_attempt) == "released"
    assert world.ledger.hold_state(RUN, second_attempt) == "unknown"
    assert (await request(app, "GET", "/health")).json()["grants"] == "ready"


async def test_missing_verifier_state_is_unavailable_and_never_opens_the_ledger(
    serving_module: ModuleType, world: World, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An empty private directory is not a bootstrap: unavailable, 503, ledger untouched."""
    empty = tmp_path / "empty-state"
    empty.mkdir(mode=0o700)
    constructed: list[object] = []

    def spy(path: Path) -> StepLedger:
        constructed.append(path)
        raise AssertionError("an unavailable verifier constructed a ledger")

    monkeypatch.setattr(serving_module, "StepLedger", spy)
    app = serving_module.build_app(world.environ(state=empty))

    assert (await request(app, "GET", "/health")).json()["grants"] == "unavailable"
    response = await request(app, "POST", "/adjustments", json={"grant": "{}"}, headers=AUTH)
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "adjustments_unavailable"
    assert constructed == []
    assert list(empty.iterdir()) == []


async def test_shutdown_closes_the_verifier_and_the_ledger_exactly_once(
    serving_module: ModuleType, world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Closure is asserted positively: a leaked connection warns only on Python 3.13+."""
    grant, _attempt = world.grant_for_new_hold()
    real_open = serving_module.open_phylax_verifier
    closes: list[str] = []
    opened: dict[str, object] = {}

    def recording_opener(environ: dict[str, str]):  # type: ignore[no-untyped-def]
        verifier, close = real_open(environ)
        opened["verifier"] = verifier

        def counted() -> None:
            closes.append("verifier")
            close()

        return verifier, counted

    ledgers: list[StepLedger] = []

    def tracking_ledger(path: Path) -> StepLedger:
        ledgers.append(StepLedger(path))
        return ledgers[-1]

    monkeypatch.setattr(serving_module, "StepLedger", tracking_ledger)
    app = serving_module.build_app(world.environ(), open_verifier=recording_opener)
    spent = await request(
        app, "POST", "/adjustments", json={"grant": grant.to_wire().decode()}, headers=AUTH
    )
    assert spent.status_code == 200
    assert closes == []  # not closed while serving
    async with app.router.lifespan_context(app):
        pass
    assert closes == ["verifier"]
    assert len(ledgers) == 1
    with pytest.raises(sqlite3.ProgrammingError):
        ledgers[0]._db.execute("SELECT 1")  # noqa: SLF001 - evidence the connection is closed
    with pytest.raises(Exception) as refused:
        opened["verifier"].verify(grant.to_wire())  # type: ignore[attr-defined]
    assert getattr(refused.value, "reason", None) is not None
    assert refused.value.reason.value == "verifier.unavailable"  # type: ignore[attr-defined]


async def test_a_missing_phylax_is_logged_as_not_installed_not_as_a_mystery(
    serving_module: ModuleType, world: World, monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The unavailable state names its cause class so a rollout can tell why it is off."""
    def absent(_environ: dict[str, str]):  # type: ignore[no-untyped-def]
        raise ModuleNotFoundError("No module named 'phylax'", name="phylax")

    with caplog.at_level("WARNING", logger="orama.serve"):
        app = serving_module.build_app(world.environ(), open_verifier=absent)
    assert (await request(app, "GET", "/health")).json()["grants"] == "unavailable"
    assert any(getattr(r, "reason", None) == "phylax_not_installed" for r in caplog.records)
