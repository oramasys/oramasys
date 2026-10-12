"""Public representation of admission refusals."""
from __future__ import annotations

from httpx import ASGITransport, AsyncClient

from orama.api.server import create_app
from orama.graph.admission import AdmissionRefused


_RUN_PAYLOAD = {
    "session_id": "test-session",
    "task": "Explain hardware routing.",
    "task_type": "reasoning",
    "target_tier": "shared",
}


class _RefusingRunner:
    def __init__(self, reason: str) -> None:
        self.reason = reason

    async def invoke(self, graph: object, state: object) -> object:
        raise AdmissionRefused(self.reason)


async def test_public_503_redacts_internal_reason(monkeypatch) -> None:
    """Different internal refusals share one opaque public error envelope."""
    monkeypatch.setenv("ORAMA_INSECURE_DEV", "1")
    bodies = []
    reasons = ("admission.owner_revoked:private", "budget.steps_exhausted:private")
    for reason in reasons:
        app = create_app(runner=_RefusingRunner(reason))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://127.0.0.1") as client:
            response = await client.post("/run", json=_RUN_PAYLOAD)
        assert response.status_code == 503
        body = response.json()
        assert reason not in response.text
        assert body["detail"]["code"] == "run_unavailable"
        assert isinstance(body["detail"]["correlation_id"], str)
        assert body["detail"]["correlation_id"]
        bodies.append(body)

    assert [set(body["detail"]) for body in bodies] == [{"code", "correlation_id"}] * 2


async def test_refusal_reason_is_logged_with_the_public_correlation_id(monkeypatch, caplog) -> None:
    """Operators can map a reported correlation id to its internal refusal reason."""
    import logging

    monkeypatch.setenv("ORAMA_INSECURE_DEV", "1")
    app = create_app(runner=_RefusingRunner("admission.stop_requested"))
    with caplog.at_level(logging.WARNING, logger="orama.api.server"):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://127.0.0.1") as client:
            response = await client.post("/run", json=_RUN_PAYLOAD)

    correlation_id = response.json()["detail"]["correlation_id"]
    record = next(r for r in caplog.records if r.name == "orama.api.server")
    assert record.correlation_id == correlation_id
    assert record.reason == "admission.stop_requested"
    assert "admission.stop_requested" not in response.text
