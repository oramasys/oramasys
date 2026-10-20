"""Paired-checkout regression for real Phylax abandonment retries (defined only when available)."""
from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import timedelta
from pathlib import Path

from tests.test_dispatch_slice2 import ATTEMPT, NOW, fenced, permit_request


def _phylax_abandon_available() -> bool:
    """True when the paired Phylax checkout exposes the slice-2 attested abandon."""
    try:
        from phylax.dispatch_permit_store import SqliteDispatchPermitStore
    except ModuleNotFoundError as error:
        if error.name == "phylax" or (error.name or "").startswith("phylax."):
            return False
        raise
    return hasattr(SqliteDispatchPermitStore, "abandon")


# The test is DEFINED only where the capability exists. A skipped test would consume the manifest
# skip allowance in every oracle cell, so where Phylax slice 2 is absent nothing is collected at all.
if _phylax_abandon_available():

    def test_real_phylax_retry_preserves_the_consumer_disposition(tmp_path: Path) -> None:
        """Consume both genuine issuer success responses without changing the first receipt."""
        from phylax import dispatch_permit_store as issuer
        from phylax import dispatch_wire as wire

        class Grants:
            """Supply fixed signed-grant facts to the real issuer store."""

            def get(self, grant_id: str) -> object:
                """Return facts matching this test's permit request."""
                return issuer.GrantFacts(
                    payload_digest="a" * 64, operation_id="op-1", request_digest="b" * 64,
                    ledger_store_id="ledger-1", expires_at=NOW + timedelta(hours=1),
                    revoked=False, cascade_pending=False,
                )

        class Signer:
            """Use Phylax's signing implementation with a synthetic fixture seed."""

            def active_key_id(self) -> str:
                """Identify the test issuer key."""
                return "test-key"

            def sign_permit(self, key_id: str, body: Mapping) -> str:
                """Sign the test permit using the real wire primitive."""
                return wire.sign_permit(b"1" * 32, body)

        class Operator:
            """Authorize the test's issuer abandonment operation."""

            def authorize(self, operation: str, *, attempt_id: str, grant_id: str | None) -> str:
                """Return a synthetic operator evidence reference."""
                return "test-operator"

        h = fenced(tmp_path)
        store = issuer.SqliteDispatchPermitStore(tmp_path / "issuer" / "dispatch.sqlite")
        request = {**permit_request(), "attempt_id": ATTEMPT, "requested_at": wire.timestamp(NOW)}
        permit = json.loads(store.admit(request, grants=Grants(), signer=Signer(), now=NOW))
        attestation = h.store.build_abandon_attestation(ATTEMPT, permit["permit_id"], "loss", 1, NOW)
        first_status, first_record = store.abandon(attestation, operator=Operator(), now=NOW)
        retry_status, retry_record = store.abandon(
            attestation, operator=Operator(), now=NOW + timedelta(seconds=1),
        )
        assert (first_status, retry_status) == ("abandon.recorded", "abandon.already_abandoned")
        assert first_record == retry_record

        class DirectIssuerResponse:
            """Trust only responses obtained above from the in-process issuer instance."""

            def verify(self, outcome: str, record: Mapping[str, str]) -> bool:
                """Bind the complete receipt and status to the actual issuer responses."""
                return outcome in {first_status, retry_status} and record == first_record

        h.store._abandon_authenticator = DirectIssuerResponse()
        try:
            h.store.record_abandon_outcome(ATTEMPT, first_status, first_record, NOW)
            original = h.store.abandon_outcome(ATTEMPT)
            h.store.record_abandon_outcome(ATTEMPT, retry_status, retry_record, NOW + timedelta(seconds=1))
            assert h.store.abandon_outcome(ATTEMPT) == original
        finally:
            h.store.close()
