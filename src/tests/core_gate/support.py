"""Shared builders for gate-level runtime tests."""
from __future__ import annotations

from pathlib import Path

from orama.graph.admission import AdmissionRequirements
from orama.graph.admission_runtime import AdmissionGraphRunner
from orama.graph.execution_guard import StepLedger
from orama.graph.run_control import RunControl
from tests.test_admission_decision import binding, context, providers


def runner_with_stores(tmp_path: Path) -> tuple[AdmissionGraphRunner, StepLedger, RunControl]:
    """Build an admission runner, ledger and run control sharing one SQLite store."""
    owner_providers, clock = providers()
    store = tmp_path / "shared.sqlite3"
    ledger = StepLedger(store)
    run_control = RunControl(store_path=store)
    runner = AdmissionGraphRunner(
        binding=binding(),
        providers=owner_providers,
        ledger=ledger,
        run_control=run_control,
        context_from_state=lambda _state: context(run_id="client-run"),
        max_steps=6,
        requirements=AdmissionRequirements.for_effects(
            model_dispatch=True, endpoint_purposes=("model_egress",)
        ),
        clock=clock,
    )
    return runner, ledger, run_control
