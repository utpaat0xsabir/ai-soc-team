"""Offline L1 orchestration over the existing synthetic analyst contracts."""

from datetime import datetime

from app.analysts import contracts, evaluation, inference
from app.gateway.contracts import TrustedContext


def orchestrate_l1(
    context: TrustedContext,
    task: contracts.AnalystTask,
    evidence: tuple[contracts.EvidenceReference, ...],
    configuration: inference.InferenceConfiguration,
    provider: inference.FakeModelProvider,
    admission: inference.AdmissionController,
    control: inference.InferenceControl,
    *,
    captured_at: datetime,
    at: datetime,
    forbidden_values: tuple[str, ...] = (),
) -> inference.InferenceResult:
    """Build an L1 snapshot/package and return a proposed-only fake result."""
    if type(provider) is not inference.FakeModelProvider:
        return inference.InferenceResult(
            status='DENIED', reason='UNSUPPORTED_PROVIDER', request_id=None, request_sha256=None
        )
    if type(task) is not contracts.AnalystTask or task.tier != 'L1':
        return inference.InferenceResult(
            status='DENIED', reason='INVALID_INPUT', request_id=None, request_sha256=None
        )
    try:
        snapshot = contracts.build_snapshot(
            context,
            snapshot_id=task.snapshot_id,
            captured_at=captured_at,
            evidence=evidence,
        )
        package = evaluation.assemble_input(
            context, task, snapshot, at=at, forbidden_values=forbidden_values
        )
    except Exception:
        return inference.InferenceResult(
            status='DENIED', reason='INVALID_INPUT', request_id=None, request_sha256=None
        )
    return inference.run_inference(
        context,
        task,
        snapshot,
        package,
        configuration,
        provider,
        admission,
        control,
        forbidden_values=forbidden_values,
    )
