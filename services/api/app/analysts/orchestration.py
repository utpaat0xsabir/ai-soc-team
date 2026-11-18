"""Offline L1 orchestration over the existing synthetic analyst contracts."""

from datetime import datetime

from app.analysts import contracts, evaluation, inference
from app.analysts.evidence_adapter import StoredEvidenceAdapter, TrustedEvidenceAdapter
from app.gateway.contracts import TrustedContext


def _orchestrate_l1_with_receipt(
    context: TrustedContext,
    task: contracts.AnalystTask,
    evidence: tuple[contracts.EvidenceReference, ...] | TrustedEvidenceAdapter | StoredEvidenceAdapter,
    configuration: inference.InferenceConfiguration,
    provider: inference.FakeModelProvider,
    admission: inference.AdmissionController,
    control: inference.InferenceControl,
    *,
    captured_at: datetime,
    at: datetime,
    forbidden_values: tuple[str, ...] = (),
) -> tuple[inference.InferenceResult, inference.InferenceExecutionReceipt | None, contracts.EvidenceSnapshot | None]:
    """Build an L1 snapshot/package and return a proposed-only fake result."""
    if type(provider) is not inference.FakeModelProvider:
        return inference.InferenceResult(
            status='DENIED', reason='UNSUPPORTED_PROVIDER', request_id=None, request_sha256=None
        ), None, None
    if type(task) is not contracts.AnalystTask or task.tier != 'L1':
        return inference.InferenceResult(
            status='DENIED', reason='INVALID_INPUT', request_id=None, request_sha256=None
        ), None, None
    try:
        if type(evidence) in (TrustedEvidenceAdapter, StoredEvidenceAdapter):
            if type(context) is not TrustedContext:
                raise ValueError('invalid_analyst_inputs')
            context = TrustedContext.model_validate(context)
            contracts._bounded(task)
            task = contracts.AnalystTask.model_validate(task)
            if (task.tenant_id != context.tenant_id or task.principal_id != context.principal_id
                    or task.classification != 'SYNTHETIC / TEST ONLY'):
                raise ValueError('invalid_analyst_inputs')
            evidence = evidence.load_bundle(context, task.original_evidence_ids)
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
        ), None, None
    result, receipt = inference.run_inference_with_receipt(
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
    return result, receipt, snapshot


def orchestrate_l1(
    context: TrustedContext,
    task: contracts.AnalystTask,
    evidence: tuple[contracts.EvidenceReference, ...] | TrustedEvidenceAdapter | StoredEvidenceAdapter,
    configuration: inference.InferenceConfiguration,
    provider: inference.FakeModelProvider,
    admission: inference.AdmissionController,
    control: inference.InferenceControl,
    *,
    captured_at: datetime,
    at: datetime,
    forbidden_values: tuple[str, ...] = (),
) -> inference.InferenceResult:
    """Preserve the existing synthetic L1 orchestration interface."""

    result, _, _ = _orchestrate_l1_with_receipt(
        context, task, evidence, configuration, provider,
        admission, control, captured_at=captured_at, at=at,
        forbidden_values=forbidden_values,
    )
    return result


def orchestrate_l1_review(
    context: TrustedContext,
    task: contracts.AnalystTask,
    evidence: tuple[contracts.EvidenceReference, ...] | TrustedEvidenceAdapter | StoredEvidenceAdapter,
    configuration: inference.InferenceConfiguration,
    provider: inference.FakeModelProvider,
    admission: inference.AdmissionController,
    control: inference.InferenceControl,
    *,
    captured_at: datetime,
    at: datetime,
    forbidden_values: tuple[str, ...] = (),
) -> tuple[inference.InferenceResult, "L1ReviewDecision"]:
    """Execute and review one synthetic L1 request, without authority."""

    from app.analysts.l1_binding import review_bound_l1_result
    from app.analysts.l1_review_gate import L1ReviewDecision

    rejected = L1ReviewDecision(outcome="REJECTED")

    result, receipt, snapshot = _orchestrate_l1_with_receipt(
        context, task, evidence, configuration, provider,
        admission, control, captured_at=captured_at, at=at,
        forbidden_values=forbidden_values,
    )

    if (
        type(receipt) is not inference.InferenceExecutionReceipt
        or type(snapshot) is not contracts.EvidenceSnapshot
        or receipt.result is not result
        or receipt.proposed_only is not True
        or receipt.executable is not False
    ):
        return result, rejected

    decision = review_bound_l1_result(
        result,
        context=context,
        task=task,
        snapshot=snapshot,
        expected_request=receipt.request,
    )

    return result, decision
