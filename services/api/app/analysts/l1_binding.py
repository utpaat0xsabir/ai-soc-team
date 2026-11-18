"""AI-05C1: deterministic binding for proposed-only L1 reviews.

The expected request must come from trusted application composition.
Matching hashes do not authenticate execution provenance.
"""

import hmac

from app.analysts import contracts, inference
from app.analysts.l1_review_gate import (
    L1ReviewDecision,
    review_l1_result,
)
from app.gateway.contracts import TrustedContext


def review_bound_l1_result(
    value: object,
    *,
    context: TrustedContext,
    task: contracts.AnalystTask,
    snapshot: contracts.EvidenceSnapshot,
    expected_request: inference.InferenceRequest,
) -> L1ReviewDecision:
    """Reject results not bound to the expected synthetic L1 request."""

    rejected = L1ReviewDecision(outcome="REJECTED")

    try:
        if (
            type(context) is not TrustedContext
            or type(task) is not contracts.AnalystTask
            or type(snapshot) is not contracts.EvidenceSnapshot
            or type(expected_request) is not inference.InferenceRequest
            or type(value) is not inference.InferenceResult
        ):
            return rejected

        contracts._bounded(context)
        contracts._bounded(task)
        contracts._bounded(snapshot)
        contracts._bounded(expected_request)
        contracts._bounded(value)

        context = TrustedContext.model_validate_json(
            context.model_dump_json()
        )
        task = contracts.AnalystTask.model_validate_json(
            task.model_dump_json()
        )
        snapshot = contracts.EvidenceSnapshot.model_validate_json(
            snapshot.model_dump_json()
        )
        request = inference.InferenceRequest.model_validate_json(
            expected_request.model_dump_json()
        )
        result = inference.InferenceResult.model_validate_json(
            value.model_dump_json()
        )

        contracts.validate_inputs(
            context,
            task,
            snapshot,
            at=request.created_at,
        )

        if (
            task.tier != "L1"
            or task.classification != "SYNTHETIC / TEST ONLY"
            or request.tier != "L1"
            or request.tenant_id != context.tenant_id
            or request.principal_id != context.principal_id
            or request.task_id != task.task_id
            or request.snapshot_id != snapshot.snapshot_id
            or request.classification != task.classification
            or request.executable is not False
        ):
            return rejected

        if not hmac.compare_digest(
            request.snapshot_sha256,
            snapshot.snapshot_sha256,
        ):
            return rejected

        if (
            result.request_id != request.request_id
            or result.request_sha256 is None
            or not hmac.compare_digest(
                result.request_sha256,
                request.request_sha256,
            )
        ):
            return rejected

        if (
            result.status != "COMPLETED"
            or result.parsed is None
            or result.parsed.evaluation is None
            or result.parsed.evaluation.assessment is None
        ):
            return rejected

        assessment = result.parsed.evaluation.assessment

        if (
            not hmac.compare_digest(
                assessment.task_sha256,
                contracts._digest(task),
            )
            or not hmac.compare_digest(
                assessment.snapshot_sha256,
                snapshot.snapshot_sha256,
            )
            or assessment.assessment.task_id != task.task_id
            or assessment.assessment.tier != "L1"
            or assessment.assessment.classification
                != task.classification
        ):
            return rejected

        return review_l1_result(result)

    except Exception:
        return rejected
