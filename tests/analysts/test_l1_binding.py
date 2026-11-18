"""AI-05C1 deterministic L1 request-binding tests."""

from uuid import UUID

import pytest

from app.analysts.l1_binding import review_bound_l1_result
from tests.analysts.test_analyst_inference import setup, request
from tests.analysts.test_orchestration import run


def bound_review(args, result, **overrides):
    values = {
        "context": args["context"],
        "task": args["task"],
        "snapshot": args["snapshot"],
        "expected_request": request(args),
    }
    values.update(overrides)
    return review_bound_l1_result(result, **values)


def test_valid_request_binding():
    args = setup("L1")
    result = run(args)

    assert result.status == "COMPLETED"

    decision = bound_review(args, result)

    assert decision.outcome == "OBSERVATION_VALIDATED"
    assert decision.proposed_only is True
    assert decision.executable is False


@pytest.mark.parametrize(
    "field",
    ["request_id", "request_sha256"],
)
def test_result_request_mismatch_is_rejected(field):
    args = setup("L1")
    result = run(args)

    changes = {
        "request_id": UUID(int=99),
        "request_sha256": "0" * 64,
    }

    forged = result.model_copy(
        update={field: changes[field]}
    )

    assert bound_review(
        args, forged
    ).outcome == "REJECTED"


def test_cross_tenant_context_is_rejected():
    args = setup("L1")
    result = run(args)

    wrong_context = args["context"].model_copy(
        update={"tenant_id": UUID(int=99)}
    )

    assert bound_review(
        args,
        result,
        context=wrong_context,
    ).outcome == "REJECTED"


def test_wrong_task_is_rejected():
    args = setup("L1")
    result = run(args)

    wrong_task = args["task"].model_copy(
        update={"task_id": UUID(int=99)}
    )

    assert bound_review(
        args,
        result,
        task=wrong_task,
    ).outcome == "REJECTED"


def test_wrong_snapshot_is_rejected():
    args = setup("L1")
    result = run(args)

    wrong_snapshot = args["snapshot"].model_copy(
        update={"snapshot_sha256": "0" * 64}
    )

    assert bound_review(
        args,
        result,
        snapshot=wrong_snapshot,
    ).outcome == "REJECTED"


def test_tampered_expected_request_is_rejected():
    args = setup("L1")
    result = run(args)

    expected = request(args).model_copy(
        update={"request_sha256": "0" * 64}
    )

    assert bound_review(
        args,
        result,
        expected_request=expected,
    ).outcome == "REJECTED"


def test_tampered_assessment_binding_is_rejected():
    args = setup("L1")
    result = run(args)

    parsed = result.parsed
    evaluation = parsed.evaluation

    assessment = evaluation.assessment.model_copy(
        update={"task_sha256": "0" * 64}
    )

    modified_evaluation = evaluation.model_copy(
        update={"assessment": assessment}
    )

    modified_parsed = parsed.model_copy(
        update={"evaluation": modified_evaluation}
    )

    forged = result.model_copy(
        update={"parsed": modified_parsed}
    )

    assert bound_review(
        args, forged
    ).outcome == "REJECTED"


def test_untrusted_result_is_rejected():
    args = setup("L1")

    decision = bound_review(args, object())

    assert decision.outcome == "REJECTED"
    assert decision.executable is False
