"""AI-05C1: structural outcome mapping, not provenance proof."""

import pytest

from app.analysts.inference import InferenceResult
from app.analysts.l1_review_gate import review_l1_result
from tests.analysts.test_analyst_inference import setup
from tests.analysts.test_l1_binding import bound_review
from tests.analysts.test_orchestration import run


@pytest.mark.parametrize(
    "outcome,reason,expected",
    [
        (
            "VALID",
            "VALIDATED_SOURCE_FIELDS",
            "OBSERVATION_VALIDATED",
        ),
        (
            "REQUIRES_HUMAN_REVIEW",
            "UNSUPPORTED_NARRATIVE",
            "HUMAN_REVIEW_REQUIRED",
        ),
        (
            "INSUFFICIENT_EVIDENCE",
            "INSUFFICIENT_SUPPORT",
            "INSUFFICIENT_EVIDENCE",
        ),
    ],
)
def test_review_outcome_mapping(outcome, reason, expected):
    args = setup("L1")
    result = run(args)

    assert result.status == "COMPLETED"

    parsed = result.parsed
    evaluation = parsed.evaluation

    # Structural fixture only. Changing the outcome here does
    # not establish that an actual model produced this evaluation.
    modified_evaluation = evaluation.model_copy(
        update={"outcome": outcome, "reason": reason}
    )

    modified_parsed = parsed.model_copy(
        update={"evaluation": modified_evaluation}
    )

    modified_result = result.model_copy(
        update={"parsed": modified_parsed}
    )

    checked = InferenceResult.model_validate_json(
        modified_result.model_dump_json()
    )

    direct = review_l1_result(checked)
    bound = bound_review(args, checked)

    assert direct.outcome == expected
    assert bound.outcome == expected

    for decision in (direct, bound):
        assert decision.proposed_only is True
        assert decision.executable is False


def test_invalid_accepted_evaluation_is_rejected():
    args = setup("L1")
    result = run(args)

    evaluation = result.parsed.evaluation.model_copy(
        update={
            "outcome": "INVALID",
            "reason": "INVALID_INPUT",
            "assessment": None,
        }
    )

    parsed = result.parsed.model_copy(
        update={"evaluation": evaluation}
    )

    forged = result.model_copy(update={"parsed": parsed})

    assert review_l1_result(forged).outcome == "REJECTED"
    assert bound_review(args, forged).outcome == "REJECTED"


def test_untrusted_classification_is_rejected():
    args = setup("L1")
    result = run(args)

    forged = result.model_copy(
        update={"classification": "OBSERVED"}
    )

    assert review_l1_result(forged).outcome == "REJECTED"
    assert bound_review(args, forged).outcome == "REJECTED"
