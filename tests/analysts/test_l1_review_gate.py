"""AI-05C1 review gate regression tests."""

from dataclasses import FrozenInstanceError

import pytest

from app.analysts.l1_review_gate import review_l1_result
from tests.analysts.test_analyst_inference import setup
from tests.analysts.test_orchestration import run


def test_completed_synthetic_result_maps_evaluation():
    args = setup("L1")
    result = run(args)

    assert result.status == "COMPLETED"

    expected = {
        "VALID": "OBSERVATION_VALIDATED",
        "REQUIRES_HUMAN_REVIEW": "HUMAN_REVIEW_REQUIRED",
        "INSUFFICIENT_EVIDENCE": "INSUFFICIENT_EVIDENCE",
        "INVALID": "REJECTED",
    }

    decision = review_l1_result(result)

    assert decision.outcome == expected[
        result.parsed.evaluation.outcome
    ]
    assert decision.proposed_only is True
    assert decision.executable is False
    assert args["provider"].calls == 1


def test_denied_orchestration_is_rejected():
    args = setup("L1")
    result = run(args, task=setup("L2")["task"])

    assert result.status == "DENIED"
    assert review_l1_result(result).outcome == "REJECTED"
    assert args["provider"].calls == 0


@pytest.mark.parametrize(
    "patch",
    [
        {"executable": True},
        {"classification": "OBSERVED"},
        {"source": "UNSUPPORTED_PROVIDER"},
        {"parsed": None},
    ],
)
def test_modified_result_fails_closed(patch):
    result = run(setup("L1"))

    modified = result.model_copy(update=patch)

    assert review_l1_result(modified).outcome == "REJECTED"


def test_untrusted_object_is_rejected():
    decision = review_l1_result(object())

    assert decision.outcome == "REJECTED"
    assert decision.executable is False


def test_review_decision_is_immutable():
    decision = review_l1_result(object())

    with pytest.raises(FrozenInstanceError):
        decision.outcome = "OBSERVATION_VALIDATED"
