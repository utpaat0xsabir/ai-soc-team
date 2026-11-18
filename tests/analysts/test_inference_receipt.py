"""AI-05C1 3B-1: synthetic inference execution receipt tests."""

import pytest

from app.analysts import inference
from app.analysts.l1_binding import review_bound_l1_result
from tests.analysts.test_analyst_inference import setup


def test_completed_inference_captures_actual_request():
    args = setup("L1")

    result, receipt = inference.run_inference_with_receipt(**args)

    assert result.status == "COMPLETED"
    assert receipt is not None

    assert receipt.result is result
    assert receipt.request.request_id == result.request_id
    assert receipt.request.request_sha256 == result.request_sha256

    assert receipt.request.tenant_id == args["context"].tenant_id
    assert receipt.request.principal_id == args["context"].principal_id
    assert receipt.request.task_id == args["task"].task_id
    assert receipt.request.snapshot_id == args["snapshot"].snapshot_id
    assert receipt.request.snapshot_sha256 == (
        args["snapshot"].snapshot_sha256
    )

    assert receipt.proposed_only is True
    assert receipt.executable is False
    assert args["provider"].calls == 1
    assert args["admission"].in_flight == 0


def test_receipt_passes_existing_binding_gate():
    args = setup("L1")

    result, receipt = inference.run_inference_with_receipt(**args)

    assert receipt is not None

    decision = review_bound_l1_result(
        result,
        context=args["context"],
        task=args["task"],
        snapshot=args["snapshot"],
        expected_request=receipt.request,
    )

    assert decision.outcome == "OBSERVATION_VALIDATED"
    assert decision.proposed_only is True
    assert decision.executable is False


@pytest.mark.parametrize(
    "event,expected",
    [
        ("FAILURE", "FAILED"),
        ("CANCEL", "CANCELLED"),
    ],
)
def test_failed_or_cancelled_execution_has_no_receipt(
    event, expected
):
    args = setup("L1")

    args["provider"] = inference.FakeModelProvider(
        steps=(inference.FakeStep(event=event),)
    )

    result, receipt = inference.run_inference_with_receipt(**args)

    assert result.status == expected
    assert receipt is None
    assert result.executable is False
    assert args["admission"].in_flight == 0


def test_rejected_provider_binding_has_no_receipt():
    args = setup("L1")

    args["provider"] = args["provider"].model_copy(
        update={"fault": "WRONG_REQUEST"}
    )

    result, receipt = inference.run_inference_with_receipt(**args)

    assert result.status == "DENIED"
    assert receipt is None
    assert result.executable is False
    assert args["admission"].in_flight == 0


@pytest.mark.parametrize(
    "scenario",
    ["provider_timeout", "post_parse_deadline"],
)
def test_timeout_does_not_issue_receipt(scenario):
    from datetime import timedelta
    from tests.analysts.test_analyst_contracts import NOW

    args = setup("L1")

    if scenario == "provider_timeout":
        step = args["provider"].steps[0].model_copy(
            update={"elapsed_ms": 1001}
        )
        args["provider"] = inference.FakeModelProvider(
            steps=(step,)
        )
    else:
        readings = iter((0, 0, 0, 0, 0, 2500))
        args["control"] = inference.InferenceControl(
            now=lambda: NOW + timedelta(
                milliseconds=next(readings, 2500)
            )
        )

    result, receipt = inference.run_inference_with_receipt(
        **args
    )

    assert result.status == "TIMED_OUT"
    assert result.reason == "DEADLINE"
    assert result.parsed is None
    assert receipt is None
    assert result.executable is False
    assert args["admission"].in_flight == 0
