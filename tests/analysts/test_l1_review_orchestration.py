"""AI-05C1 3B-3: synthetic L1 reviewed orchestration."""

from dataclasses import replace
from uuid import UUID

import pytest

from app.analysts import inference
from app.analysts.orchestration import orchestrate_l1_review
from tests.analysts.test_analyst_contracts import NOW
from tests.analysts.test_analyst_inference import setup


def reviewed(args, *, task=None, evidence=None):
    return orchestrate_l1_review(
        args["context"],
        args["task"] if task is None else task,
        args["snapshot"].evidence if evidence is None else evidence,
        args["configuration"],
        args["provider"],
        args["admission"],
        args["control"],
        captured_at=args["snapshot"].captured_at,
        at=NOW,
    )


def test_completed_l1_has_bound_proposed_review():
    args = setup("L1")

    result, decision = reviewed(args)

    assert result.status == "COMPLETED"
    assert decision.outcome == "OBSERVATION_VALIDATED"
    assert decision.proposed_only is True
    assert decision.executable is False
    assert args["provider"].calls == 1
    assert args["admission"].in_flight == 0


@pytest.mark.parametrize(
    "event,status",
    [
        ("FAILURE", "FAILED"),
        ("CANCEL", "CANCELLED"),
    ],
)
def test_failed_and_cancelled_runs_reject_review(event, status):
    args = setup("L1")
    args["provider"] = inference.FakeModelProvider(
        steps=(inference.FakeStep(event=event),)
    )

    result, decision = reviewed(args)

    assert result.status == status
    assert decision.outcome == "REJECTED"
    assert decision.executable is False
    assert args["admission"].in_flight == 0


def test_invalid_task_rejected_before_inference():
    args = setup("L1")
    wrong_task = setup("L2")["task"]

    result, decision = reviewed(args, task=wrong_task)

    assert result.status == "DENIED"
    assert decision.outcome == "REJECTED"
    assert args["provider"].calls == 0


def test_cross_tenant_evidence_rejected():
    args = setup("L1")
    evidence = args["snapshot"].evidence

    foreign = (
        evidence[0].model_copy(
            update={"tenant_id": UUID(int=99)}
        ),
    )

    result, decision = reviewed(args, evidence=foreign)

    assert result.status == "DENIED"
    assert decision.outcome == "REJECTED"
    assert args["provider"].calls == 0


def test_missing_receipt_rejected(monkeypatch):
    args = setup("L1")

    original = inference.run_inference_with_receipt

    def without_receipt(*a, **kw):
        result, _ = original(*a, **kw)
        return result, None

    monkeypatch.setattr(
        inference, "run_inference_with_receipt", without_receipt
    )

    result, decision = reviewed(args)

    assert result.status == "COMPLETED"
    assert decision.outcome == "REJECTED"
    assert args["provider"].calls == 1


def test_mismatched_receipt_rejected(monkeypatch):
    args = setup("L1")

    original = inference.run_inference_with_receipt

    def mismatched(*a, **kw):
        result, receipt = original(*a, **kw)
        assert receipt is not None

        wrong_request = receipt.request.model_copy(
            update={"tenant_id": UUID(int=99)}
        )

        return result, replace(
            receipt, request=wrong_request
        )

    monkeypatch.setattr(
        inference, "run_inference_with_receipt", mismatched
    )

    result, decision = reviewed(args)

    assert result.status == "COMPLETED"
    assert decision.outcome == "REJECTED"
    assert args["provider"].calls == 1


def test_result_substitution_rejected(monkeypatch):
    args = setup("L1")

    original = inference.run_inference_with_receipt

    def substitute_result(*a, **kw):
        result, receipt = original(*a, **kw)

        assert result.status == "COMPLETED"
        assert receipt is not None

        # Same validated content, different object.
        substituted = result.model_copy(deep=True)

        assert substituted is not receipt.result
        assert substituted == receipt.result

        return substituted, receipt

    monkeypatch.setattr(
        inference,
        "run_inference_with_receipt",
        substitute_result,
    )

    result, decision = reviewed(args)

    assert result.status == "COMPLETED"
    assert decision.outcome == "REJECTED"
    assert decision.proposed_only is True
    assert decision.executable is False
    assert args["provider"].calls == 1
    assert args["admission"].in_flight == 0


@pytest.mark.parametrize(
    "scenario",
    ["provider_timeout", "post_parse_deadline"],
)
def test_l1_timeout_rejects_review(scenario):
    from datetime import timedelta

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

    result, decision = reviewed(args)

    assert result.status == "TIMED_OUT"
    assert result.reason == "DEADLINE"
    assert result.parsed is None
    assert result.executable is False

    assert decision.outcome == "REJECTED"
    assert decision.proposed_only is True
    assert decision.executable is False

    assert args["admission"].in_flight == 0
