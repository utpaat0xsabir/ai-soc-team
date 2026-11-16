"""AI-05A offline L1 orchestration; synthetic evidence and fake provider only."""

from uuid import UUID

import pytest

from app.analysts import inference
from app.analysts.orchestration import orchestrate_l1
from tests.analysts.test_analyst_contracts import NOW
from tests.analysts.test_analyst_inference import setup


def run(args, *, evidence=None, task=None, captured_at=None):
    return orchestrate_l1(
        args['context'],
        args['task'] if task is None else task,
        args['snapshot'].evidence if evidence is None else evidence,
        args['configuration'],
        args['provider'],
        args['admission'],
        args['control'],
        captured_at=args['snapshot'].captured_at if captured_at is None else captured_at,
        at=NOW,
    )


def test_l1_orchestration_reuses_snapshot_input_and_fake_inference():
    args = setup('L1')

    result = run(args)

    assert result.status == 'COMPLETED'
    assert result.source == 'FAKE_MODEL / TEST ONLY'
    assert result.classification == 'SYNTHETIC / TEST ONLY'
    assert result.executable is False
    assert result.parsed.evaluation.assessment.proposed_only is True
    assert args['provider'].calls == 1
    assert args['admission'].in_flight == 0


@pytest.mark.parametrize('kind', ['non_l1', 'snapshot_mismatch', 'cross_tenant_evidence'])
def test_invalid_l1_scope_fails_closed_before_provider(kind):
    args = setup('L1')
    task = args['task']
    evidence = args['snapshot'].evidence
    if kind == 'non_l1':
        task = setup('L2')['task']
    elif kind == 'snapshot_mismatch':
        task = task.model_copy(update={'snapshot_sha256': '0' * 64})
    else:
        evidence = (evidence[0].model_copy(update={'tenant_id': UUID(int=99)}),)

    result = run(args, task=task, evidence=evidence)

    assert result.status == 'DENIED'
    assert result.reason == 'INVALID_INPUT'
    assert result.executable is False
    assert result.request_id is None
    assert args['provider'].calls == 0
    assert args['admission'].in_flight == 0


def test_fake_provider_failure_is_sanitized_and_not_executable():
    args = setup('L1')
    args['provider'] = inference.FakeModelProvider(
        steps=(inference.FakeStep(event='FAILURE'),)
    )

    result = run(args)

    assert result.status == 'FAILED'
    assert result.reason == 'PROVIDER_FAILURE'
    assert result.executable is False
    assert 'canary' not in result.model_dump_json()
    assert args['provider'].calls == 1
    assert args['admission'].in_flight == 0
