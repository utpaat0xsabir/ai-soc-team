"""Offline authority and policy fixtures. No production issuer is configured."""

from dataclasses import dataclass
import socket
from uuid import UUID

import pytest

from app.analysts import contracts, evaluation, inference
from app.analysts.evidence_adapter import StoredEvidenceAdapter, validate_stored_evidence
from app.analysts.evidence_admission import (
    AdmissionPolicy,
    AdmissionResult,
    ClassificationDecision,
    evaluate_admission,
)
from app.analysts.orchestration import orchestrate_l1
from app.analysts.postgres_evidence import PostgresEvidenceRepository
from app.gateway.contracts import TrustedContext
from tests.analysts.test_analyst_contracts import NOW
from tests.analysts.test_analyst_inference import setup
from tests.analysts.test_postgres_evidence import Session, row


@dataclass(frozen=True)
class OfflineTestAuthority:
    name: str = "offline-test-authority"

    def issue(self, evidence, classification="OBSERVED"):
        return ClassificationDecision(
            tenant_id=evidence.tenant_id, evidence_id=evidence.evidence_id,
            content_sha256=evidence.content_sha256, classification=classification,
            authority=self.name, policy_version="1",
        )


@pytest.fixture
def inputs():
    evidence = validate_stored_evidence(row(trust_level="system_verified"))
    context = TrustedContext(tenant_id=evidence.tenant_id, principal_id=UUID(int=2))
    authority = OfflineTestAuthority()
    decision = authority.issue(evidence)
    return dict(evidence=evidence, decision=decision, context=context, tier="L1",
                policy=AdmissionPolicy(context=context, policy_version="1",
                                       trusted_authorities=(authority.name,),
                                       issued_decisions=(decision,)))


def test_policy_match_is_deterministic_without_io(inputs, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("policy attempted network or model access")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(inference.FakeModelProvider, "generate", forbidden)
    assert [evaluate_admission(**inputs) for _ in range(3)] == [AdmissionResult.POLICY_MATCH] * 3


@pytest.mark.parametrize(("field", "value", "result"), [
    ("tenant_id", UUID(int=9), AdmissionResult.SCOPE_MISMATCH),
    ("evidence_id", UUID(int=9), AdmissionResult.SCOPE_MISMATCH),
    ("content_sha256", "a" * 64, AdmissionResult.DIGEST_MISMATCH),
    ("authority", "unknown-authority", AdmissionResult.UNTRUSTED_AUTHORITY),
    ("policy_version", "2", AdmissionResult.UNSUPPORTED_POLICY_VERSION),
    ("classification", "SYNTHETIC / TEST ONLY", AdmissionResult.UNSUPPORTED_CLASSIFICATION),
    ("classification", {"secret": "malformed"}, AdmissionResult.INVALID_INPUT),
    ("authority", "contains spaces", AdmissionResult.INVALID_INPUT),
])
def test_decision_substitution(inputs, field, value, result):
    inputs["decision"] = inputs["decision"].model_copy(update={field: value})
    assert evaluate_admission(**inputs) is result


def test_matching_authority_label_without_issuance_is_denied(inputs):
    inputs["policy"] = inputs["policy"].model_copy(update={"issued_decisions": ()})
    assert evaluate_admission(**inputs) is AdmissionResult.UNCONFIRMED_ISSUANCE


@pytest.mark.parametrize("tier", ["L2", "L3", "unknown", None])
def test_wrong_tier(inputs, tier):
    assert evaluate_admission(**dict(inputs, tier=tier)) is AdmissionResult.UNSUPPORTED_TIER


@pytest.mark.parametrize(("changes", "result"), [
    ({"principal_id": None}, AdmissionResult.INVALID_CONTEXT),
    ({"principal_id": UUID(int=0)}, AdmissionResult.INVALID_CONTEXT),
    ({"principal_id": UUID(int=9)}, AdmissionResult.SCOPE_MISMATCH),
    ({"tenant_id": UUID(int=9)}, AdmissionResult.SCOPE_MISMATCH),
])
def test_context_binding(inputs, changes, result):
    inputs["context"] = inputs["context"].model_copy(update=changes)
    assert evaluate_admission(**inputs) is result


@pytest.mark.parametrize("trust", ["unverified", "source_verified"])
def test_issuance_does_not_promote_trust(inputs, trust):
    evidence = validate_stored_evidence(row(trust_level=trust))
    decision = OfflineTestAuthority().issue(evidence)
    policy = inputs["policy"].model_copy(update={"issued_decisions": (decision,)})
    assert evaluate_admission(**dict(inputs, evidence=evidence, decision=decision,
                                     policy=policy)) is AdmissionResult.INSUFFICIENT_TRUST


@pytest.mark.parametrize("change", [
    {"collector_name": ""}, {"source_reference": None}, {"collector_version": " "},
    {"event_time": None}, {"payload_json": "{}"}, {"payload_json": "[" * 5000},
    {"payload_json": "9" * 5000},
    {"payload_json": '{"text":"different","text":"evidence canary"}'},
    {"trust_level": "unknown"}, {"content_sha256": "0" * 64},
])
def test_inconsistent_or_missing_provenance_or_integrity(inputs, change):
    evidence = inputs["evidence"].model_copy(update=change)
    assert evaluate_admission(**dict(inputs, evidence=evidence)) is AdmissionResult.INVALID_EVIDENCE


def test_changed_content_with_valid_new_digest_requires_new_decision(inputs):
    evidence = validate_stored_evidence(row(trust_level="system_verified", payload={"changed": True}))
    assert evaluate_admission(**dict(inputs, evidence=evidence)) is AdmissionResult.DIGEST_MISMATCH


def test_unknown_policy_version_denied_even_when_decision_matches(inputs):
    decision = inputs["decision"].model_copy(update={"policy_version": "2"})
    policy = inputs["policy"].model_copy(update={"policy_version": "2", "issued_decisions": (decision,)})
    assert evaluate_admission(**dict(inputs, decision=decision,
                                     policy=policy)) is AdmissionResult.UNSUPPORTED_POLICY_VERSION


def test_policy_match_cannot_admit_stored_evidence_to_orchestration(inputs):
    args = setup()
    context = args["context"]
    task = args["task"]
    stored = row(tenant_id=context.tenant_id, evidence_id=task.original_evidence_ids[0],
                 trust_level="system_verified")
    evidence = validate_stored_evidence(stored)
    decision = OfflineTestAuthority().issue(evidence)
    policy = inputs["policy"].model_copy(update={"context": context, "issued_decisions": (decision,)})
    result = evaluate_admission(evidence=evidence, decision=decision, context=context, tier="L1", policy=policy)
    assert result is AdmissionResult.POLICY_MATCH

    adapter = StoredEvidenceAdapter(PostgresEvidenceRepository(Session((stored,))))
    del args["snapshot"], args["package"]
    for candidate in (adapter, (evidence,), (result,)):
        denied = orchestrate_l1(**args, evidence=candidate, captured_at=NOW, at=NOW)
        assert (denied.status, denied.reason, denied.request_id) == ("DENIED", "INVALID_INPUT", None)
    assert args["provider"].calls == 0


def test_observed_reference_still_fails_inference_guard(inputs):
    assert evaluate_admission(**inputs) is AdmissionResult.POLICY_MATCH
    args = setup()
    snapshot = args["snapshot"]
    observed = tuple(item.model_copy(update={"classification": "OBSERVED"}) for item in snapshot.evidence)
    args["snapshot"] = contracts.build_snapshot(args["context"], snapshot_id=snapshot.snapshot_id,
                                                captured_at=snapshot.captured_at, evidence=observed)
    args["task"] = args["task"].model_copy(update={
        "classification": "OBSERVED",
        "snapshot_sha256": args["snapshot"].snapshot_sha256,
    })
    args["package"] = evaluation.assemble_input(args["context"], args["task"], args["snapshot"], at=NOW)
    with pytest.raises(ValueError, match="^synthetic_only$"):
        inference._prepare_request(
            args["context"], args["task"], args["snapshot"], args["package"],
            args["configuration"], at=NOW,
        )
    result = inference.run_inference(**args)
    assert result.status == "DENIED" and result.request_id is None
    assert args["provider"].calls == 0
