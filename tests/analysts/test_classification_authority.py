"""Synthetic trusted state for the offline classification authority."""

from datetime import datetime, timedelta, timezone
import socket
from uuid import UUID

import pytest

from app.analysts import classification_authority as ca
from app.analysts.inference import FakeModelProvider


def uid(number):
    return UUID(int=number)


NOW = datetime(2026, 11, 11, 12, 0, 0, 123, timezone.utc)
EVIDENCE_HASH = "a" * 64
POLICY_HASH = "b" * 64


@pytest.fixture
def inputs():
    record = ca.IssuedClassificationRecord(
        record_domain="ai-soc-team.evidence-classification", schema_version="1.0",
        decision_id=uid(1), tenant_id=uid(2), evidence_id=uid(3), content_sha256=EVIDENCE_HASH,
        classification="OBSERVED", authority_id="test-authority", evaluator_policy_version="1",
        issuer_scope_id=uid(4), issuer_principal_id=uid(5), requester_principal_id=uid(6),
        policy_id="classification", policy_generation=7, policy_sha256=POLICY_HASH,
        source_verification_id=uid(7), issued_at=NOW, expires_at=NOW + timedelta(minutes=1),
        request_id=uid(8),
    )
    issuer = ca.AuthenticatedIssuer(tenant_id=uid(2), scope_id=uid(4), principal_id=uid(5),
                                    database_login="test_issuer")
    return dict(
        record=record, at=NOW, issuer=issuer,
        evidence=ca.EvidenceBinding(tenant_id=uid(2), evidence_id=uid(3), content_sha256=EVIDENCE_HASH),
        scope=ca.IssuerScope(**issuer.model_dump(exclude={"schema_version"}), authority_id="test-authority",
                             source_id=uid(9), active=True),
        policy=ca.PolicyActivation(tenant_id=uid(2), policy_id="classification", generation=7,
                                   policy_sha256=POLICY_HASH, active=True),
        source=ca.SourceVerificationReference(
            tenant_id=uid(2), evidence_id=uid(3), content_sha256=EVIDENCE_HASH,
            source_id=uid(9), verification_id=uid(7), active=True,
        ),
        state=ca.DecisionState(tenant_id=uid(2), decision_id=uid(1),
                               issuance_sha256=ca.issuance_digest(record), revoked=False),
    )


def test_validity_is_deterministic_and_offline(inputs, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("unexpected I/O or provider call")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(FakeModelProvider, "generate", forbidden)
    import psycopg
    monkeypatch.setattr(psycopg, "connect", forbidden)
    assert [ca.evaluate_validity(**inputs) for _ in range(3)] == [ca.ValidityResult.VALID] * 3


def test_canonical_golden_record(inputs):
    expected = (
        b'{"authority_id":"test-authority","classification":"OBSERVED",'
        b'"content_sha256":"' + b"a" * 64 + b'",'
        b'"decision_id":"00000000-0000-0000-0000-000000000001","evaluator_policy_version":"1",'
        b'"evidence_id":"00000000-0000-0000-0000-000000000003",'
        b'"expires_at":"2026-11-11T12:01:00.000123+00:00","issued_at":"2026-11-11T12:00:00.000123+00:00",'
        b'"issuer_principal_id":"00000000-0000-0000-0000-000000000005",'
        b'"issuer_scope_id":"00000000-0000-0000-0000-000000000004",'
        b'"policy_generation":7,"policy_id":"classification","policy_sha256":"' + b"b" * 64 + b'",'
        b'"record_domain":"ai-soc-team.evidence-classification",'
        b'"request_id":"00000000-0000-0000-0000-000000000008",'
        b'"requester_principal_id":"00000000-0000-0000-0000-000000000006","schema_version":"1.0",'
        b'"source_verification_id":"00000000-0000-0000-0000-000000000007",'
        b'"tenant_id":"00000000-0000-0000-0000-000000000002"}'
    )
    record = inputs["record"]
    fields = dict(reversed(tuple(record.model_dump().items())))
    fields["decision_id"] = UUID(record.decision_id.hex.upper())
    assert ca.canonical_issuance_bytes(ca.IssuedClassificationRecord(**fields)) == expected
    assert ca.issuance_digest(record) == "08ee9212c580dcf08ea721bb01fa7652db031ef46602a264687de20db909bffb"


@pytest.mark.parametrize("change", [
    {"audit_sequence": 42}, {"schema_version": "2.0"}, {"record_domain": "another-domain"},
    {"policy_generation": "7"}, {"policy_generation": True}, {"policy_generation": 2**63},
    {"decision_id": str(uid(1))}, {"decision_id": uid(0)}, {"authority_id": "x" * 5000},
    {"classification": "UNKNOWN"}, {"evaluator_policy_version": "2"},
    {"issued_at": NOW.replace(tzinfo=None)}, {"issued_at": NOW.isoformat()},
    {"expires_at": NOW}, {"issued_at": NOW.astimezone(timezone(timedelta(hours=1)))},
])
def test_malformed_record_has_safe_denial(inputs, change):
    record = inputs["record"].model_copy(update=change)
    assert ca.evaluate_validity(**dict(inputs, record=record)) is ca.ValidityResult.INVALID_RECORD
    with pytest.raises(ValueError, match="^invalid_issuance_record$"):
        ca.canonical_issuance_bytes(record)


@pytest.mark.parametrize(("part", "changes", "reason"), [
    ("evidence", {"tenant_id": uid(42)}, "SCOPE_MISMATCH"),
    ("evidence", {"evidence_id": uid(42)}, "SCOPE_MISMATCH"),
    ("evidence", {"content_sha256": "c" * 64}, "DIGEST_MISMATCH"),
    ("state", {"decision_id": uid(42)}, "SCOPE_MISMATCH"),
    ("state", {"issuance_sha256": "c" * 64}, "ISSUANCE_MISMATCH"),
    ("state", {"revoked": 0}, "INVALID_STATE"),
    ("record", {"issuer_scope_id": uid(42)}, "ISSUER_DENIED"),
    ("record", {"classification": "SYNTHETIC / TEST ONLY"}, "UNSUPPORTED_CLASSIFICATION"),
    ("record", {"authority_id": "claimed-authority"}, "ISSUER_DENIED"),
    ("issuer", {"principal_id": uid(42)}, "ISSUER_DENIED"),
    ("issuer", {"database_login": "wrong_login"}, "ISSUER_DENIED"),
    ("scope", {"active": False}, "ISSUER_DENIED"),
    ("policy", {"active": False}, "POLICY_INACTIVE"),
    ("policy", {"policy_id": "wrong-policy"}, "POLICY_INACTIVE"),
    ("policy", {"generation": 8}, "POLICY_INACTIVE"),
    ("policy", {"policy_sha256": "c" * 64}, "POLICY_DIGEST_MISMATCH"),
    ("source", {"active": False}, "SOURCE_UNVERIFIED"),
    ("source", {"verification_id": uid(42)}, "SOURCE_UNVERIFIED"),
    ("source", {"source_id": uid(42)}, "SOURCE_UNVERIFIED"),
    ("source", {"evidence_id": uid(42)}, "SOURCE_UNVERIFIED"),
    ("source", {"content_sha256": "c" * 64}, "SOURCE_UNVERIFIED"),
])
def test_binding_denials(inputs, part, changes, reason):
    inputs[part] = inputs[part].model_copy(update=changes)
    assert ca.evaluate_validity(**inputs) is ca.ValidityResult[reason]


@pytest.mark.parametrize("part", ["evidence", "issuer", "scope", "policy", "source", "state", "at"])
def test_missing_state_never_defaults_to_authorized(inputs, part):
    assert ca.evaluate_validity(**dict(inputs, **{part: None})) is ca.ValidityResult.MISSING_STATE


@pytest.mark.parametrize(("at", "reason"), [
    (NOW - timedelta(microseconds=1), "NOT_YET_VALID"), (NOW, "VALID"),
    (NOW + timedelta(seconds=60, microseconds=-1), "VALID"),
    (NOW + timedelta(minutes=1), "EXPIRED"),
    (NOW.replace(tzinfo=None), "INVALID_TIME"), (NOW.isoformat(), "INVALID_TIME"),
])
def test_time_boundaries(inputs, at, reason):
    assert ca.evaluate_validity(**dict(inputs, at=at)) is ca.ValidityResult[reason]


def test_revocation_and_historical_expiration_cannot_be_rewritten(inputs):
    record = inputs["record"]
    changed = record.model_copy(update={"expires_at": NOW + timedelta(hours=1)})
    at = record.expires_at
    assert ca.evaluate_validity(**dict(inputs, record=changed, at=at)) is ca.ValidityResult.ISSUANCE_MISMATCH
    state = inputs["state"].model_copy(update={"revoked": True})
    assert ca.evaluate_validity(**dict(inputs, state=state)) is ca.ValidityResult.REVOKED
    assert ca.evaluate_validity(**dict(inputs, state=state, record=changed, at=at)) is ca.ValidityResult.REVOKED
    with pytest.raises(ValueError, match="frozen"):
        record.expires_at = changed.expires_at


def test_policy_transition_requires_higher_generation_even_after_disable(inputs):
    previous = inputs["policy"].model_copy(update={"active": False})
    assert not ca.is_policy_successor(previous, inputs["policy"])
    assert not ca.is_policy_successor(previous, previous.model_copy(update={"generation": 6}))
    next_policy = previous.model_copy(update={"generation": 8, "active": True})
    assert ca.is_policy_successor(previous, next_policy)
    assert not ca.is_policy_successor(previous, next_policy.model_copy(update={"tenant_id": uid(42)}))


def test_model_shaped_output_and_matching_labels_cannot_forge_issuance(inputs):
    record = inputs["record"]
    model_output = record.model_dump(mode="json")
    assert ca.evaluate_validity(**dict(inputs, record=model_output)) is ca.ValidityResult.INVALID_RECORD
    forged = record.model_copy(update={"requester_principal_id": uid(42)})
    assert ca.evaluate_validity(**dict(inputs, record=forged)) is ca.ValidityResult.ISSUANCE_MISMATCH
    assert ca.evaluate_validity(**dict(inputs, record=forged, state=None)) is ca.ValidityResult.MISSING_STATE


def test_validity_result_has_no_l1_admission_path(inputs):
    from app.analysts.evidence_adapter import StoredEvidenceAdapter
    from app.analysts.orchestration import orchestrate_l1
    from app.analysts.postgres_evidence import PostgresEvidenceRepository
    from tests.analysts.test_analyst_contracts import NOW as TASK_TIME
    from tests.analysts.test_analyst_inference import setup
    from tests.analysts.test_postgres_evidence import Session, row

    args = setup()
    evidence = row(tenant_id=args["context"].tenant_id, trust_level="system_verified",
                   evidence_id=args["task"].original_evidence_ids[0])
    validity = ca.evaluate_validity(**inputs)
    assert validity is ca.ValidityResult.VALID
    del args["snapshot"], args["package"]
    for candidate in ((validity,), (inputs["record"],), StoredEvidenceAdapter(PostgresEvidenceRepository(Session((evidence,))))):
        result = orchestrate_l1(**args, evidence=candidate, captured_at=TASK_TIME, at=TASK_TIME)
        assert (result.status, result.request_id) == ("DENIED", None)
    assert args["provider"].calls == 0
