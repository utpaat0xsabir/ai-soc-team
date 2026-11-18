"""Offline source-verification fixtures are consistency examples only."""

from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest

from app.analysts import source_verification as sv
from app.analysts.classification_authority import EvidenceBinding
from app.gateway.contracts import TrustedContext


def uid(value):
    return UUID(int=value)


NOW = datetime(2026, 11, 11, 12, 0, 0, 123, timezone.utc)


def test_origin_is_domain_separated():
    locator = sv.ProtectedEventLocator(installation_id=uid(1), index_uuid="AAAAAAAAAAAAAAAAAAAAAQ", document_id="event-42")
    assert b'"domain":"ai-soc-team.source-origin"' in sv.canonical_origin_bytes(locator)


@pytest.fixture
def state():
    locator = sv.ProtectedEventLocator(
        installation_id=uid(1), index_uuid="AAAAAAAAAAAAAAAAAAAAAQ", document_id="event-42", event_revision=3,
    )
    scope = dict(tenant_id=uid(2), source_scope_id=uid(3), integration_id=uid(4))
    binding = dict(tenant_id=uid(2), evidence_id=uid(5), content_sha256="a" * 64)
    collector = sv.AuthenticatedCollector(
        **scope, principal_id=uid(6), collector_scope_id=uid(7), database_login="collector",
        generation=4, credential_epoch_id=uid(8),
    )
    attestor = sv.AuthenticatedAttestor(
        **scope, principal_id=uid(9), attestor_scope_id=uid(10), database_login="attestor",
        verification_method="independent_fetch", verification_version="1",
    )
    config = sv.SourceConfiguration(
        **scope, installation_id=locator.installation_id, generation=4, config_sha256="b" * 64,
        collector_principal_id=collector.principal_id, collector_scope_id=collector.collector_scope_id,
        collector_database_login=collector.database_login, normalization="wazuh",
        normalization_version="1", credential_epoch_id=collector.credential_epoch_id,
        mode="DEDICATED", active=True,
    )
    collection = sv.CollectionRequest(**(scope | binding), request_id=uid(11), generation=4,
                                      config_sha256=config.config_sha256, locator=locator)
    receipt = sv.SourceCollectionReceipt(
        **collection.model_dump(), record_domain="ai-soc-team.source-collection-receipt",
        receipt_id=uid(12), collector_principal_id=collector.principal_id,
        collector_scope_id=collector.collector_scope_id, origin_sha256=sv.origin_digest(locator),
        collected_at=NOW - timedelta(seconds=1),
        request_sha256=sv.request_digest(
            TrustedContext(tenant_id=collector.tenant_id, principal_id=collector.principal_id), collection,
        ),
    )
    attestation = sv.SourceVerificationAttestation(
        **(scope | binding), schema_version="1.0", record_domain="ai-soc-team.source-verification-attestation",
        attestation_id=uid(13), receipt_id=receipt.receipt_id, receipt_sha256=sv.receipt_digest(receipt),
        collector_principal_id=collector.principal_id, origin_sha256=receipt.origin_sha256,
        attestor_principal_id=attestor.principal_id, attestor_scope_id=attestor.attestor_scope_id,
        verification_method=attestor.verification_method, verification_version=attestor.verification_version,
        generation=config.generation, config_sha256=config.config_sha256, verified_at=NOW,
        expires_at=NOW + timedelta(minutes=1), requester_principal_id=uid(14), request_id=uid(15),
    )
    retrieval = sv.IndependentRetrievalResult(
        **scope, installation_id=config.installation_id, receipt_id=receipt.receipt_id,
        attestor_principal_id=attestor.principal_id, attestor_scope_id=attestor.attestor_scope_id,
        requested_locator=locator, returned_locator=locator, generation=4, config_sha256=config.config_sha256,
        normalization="wazuh", normalization_version="1", reproduced_sha256=binding["content_sha256"],
        outcome="MATCH",
    )
    return dict(
        evidence=EvidenceBinding(**binding), collector=collector, attestor=attestor, configuration=config,
        receipt=receipt, receipt_sha256=sv.receipt_digest(receipt), attestation=attestation,
        scope_state=sv.ScopeState(**scope, suspended=False), retrieval=retrieval,
        attestation_state=sv.AttestationState(**scope, attestation_id=attestation.attestation_id,
                                              attestation_sha256=sv.attestation_digest(attestation), revoked=False),
        at=NOW, latest_generation=4,
    )


def test_valid_fixture_is_deterministic_and_offline(state, monkeypatch):
    import socket

    import psycopg

    from app.analysts.inference import FakeModelProvider

    def forbidden(*args, **kwargs):
        pytest.fail("unexpected I/O or model call")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(psycopg, "connect", forbidden)
    monkeypatch.setattr(FakeModelProvider, "generate", forbidden)
    result = sv.evaluate_source_verification(**state)
    assert result == sv.evaluate_source_verification(**state)
    assert (result.valid, result.reason, result.evaluator_version) == (True, "CONSISTENT", "1")
    assert result.tenant_id == state["evidence"].tenant_id
    assert result.evidence_id == state["evidence"].evidence_id
    assert result.attestation_id == state["attestation"].attestation_id


@pytest.mark.parametrize(("part", "change", "reason"), [
    ("evidence", {"tenant_id": uid(99)}, "SCOPE_MISMATCH"),
    ("evidence", {"evidence_id": uid(99)}, "EVIDENCE_MISMATCH"),
    ("evidence", {"content_sha256": "c" * 64}, "EVIDENCE_MISMATCH"),
    ("receipt", {"origin_sha256": "c" * 64}, "INVALID_RECEIPT"),
    ("receipt", {"request_sha256": "c" * 64}, "INVALID_RECEIPT"),
    ("collector", {"principal_id": uid(99)}, "COLLECTOR_MISMATCH"),
    ("collector", {"collector_scope_id": uid(99)}, "COLLECTOR_MISMATCH"),
    ("collector", {"database_login": "forged_collector"}, "COLLECTOR_MISMATCH"),
    ("collector", {"credential_epoch_id": uid(99)}, "COLLECTOR_MISMATCH"),
    ("collector", {"integration_id": uid(99)}, "SCOPE_MISMATCH"),
    ("attestor", {"source_scope_id": uid(99)}, "SCOPE_MISMATCH"),
    ("attestor", {"attestor_scope_id": uid(99)}, "ATTESTOR_MISMATCH"),
    ("attestor", {"principal_id": uid(99)}, "ATTESTOR_MISMATCH"),
    ("attestor", {"database_login": "collector"}, "IDENTITY_COLLISION"),
    ("configuration", {"generation": 3}, "CONFIGURATION_INACTIVE"),
    ("configuration", {"config_sha256": "c" * 64}, "CONFIGURATION_INACTIVE"),
    ("configuration", {"active": False}, "CONFIGURATION_INACTIVE"),
    ("configuration", {"mode": "SHARED"}, "INVALID_STATE"),
    ("configuration", {"installation_id": uid(99)}, "RETRIEVAL_NOT_MATCHED"),
    ("retrieval", {"installation_id": uid(99)}, "RETRIEVAL_NOT_MATCHED"),
    ("retrieval", {"receipt_id": uid(99)}, "RETRIEVAL_NOT_MATCHED"),
    ("retrieval", {"normalization_version": "2"}, "RETRIEVAL_NOT_MATCHED"),
    ("retrieval", {"reproduced_sha256": "c" * 64}, "RETRIEVAL_NOT_MATCHED"),
    ("retrieval", {"returned_locator": None}, "RETRIEVAL_NOT_MATCHED"),
    ("scope_state", {"suspended": True}, "SCOPE_SUSPENDED"),
    ("scope_state", {"suspended": 0}, "INVALID_STATE"),
    ("attestation_state", {"revoked": True}, "ATTESTATION_REVOKED"),
    ("attestation_state", {"attestation_sha256": "c" * 64}, "INVALID_ATTESTATION"),
    ("attestation_state", {"attestation_id": uid(99)}, "INVALID_ATTESTATION"),
])
def test_exact_bindings_and_current_state(state, part, change, reason):
    state[part] = state[part].model_copy(update=change)
    result = sv.evaluate_source_verification(**state)
    assert not result.valid and result.reason == reason


@pytest.mark.parametrize("outcome", ["MISMATCH", "NOT_FOUND", "SOURCE_UNAVAILABLE", "UNAUTHORIZED", "AMBIGUOUS", "ERROR"])
def test_retrieval_failure_denies_even_with_matching_fields(state, outcome):
    state["retrieval"] = state["retrieval"].model_copy(update={"outcome": outcome})
    assert sv.evaluate_source_verification(**state).reason == "RETRIEVAL_NOT_MATCHED"


def test_mismatched_locators_and_generation_floor_deny(state):
    locator = state["receipt"].locator.model_copy(update={"event_revision": 2})
    state["retrieval"] = state["retrieval"].model_copy(update={"requested_locator": locator})
    assert sv.evaluate_source_verification(**state).reason == "RETRIEVAL_NOT_MATCHED"
    assert sv.evaluate_source_verification(**dict(state, latest_generation=5)).reason == "CONFIGURATION_INACTIVE"
    assert sv.evaluate_source_verification(**dict(state, latest_generation=True)).reason == "INVALID_STATE"


@pytest.mark.parametrize("part", [
    "evidence", "receipt", "receipt_sha256", "attestation", "collector", "attestor", "configuration",
    "latest_generation", "retrieval", "scope_state", "attestation_state", "at",
])
def test_missing_state_is_not_an_authorization(state, part):
    result = sv.evaluate_source_verification(**dict(state, **{part: None}))
    assert not result.valid and result.reason == "MISSING_STATE"


@pytest.mark.parametrize(("at", "reason"), [
    (NOW - timedelta(microseconds=1), "NOT_YET_VALID"), (NOW, "CONSISTENT"),
    (NOW + timedelta(seconds=60, microseconds=-1), "CONSISTENT"),
    (NOW + timedelta(minutes=1), "EXPIRED"), (NOW.replace(tzinfo=None), "INVALID_STATE"),
])
def test_validity_interval(state, at, reason):
    assert sv.evaluate_source_verification(**dict(state, at=at)).reason == reason


def _edit_receipt(receipt, **changes):
    updated = receipt.model_copy(update=changes)
    request = sv.CollectionRequest.model_validate(updated.model_dump(include=set(sv.CollectionRequest.model_fields)))
    context = TrustedContext(tenant_id=updated.tenant_id, principal_id=updated.collector_principal_id)
    return updated.model_copy(update={
        "request_sha256": sv.request_digest(context, request),
        "origin_sha256": sv.origin_digest(updated.locator),
    })


@pytest.mark.parametrize("changed", [
    {"tenant_id": uid(99)}, {"evidence_id": uid(99)}, {"content_sha256": "c" * 64},
    {"integration_id": uid(99)}, {"source_scope_id": uid(99)}, {"collector_scope_id": uid(99)},
])
def test_same_origin_with_a_different_binding_conflicts(state, changed):
    receipt = state["receipt"]
    assert sv.classify_replay(_edit_receipt(receipt, **changed), (receipt,), latest_generation=4) is sv.ReplayResult.CONFLICT


def test_replay_requires_a_complete_lookup_in_the_origin_namespace(state):
    receipt = state["receipt"]
    replay = sv.classify_replay
    assert replay(receipt, (), latest_generation=4) is sv.ReplayResult.NEW
    retry = receipt.model_copy(update={"receipt_id": uid(99), "collected_at": NOW})
    assert replay(retry, (receipt,), latest_generation=4) is sv.ReplayResult.EXACT_RETRY
    assert replay(receipt, None, latest_generation=4) is sv.ReplayResult.UNKNOWN
    assert replay(receipt, (receipt, receipt), latest_generation=4) is sv.ReplayResult.UNKNOWN
    assert replay(receipt, (), latest_generation=5) is sv.ReplayResult.UNKNOWN

    locator = receipt.locator.model_copy(update={"index_uuid": "AAAAAAAAAAAAAAAAAAAABQ"})
    reindexed = _edit_receipt(receipt, locator=locator)
    assert reindexed.origin_sha256 != receipt.origin_sha256
    assert replay(reindexed, (receipt,), latest_generation=4) is sv.ReplayResult.UNKNOWN
    assert replay(reindexed, (), latest_generation=4) is sv.ReplayResult.NEW
    revised = _edit_receipt(receipt, locator=receipt.locator.model_copy(update={"event_revision": 4}))
    assert revised.origin_sha256 == receipt.origin_sha256
    assert replay(revised, (receipt,), latest_generation=4) is sv.ReplayResult.CONFLICT


@pytest.mark.parametrize("bad", [
    {"index_uuid": "wazuh-index-alias"}, {"index_uuid": "AAAAAAAAAAAAAAAAAAAAAB"},
    {"installation_id": "https://host"}, {"document_id": "../alert"}, {"document_id": ".."},
    {"document_id": ""}, {"document_id": "a" * 513}, {"event_revision": True},
    {"schema_version": "2.0"}, {"agent_name": "claimed"},
])
def test_locator_rejects_unsafe_or_ambiguous_formats(state, bad):
    locator = state["receipt"].locator.model_copy(update=bad)
    with pytest.raises(ValueError):
        sv.canonical_origin_bytes(locator)


@pytest.mark.parametrize("bad", [
    {"schema_version": "2.0"}, {"audit_sequence": 1}, {"receipt_id": "bad"},
    {"collected_at": NOW.replace(tzinfo=None)}, {"content_sha256": "A" * 64},
    {"content_sha256": float("nan")}, {"generation": "4"},
])
def test_receipt_encoding_rejects_malformed_records(state, bad):
    with pytest.raises(ValueError, match="^invalid_source_record$"):
        sv.canonical_receipt_bytes(state["receipt"].model_copy(update=bad))


@pytest.mark.parametrize("bad", [
    {"expires_at": NOW}, {"expires_at": float("inf")}, {"schema_version": "2.0"},
    {"verification_method": "x" * 4096}, {"attestation_id": uid(0)}, {"active": True},
])
def test_attestation_encoding_rejects_malformed_records(state, bad):
    with pytest.raises(ValueError, match="^invalid_source_record$"):
        sv.canonical_attestation_bytes(state["attestation"].model_copy(update=bad))


# Fixed wire vectors. Keep their preimages independent of the serializers under test.
ORIGIN_GOLDEN = (
    b'{"document_id":"event-42","domain":"ai-soc-team.source-origin","index_uuid":"AAAAAAAAAAAAAAAAAAA'
    b'AAQ","installation_id":"00000000-0000-0000-0000-000000000001","version":"1.0"}'
)
ORIGIN_SHA256 = "1fa37652304d4ff8fc25c09b1e3e59f1c908b8a8797bd5e12b5d39c13970a80b"
RECEIPT_GOLDEN = (
    b'{"collected_at":"2026-11-11T11:59:59.000123+00:00","collector_principal_id":"00000000-0000-0000-'
    b'0000-000000000006","collector_scope_id":"00000000-0000-0000-0000-000000000007","config_sha256":"'
    b'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","content_sha256":"aaaaaaaaaaaa'
    b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","evidence_id":"00000000-0000-0000-0000-000'
    b'000000005","generation":4,"integration_id":"00000000-0000-0000-0000-000000000004","locator":{"do'
    b'cument_id":"event-42","event_revision":3,"index_uuid":"AAAAAAAAAAAAAAAAAAAAAQ","installation_id"'
    b':"00000000-0000-0000-0000-000000000001","schema_version":"1.0"},"origin_sha256":"1fa37652304d4ff'
    b'8fc25c09b1e3e59f1c908b8a8797bd5e12b5d39c13970a80b","receipt_id":"00000000-0000-0000-0000-0000000'
    b'0000c","record_domain":"ai-soc-team.source-collection-receipt","request_id":"00000000-0000-0000-'
    b'0000-00000000000b","request_sha256":"a943db00bd5fa8318994b0f9cab31090020bdfa4704fc2a1908c4f15699'
    b'3cc11","schema_version":"1.0","source_scope_id":"00000000-0000-0000-0000-000000000003","tenant_i'
    b'd":"00000000-0000-0000-0000-000000000002"}'
)
RECEIPT_SHA256 = "a30343f05e7e49033bcd027c3419c578a4f8f8c888fb75c0b11b64029687e4ec"
ATTESTATION_GOLDEN = (
    b'{"attestation_id":"00000000-0000-0000-0000-00000000000d","attestor_principal_id":"00000000-0000-'
    b'0000-0000-000000000009","attestor_scope_id":"00000000-0000-0000-0000-00000000000a","collector_pr'
    b'incipal_id":"00000000-0000-0000-0000-000000000006","config_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbb'
    b'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","content_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    b'aaaaaaaaaaaaaaaaaaaaaaaa","evidence_id":"00000000-0000-0000-0000-000000000005","expires_at":"202'
    b'6-11-11T12:01:00.000123+00:00","generation":4,"integration_id":"00000000-0000-0000-0000-00000000'
    b'0004","origin_sha256":"1fa37652304d4ff8fc25c09b1e3e59f1c908b8a8797bd5e12b5d39c13970a80b","receip'
    b't_id":"00000000-0000-0000-0000-00000000000c","receipt_sha256":"a30343f05e7e49033bcd027c3419c578a'
    b'4f8f8c888fb75c0b11b64029687e4ec","record_domain":"ai-soc-team.source-verification-attestation","'
    b'request_id":"00000000-0000-0000-0000-00000000000f","requester_principal_id":"00000000-0000-0000-'
    b'0000-00000000000e","schema_version":"1.0","source_scope_id":"00000000-0000-0000-0000-00000000000'
    b'3","tenant_id":"00000000-0000-0000-0000-000000000002","verification_method":"independent_fetch",'
    b'"verification_version":"1","verified_at":"2026-11-11T12:00:00.000123+00:00"}'
)
ATTESTATION_SHA256 = "fdfae5c08086a276e8b7d375ef917fd96ec1c7fa11ab9568a811db97d19e03e0"
COLLECTION_REQUEST_SHA256 = "a943db00bd5fa8318994b0f9cab31090020bdfa4704fc2a1908c4f156993cc11"
VERIFICATION_REQUEST_SHA256 = "45565be2a55fa99a319630529c1537879894743a1e7c5586091775b58ee2f33d"


def test_golden_wire_records_and_digests(state):
    receipt, attestation = state["receipt"], state["attestation"]
    assert sv.canonical_origin_bytes(receipt.locator) == ORIGIN_GOLDEN
    assert sv.origin_digest(receipt.locator) == ORIGIN_SHA256
    assert sv.canonical_receipt_bytes(receipt) == RECEIPT_GOLDEN
    assert sv.receipt_digest(receipt) == RECEIPT_SHA256
    assert sv.canonical_attestation_bytes(attestation) == ATTESTATION_GOLDEN
    assert sv.attestation_digest(attestation) == ATTESTATION_SHA256
    assert receipt.request_sha256 == COLLECTION_REQUEST_SHA256

    fields = dict(reversed(tuple(attestation.model_dump(include=set(sv.VerificationRequest.model_fields)).items())))
    request = sv.VerificationRequest.model_validate(fields)
    context = TrustedContext(tenant_id=attestation.tenant_id, principal_id=attestation.requester_principal_id)
    assert sv.request_digest(context, request) == VERIFICATION_REQUEST_SHA256
    assert sv.request_digest(context.model_copy(update={"principal_id": uid(99)}), request) != VERIFICATION_REQUEST_SHA256
    with pytest.raises(ValueError, match="invalid_source_request"):
        sv.request_digest(context.model_copy(update={"tenant_id": uid(99)}), request)


def test_changed_attestation_cannot_override_expiry_or_revocation(state):
    original = state["attestation"]
    extended = original.model_copy(update={"expires_at": original.expires_at + timedelta(minutes=1)})
    assert sv.evaluate_source_verification(**dict(state, attestation=extended, at=original.expires_at)).reason == "INVALID_ATTESTATION"
    revoked = state["attestation_state"].model_copy(update={"revoked": True})
    assert sv.evaluate_source_verification(**dict(state, attestation_state=revoked)).reason == "ATTESTATION_REVOKED"


def test_internal_result_does_not_change_stored_trust_or_reach_l1(state):
    from app.analysts.evidence_adapter import StoredEvidenceAdapter
    from app.analysts.orchestration import orchestrate_l1
    from app.analysts.postgres_evidence import PostgresEvidenceRepository
    from tests.analysts.test_analyst_contracts import NOW as TASK_TIME
    from tests.analysts.test_analyst_inference import setup
    from tests.analysts.test_postgres_evidence import Session, row

    args = setup()
    evidence = row(tenant_id=args["context"].tenant_id, evidence_id=args["task"].original_evidence_ids[0])
    result = sv.evaluate_source_verification(**state)
    assert result.valid
    adapter = StoredEvidenceAdapter(PostgresEvidenceRepository(Session((evidence,))))
    del args["snapshot"], args["package"]
    for candidate in (adapter, (result,), (state["attestation"],)):
        denied = orchestrate_l1(**args, evidence=candidate, captured_at=TASK_TIME, at=TASK_TIME)
        assert (denied.status, denied.request_id) == ("DENIED", None)
    assert evidence["trust_level"] == "unverified"
    assert args["provider"].calls == 0
