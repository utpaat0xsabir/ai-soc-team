"""Offline PostgreSQL specifications for source verification."""

from dataclasses import replace
from datetime import timedelta

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateIndex, CreateTable

from app.analysts import postgres_source_verification as ps
from app.analysts import source_verification as sv
from app.database import source_registry_schema as schema
from app.database.models import Base
from tests.analysts.test_source_verification import NOW, state as sv_state, uid


def test_source_registry_metadata_is_inert():
    assert schema.RECEIPTS.metadata is not Base.metadata
    assert schema.RECEIPTS.metadata.info["deployment_ready"] is False


def complete(value):
    return ps.Lookup(ps.LookupStatus.COMPLETE_MATCH, value)


@pytest.fixture
def bundle(sv_state):
    source = sv_state
    receipt, attestation = source["receipt"], source["attestation"]
    config_fields = dict(source["configuration"].model_dump(exclude={"schema_version"}),
                         collector_build="collector-v1", approved_index_uuids={receipt.locator.index_uuid: True},
                         approval_id=uid(20), activated_at=NOW - timedelta(days=1), audit_sequence=1)
    config = ps.reconstruct_configuration(
        config_fields, tenant_id=receipt.tenant_id, source_scope_id=receipt.source_scope_id,
        integration_id=receipt.integration_id,
    )
    receipt_fields = receipt.model_dump(exclude={"locator"})
    locator = receipt.locator.model_dump()
    receipt_fields.update(locator_schema_version=locator.pop("schema_version"), **locator,
                          receipt_sha256=sv.receipt_digest(receipt), audit_sequence=2)
    receipt_row = ps.reconstruct_receipt(receipt_fields, evidence=source["evidence"], configuration=config)
    request_hash = ps._verification_request_digest(attestation)
    epoch = uid(21)
    retrieval = source["retrieval"]
    attempt = ps.RetrievalAttempt(
        attempt_id=uid(22), attestor=source["attestor"], credential_epoch_id=epoch,
        result=retrieval, result_sha256=ps.retrieval_result_digest(retrieval),
        started_at=NOW - timedelta(microseconds=2), completed_at=NOW - timedelta(microseconds=1),
        request_sha256=request_hash,
    )
    att_fields = dict(attestation.model_dump(), attestation_sha256=sv.attestation_digest(attestation),
                      request_sha256=request_hash, retrieval_attempt_id=attempt.attempt_id,
                      retrieval_attempt_sha256=ps.retrieval_attempt_digest(attempt), audit_sequence=3)
    att_row = ps.reconstruct_attestation(
        att_fields, receipt=receipt_row, evidence=source["evidence"], configuration=config,
    )
    def event(action, kind, resource, actor, sequence, digest, request, retrieval_digest=None):
        return dict(tenant_id=receipt.tenant_id, sequence_number=sequence, action=action, actor_type="service",
                    actor_id=actor, resource_type=kind, resource_id=resource,
                    details=dict(record_sha256=digest, request_sha256=request,
                                 retrieval_attempt_sha256=retrieval_digest))
    receipt_event = event("source_authority.receipt", "source_collection_receipt", receipt.receipt_id,
                          receipt.collector_principal_id, 2, receipt_row.receipt_sha256, receipt.request_sha256)
    att_event = event("source_authority.attest", "source_verification_attestation", attestation.attestation_id,
                      attestation.attestor_principal_id, 3, att_row.attestation_sha256, request_hash,
                      att_row.retrieval_attempt_sha256)
    suspension = ps.reconstruct_suspension(
        dict(tenant_id=receipt.tenant_id, source_scope_id=receipt.source_scope_id,
             integration_id=receipt.integration_id, suspended_at=None, suspension_audit_sequence=None),
        tenant_id=receipt.tenant_id, source_scope_id=receipt.source_scope_id, integration_id=receipt.integration_id,
    )
    state = ps.CurrentState(
        receipt=complete(receipt_row), attestation=complete(att_row), configuration=complete(config),
        suspension=complete(suspension),
        revocation=ps.RevocationObservation(receipt.tenant_id, attestation.attestation_id,
                                            ps.Lookup(ps.LookupStatus.COMPLETE_MISS)),
        receipt_audit=complete(ps.reconstruct_audit_link(receipt_event)),
        attestation_audit=complete(ps.reconstruct_audit_link(att_event)),
    )
    policy = ps.LifetimePolicy(
        tenant_id=receipt.tenant_id, source_scope_id=receipt.source_scope_id, policy_id="test",
        generation=config.generation, config_sha256=config.config_sha256,
        max_lifetime_seconds=60, max_retrieval_age_seconds=10,
    )
    args = dict(state=state, evidence=source["evidence"], collector=source["collector"], attestor=source["attestor"],
                attestor_epoch_id=epoch, attempt=attempt, policy=policy, latest_generation=4, at=NOW)
    return args, config_fields, receipt_fields, att_fields, att_event


def test_compile_schema_and_global_keys():
    tables = (schema.INSTALLATIONS, schema.SCOPES, schema.CONFIGURATIONS, schema.RECEIPTS,
              schema.ATTESTATIONS, schema.REVOCATIONS)
    assert len({table.name for table in tables}) == 6
    assert all(table.fullname not in Base.metadata.tables and table.name not in Base.metadata.tables for table in tables)
    sql = {table.name: str(CreateTable(table).compile(dialect=postgresql.dialect())) for table in tables}
    assert "UNIQUE (canonical_enrollment_identity)" in sql[schema.INSTALLATIONS.name]
    assert "UNIQUE (installation_id, index_uuid, document_id)" in sql[schema.RECEIPTS.name]
    assert "UNIQUE (tenant_id, attestation_id, evidence_id, content_sha256)" in sql[schema.ATTESTATIONS.name]
    assert "PRIMARY KEY (tenant_id, attestation_id)" in sql[schema.REVOCATIONS.name]
    assert "jsonb_path_exists" in sql[schema.CONFIGURATIONS.name]
    for table in tables:
        for fk in table.foreign_key_constraints:
            assert fk.ondelete == "RESTRICT" and fk.column_keys[0] == "tenant_id"
    assert any(tuple(fk.column_keys) == schema.CONFIG_KEY for fk in schema.ATTESTATIONS.foreign_key_constraints)
    assert any(tuple(fk.column_keys) == schema.RECEIPT_BINDING for fk in schema.ATTESTATIONS.foreign_key_constraints)
    assert any(tuple(fk.column_keys) == ("tenant_id", "integration_id") for fk in schema.SCOPES.foreign_key_constraints)
    indexes = {index.name: str(CreateIndex(index).compile(dialect=postgresql.dialect()))
               for table in tables for index in table.indexes}
    assert "WHERE suspended_at IS NULL" in indexes["uq_source_active_installation"]
    assert "collected_at DESC" in indexes["ix_source_receipt_history"]
    assert "verified_at DESC" in indexes["ix_source_attestation_history"]


def test_builders_bind_tenant_and_limit_without_global_claim():
    tenant, ident = uid(2), uid(3)
    builders = (
        ps.installation_lookup(tenant, ident), ps.scope_lookup(tenant, ident),
        ps.latest_configuration(tenant, ident), ps.exact_configuration(tenant, ident, 4, "a" * 64),
        ps.receipt_lookup(tenant, ident), ps.receipt_history(tenant, ident),
        ps.attestation_lookup(tenant, ident), ps.attestation_history(tenant, ident),
        ps.revocation_lookup(tenant, ident), ps.audit_lookup(tenant, 1), ps.suspension_lookup(tenant, ident),
    )
    for query in builders:
        compiled = query.compile(dialect=postgresql.dialect())
        where = str(compiled).split("WHERE ", 1)[1]
        assert "tenant_id = " in where and "LIMIT " in where
        assert tenant in compiled.params.values()
        assert " JOIN " not in str(compiled)
    assert "source_scope_id = " in str(builders[3]) and "config_sha256 = " in str(builders[3]).split("WHERE ")[1]
    assert ".active" not in str(builders[2]).split("WHERE ", 1)[1]
    assert not hasattr(ps, "global_origin_lookup")
    with pytest.raises(ps.RegistryError, match="INVALID_IDENTIFIER"):
        ps.receipt_lookup("x' OR 1=1", ident)
    with pytest.raises(ps.RegistryError, match="INVALID_HISTORY_LIMIT"):
        ps.attestation_history(tenant, ident, limit=33)


def test_canonical_round_trip_with_sqlalchemy_row_mapping(bundle):
    from sqlalchemy.engine import IteratorResult
    from sqlalchemy.engine.result import SimpleResultMetaData
    from tests.analysts.test_source_verification import RECEIPT_GOLDEN, ATTESTATION_GOLDEN

    args, _, fields, _, _ = bundle
    keys = tuple(reversed(fields))
    result = IteratorResult(SimpleResultMetaData(keys), iter([tuple(fields[key] for key in keys)]))
    reconstructed = ps.reconstruct_receipt(result.mappings().one(), evidence=args["evidence"],
                                            configuration=args["state"].configuration.value)
    assert sv.canonical_receipt_bytes(reconstructed.record) == RECEIPT_GOLDEN
    assert sv.canonical_attestation_bytes(args["state"].attestation.value.record) == ATTESTATION_GOLDEN


@pytest.mark.parametrize("changes", [
    {"tenant_id": uid(99)}, {"evidence_id": uid(99)}, {"content_sha256": "d" * 64},
    {"installation_id": uid(99)}, {"event_revision": None}, {"origin_sha256": "c" * 64},
    {"generation": 3}, {"schema_version": "2.0"}, {"collected_at": NOW.replace(tzinfo=None)},
    {"locator_schema_version": None}, {"receipt_sha256": None}, {"unexpected": "field"},
])
def test_receipt_corruption_denies(bundle, changes):
    args, _, fields, _, _ = bundle
    with pytest.raises(ps.RegistryError, match="^INVALID_RECEIPT$"):
        ps.reconstruct_receipt(fields | changes, evidence=args["evidence"],
                               configuration=args["state"].configuration.value)


@pytest.mark.parametrize("changes", [
    {"evidence_id": uid(99)}, {"receipt_id": uid(99)}, {"request_sha256": "c" * 64},
    {"generation": 3}, {"expires_at": NOW}, {"scope_id": uid(99)}, {"audit_sequence": None},
])
def test_attestation_corruption_denies(bundle, changes):
    args, _, _, fields, _ = bundle
    with pytest.raises(ps.RegistryError, match="^INVALID_ATTESTATION$"):
        ps.reconstruct_attestation(fields | changes, receipt=args["state"].receipt.value,
                                   evidence=args["evidence"], configuration=args["state"].configuration.value)


def test_missing_column_and_invalid_configuration_set_deny(bundle):
    args, fields, _, att_fields, _ = bundle
    del att_fields["receipt_id"]
    with pytest.raises(ps.RegistryError, match="^INVALID_ATTESTATION$"):
        ps.reconstruct_attestation(att_fields, receipt=args["state"].receipt.value, evidence=args["evidence"],
                                   configuration=args["state"].configuration.value)
    config = args["state"].configuration.value
    fields["approved_index_uuids"] = {config.approved_index_uuids[0]: False}
    with pytest.raises(ps.RegistryError, match="^INVALID_CONFIGURATION$"):
        ps.reconstruct_configuration(fields, tenant_id=config.tenant_id, source_scope_id=config.source_scope_id,
                                     integration_id=config.integration_id)


def _replay(bundle, status, candidate=None, **updates):
    args = bundle[0]
    row = args["state"].receipt.value
    candidate = candidate or row.record
    lookup = complete(row) if status is ps.LookupStatus.COMPLETE_MATCH else ps.Lookup(status)
    observation = ps.GlobalOriginObservation(candidate.origin_sha256, lookup)
    options = dict(configuration=args["state"].configuration.value, collector=args["collector"], latest_generation=4)
    return ps.classify_origin(candidate, observation, **(options | updates))


@pytest.mark.parametrize(("status", "expected"), [
    ("COMPLETE_MISS", "NEW"), ("COMPLETE_MATCH", "EXACT_RETRY"), ("CONFLICT", "CONFLICT"),
    ("AMBIGUOUS", "UNKNOWN"), ("UNAVAILABLE", "UNKNOWN"), ("UNAUTHORIZED", "UNKNOWN"),
])
def test_explicit_global_replay_state(bundle, status, expected):
    assert _replay(bundle, ps.LookupStatus[status]).value == expected


@pytest.mark.parametrize(("change", "expected"), [
    ({"request_id": uid(99)}, "REVIEW_REQUIRED"), ({"content_sha256": "c" * 64}, "CONFLICT"),
    ({"evidence_id": uid(99)}, "CONFLICT"), ({"tenant_id": uid(99)}, "UNKNOWN"),
    ({"source_scope_id": uid(99)}, "UNKNOWN"),
])
def test_replay_cannot_create_another_receipt(bundle, change, expected):
    from tests.analysts.test_source_verification import _edit_receipt

    receipt = bundle[0]["state"].receipt.value.record
    assert _replay(bundle, ps.LookupStatus.COMPLETE_MATCH, _edit_receipt(receipt, **change)).value == expected


def test_replay_discriminates_revision_index_generation_and_credentials(bundle):
    from tests.analysts.test_source_verification import _edit_receipt

    args = bundle[0]
    receipt = args["state"].receipt.value.record
    locator = receipt.locator
    revised = _edit_receipt(receipt, locator=locator.model_copy(update={"event_revision": 4}))
    assert _replay(bundle, ps.LookupStatus.COMPLETE_MATCH, revised).value == "CONFLICT"
    other_index = "AAAAAAAAAAAAAAAAAAAABQ"
    reindexed = _edit_receipt(receipt, locator=locator.model_copy(update={"index_uuid": other_index}))
    config = args["state"].configuration.value
    allowed = config.model_copy(update={"approved_index_uuids": (*config.approved_index_uuids, other_index)})
    assert _replay(bundle, ps.LookupStatus.COMPLETE_MATCH, reindexed, configuration=allowed).value == "UNKNOWN"
    assert _replay(bundle, ps.LookupStatus.COMPLETE_MISS, reindexed, configuration=allowed).value == "NEW"
    assert _replay(bundle, ps.LookupStatus.COMPLETE_MISS, latest_generation=5).value == "UNKNOWN"
    collector = args["collector"].model_copy(update={"credential_epoch_id": uid(99)})
    assert _replay(bundle, ps.LookupStatus.COMPLETE_MISS, collector=collector).value == "UNKNOWN"
    rotated = config.model_copy(update={"generation": 5, "config_sha256": "d" * 64, "credential_epoch_id": uid(99)})
    collector = collector.model_copy(update={"generation": 5})
    next_request = _edit_receipt(
        receipt, generation=5, config_sha256=rotated.config_sha256, request_id=uid(99),
    )
    assert _replay(bundle, ps.LookupStatus.COMPLETE_MATCH, next_request, configuration=rotated,
                   latest_generation=5, collector=collector).value == "REVIEW_REQUIRED"


def test_current_state_is_consistency_only_and_denies_expiry(bundle, monkeypatch):
    import socket
    import psycopg
    from app.analysts.inference import FakeModelProvider

    def forbidden(*args, **kwargs):
        pytest.fail("unexpected connection or model access")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(psycopg, "connect", forbidden)
    monkeypatch.setattr(FakeModelProvider, "generate", forbidden)
    args = bundle[0]
    assert ps.evaluate_current(**args) == ps.CurrentResult(True, "CONSISTENT")
    assert ps.evaluate_current(**(args | {"at": NOW + timedelta(seconds=60)})).reason == "EXPIRED"
    assert ps.evaluate_current(**(args | {"latest_generation": 5})).reason == "CONFIGURATION_INACTIVE"
    assert ps.evaluate_current(**(args | {"attestor_epoch_id": uid(99)})).reason == "RETRIEVAL_PROVENANCE_MISMATCH"
    shorter = args["policy"].model_copy(update={"max_lifetime_seconds": 59})
    assert ps.evaluate_current(**(args | {"policy": shorter})).reason == "LIFETIME_POLICY_DENIED"


@pytest.mark.parametrize("status", ["UNAVAILABLE", "UNAUTHORIZED", "AMBIGUOUS", "CONFLICT"])
def test_revocation_visibility_failures_never_prove_absence(bundle, status):
    args = bundle[0]
    state = args["state"]
    observation = replace(state.revocation, result=ps.Lookup(ps.LookupStatus[status]))
    assert ps.evaluate_current(**(args | {"state": replace(state, revocation=observation)})).reason == "INCOMPLETE_STATE"


def test_revocation_miss_is_keyed_and_permanent_revocation_denies(bundle):
    args = bundle[0]
    state = args["state"]
    observation = replace(state.revocation, attestation_id=uid(99))
    assert ps.evaluate_current(**(args | {"state": replace(state, revocation=observation)})).reason == "INCOMPLETE_STATE"
    record = ps.reconstruct_revocation(
        dict(tenant_id=state.revocation.tenant_id, attestation_id=state.revocation.attestation_id,
             revoker_principal_id=uid(25), request_id=uid(26), request_sha256="d" * 64,
             revoked_at=NOW, reason_code="REVOKED", audit_sequence=4),
        tenant_id=state.revocation.tenant_id, attestation_id=state.revocation.attestation_id,
    )
    revoked = replace(state.revocation, result=complete(record))
    assert ps.evaluate_current(**(args | {"state": replace(state, revocation=revoked)})).reason == "ATTESTATION_REVOKED"


def test_suspension_and_disabled_policy_deny(bundle):
    args = bundle[0]
    state = args["state"]
    scope = state.suspension.value.model_copy(update={
        "suspended": True, "suspended_at": NOW, "suspension_audit_sequence": 4,
    })
    assert ps.evaluate_current(**(args | {"state": replace(state, suspension=complete(scope))})).reason == "SCOPE_SUSPENDED"
    disabled = state.configuration.value.model_copy(update={"active": False})
    assert ps.evaluate_current(**(args | {"state": replace(state, configuration=complete(disabled))})).reason == "CONFIGURATION_INACTIVE"


@pytest.mark.parametrize("status", ["COMPLETE_MISS", "UNAVAILABLE", "AMBIGUOUS", "CONFLICT"])
def test_missing_or_conflicting_audit_denies(bundle, status):
    args = bundle[0]
    state = replace(args["state"], attestation_audit=ps.Lookup(ps.LookupStatus[status]))
    assert ps.evaluate_current(**(args | {"state": state})).reason == "AUDIT_LINK_MISMATCH"


@pytest.mark.parametrize("changes", [
    {"actor_id": uid(99)}, {"action": "source_authority.receipt"}, {"sequence_number": 2},
    {"record_sha256": "d" * 64}, {"request_sha256": "d" * 64}, {"retrieval_attempt_sha256": "d" * 64},
])
def test_wrong_audit_fields_deny(bundle, changes):
    args = bundle[0]
    state = args["state"]
    event = state.attestation_audit.value.model_copy(update=changes)
    assert not ps.validate_audit_link(state.attestation.value, complete(event))


def test_same_audit_sequence_cannot_link_to_two_records(bundle):
    args = bundle[0]
    state = args["state"]
    sequence = state.receipt.value.audit_sequence
    attestation = state.attestation.value.model_copy(update={"audit_sequence": sequence})
    event = state.attestation_audit.value.model_copy(update={"sequence_number": sequence})
    conflicting = replace(state, attestation=complete(attestation), attestation_audit=complete(event))
    assert ps.evaluate_current(**(args | {"state": conflicting})).reason == "AUDIT_LINK_MISMATCH"


def test_internally_consistent_registry_output_cannot_enter_l1(bundle):
    from app.analysts.evidence_adapter import StoredEvidenceAdapter
    from app.analysts.orchestration import orchestrate_l1
    from app.analysts.postgres_evidence import PostgresEvidenceRepository
    from tests.analysts.test_analyst_contracts import NOW as TASK_TIME
    from tests.analysts.test_analyst_inference import setup
    from tests.analysts.test_postgres_evidence import Session, row

    result = ps.evaluate_current(**bundle[0])
    assert result.valid
    args = setup()
    evidence = row(tenant_id=args["context"].tenant_id, trust_level="system_verified",
                   evidence_id=args["task"].original_evidence_ids[0])
    del args["snapshot"], args["package"]
    for candidate in ((result,), StoredEvidenceAdapter(PostgresEvidenceRepository(Session((evidence,))))):
        denied = orchestrate_l1(**args, evidence=candidate, captured_at=TASK_TIME, at=TASK_TIME)
        assert (denied.status, denied.request_id) == ("DENIED", None)
    assert args["provider"].calls == 0
