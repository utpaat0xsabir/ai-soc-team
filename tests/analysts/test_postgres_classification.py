"""Offline PostgreSQL statement and classification registry consistency checks."""

import pytest
from sqlalchemy.dialects import postgresql

from app.analysts import postgres_classification as pc
from app.database.models import Base
from tests.analysts.test_classification_authority import inputs, uid


def test_schema_is_outside_application_metadata():
    assert pc.DECISIONS.name not in Base.metadata.tables
    assert pc.DECISIONS.metadata is not Base.metadata
    assert pc.DECISIONS.info["unresolved_dependency"] == "source_verification_authority"


def test_decision_lookup_requires_tenant_binding():
    query = pc.decision_lookup(uid(2), uid(3)).compile(dialect=postgresql.dialect())
    assert "tenant_id = " in str(query)
    assert uid(2) in query.params.values()
    assert uid(3) in query.params.values()
    with pytest.raises(ValueError, match="invalid_identifier"):
        pc.decision_lookup(str(uid(2)), uid(3))


@pytest.mark.parametrize(("table", "second_key"), [
    (pc.SCOPES, "scope_id"), (pc.POLICIES, "policy_id"),
    (pc.DECISIONS, "decision_id"), (pc.REVOCATIONS, "decision_id"),
])
def test_registry_keys_and_foreign_keys_are_tenant_scoped(table, second_key):
    from sqlalchemy.schema import CreateTable

    assert list(table.primary_key.columns.keys())[:2] == ["tenant_id", second_key]
    for fk in table.foreign_key_constraints:
        assert fk.ondelete == "RESTRICT"
        assert list(fk.column_keys)[0] == "tenant_id"
    sql = str(CreateTable(table).compile(dialect=postgresql.dialect()))
    assert "REFERENCES public.tenants (id) ON DELETE RESTRICT" in sql
    assert "REFERENCES public.audit_logs (tenant_id, sequence_number)" in sql


def test_registry_decision_and_revocation_constraints():
    from sqlalchemy.schema import CreateTable

    dialect = postgresql.dialect()
    sql = str(CreateTable(pc.DECISIONS).compile(dialect=dialect))
    assert "FOREIGN KEY(tenant_id, evidence_id) REFERENCES public.evidence_records (tenant_id, id)" in sql
    assert "FOREIGN KEY(tenant_id, policy_id, policy_generation, policy_sha256)" in sql
    assert "FOREIGN KEY(tenant_id, issuer_scope_id, issuer_principal_id, authority_id)" in sql
    assert "UNIQUE (tenant_id, requester_principal_id, request_id)" in sql
    assert "UNIQUE (tenant_id, evidence_id, content_sha256, policy_id, policy_generation)" in sql
    assert "issuance_sha256 ~ '^[0-9a-f]{64}$'" in sql
    assert "classification = 'OBSERVED'" in sql and "issued_at < expires_at" in sql
    assert "FOREIGN KEY(tenant_id, source_verification_id)" not in sql
    revoke = str(CreateTable(pc.REVOCATIONS).compile(dialect=dialect))
    assert "UNIQUE (tenant_id, revoker_principal_id, request_id)" in revoke
    assert "PRIMARY KEY (tenant_id, decision_id)" in revoke


def test_all_query_builders_have_bounded_tenant_predicates():
    from app.gateway.contracts import TrustedContext

    tenant, obj = uid(2), uid(3)
    context = TrustedContext(tenant_id=tenant, principal_id=obj)
    statements = (
        pc.decision_lookup(tenant, obj), pc.decision_history(tenant, obj),
        pc.latest_policy(tenant, "test"), pc.historical_policy_lookup(tenant, "test", 3),
        pc.issuer_scope_lookup(tenant, obj), pc.suspension_lookup(tenant, obj),
        pc.revocation_lookup(tenant, obj), pc.idempotency_lookup(context, "issue", obj),
        pc.idempotency_lookup(context, "revoke", obj), pc.audit_link_lookup(tenant, 1),
    )
    for statement in statements:
        compiled = statement.compile(dialect=postgresql.dialect())
        where = str(compiled).split("WHERE ", 1)[1]
        assert ".tenant_id = " in where and "LIMIT " in where
        assert tenant in compiled.params.values() and " OR " not in where
    assert ".active" not in str(statements[2]).split("WHERE ", 1)[1]
    assert "generation DESC" in str(statements[2])
    assert "suspended_at IS " not in str(statements[5]).split("WHERE ", 1)[1]


def test_query_inputs_are_values_and_history_is_bounded():
    attacker = "value' OR 'x'='x"
    sql = pc.latest_policy(uid(2), attacker).compile(dialect=postgresql.dialect())
    assert attacker not in str(sql)
    assert attacker in sql.params.values()
    with pytest.raises(ValueError, match="invalid_history_limit"):
        pc.decision_history(uid(2), uid(3), limit=33)
    foreign = pc.decision_lookup(uid(9), uid(3)).compile(dialect=postgresql.dialect())
    assert uid(2) not in foreign.params.values()
    assert uid(9) in foreign.params.values()


@pytest.fixture
def stored(inputs):
    return dict(inputs["record"].model_dump(), issuance_sha256=inputs["state"].issuance_sha256,
                request_sha256="d" * 64, audit_sequence=19)


def reconstruct(stored, inputs):
    return pc.reconstruct_issuance(stored, evidence=inputs["evidence"], scope=inputs["scope"],
                                   historical_policy=inputs["policy"])


def test_round_trip_preserves_b1_golden_record(stored, inputs):
    from app.analysts.classification_authority import canonical_issuance_bytes

    issuance = reconstruct(stored, inputs)
    assert issuance.issuance_sha256 == "08ee9212c580dcf08ea721bb01fa7652db031ef46602a264687de20db909bffb"
    assert b'"issued_at":"2026-11-11T12:00:00.000123+00:00"' in canonical_issuance_bytes(issuance.record)
    assert canonical_issuance_bytes(issuance.record) == canonical_issuance_bytes(inputs["record"])


def test_sqlalchemy_row_mapping_has_same_consistency_checks(stored, inputs):
    from sqlalchemy.engine import IteratorResult
    from sqlalchemy.engine.result import SimpleResultMetaData

    # Use a SQLAlchemy result without any engine or driver.
    keys = list(reversed(stored))
    result = IteratorResult(SimpleResultMetaData(keys), iter([tuple(stored[key] for key in keys)]))
    assert reconstruct(result.mappings().one(), inputs) == reconstruct(stored, inputs)


@pytest.mark.parametrize(("change", "reason"), [
    ({"decision_id": "bad"}, "INVALID_ISSUANCE_ROW"),
    ({"schema_version": "2.0"}, "INVALID_ISSUANCE_ROW"),
    ({"issuer_scope_id": None}, "INVALID_ISSUANCE_ROW"),
    ({"authority_id": "x" * 5000}, "INVALID_ISSUANCE_ROW"),
    ({"audit_sequence": True}, "INVALID_ISSUANCE_ROW"),
    ({"issuance_sha256": "e" * 64}, "ISSUANCE_DIGEST_MISMATCH"),
    ({"tenant_id": uid(14)}, "RELATIONAL_BINDING_MISMATCH"),
    ({"evidence_id": uid(14)}, "RELATIONAL_BINDING_MISMATCH"),
    ({"policy_sha256": "e" * 64}, "RELATIONAL_BINDING_MISMATCH"),
])
def test_row_reconstruction_denials(stored, inputs, change, reason):
    with pytest.raises(pc.RegistryError, match=f"^{reason}$"):
        reconstruct(dict(stored, **change), inputs)


def test_missing_fields_and_changed_timestamp_fail(stored, inputs):
    from datetime import timedelta

    with pytest.raises(pc.RegistryError, match="^ISSUANCE_DIGEST_MISMATCH$"):
        reconstruct(dict(stored, expires_at=stored["expires_at"] + timedelta(microseconds=1)), inputs)
    del stored["source_verification_id"]
    with pytest.raises(pc.RegistryError, match="^INVALID_ISSUANCE_ROW$"):
        reconstruct(stored, inputs)


@pytest.fixture
def linkage(stored, inputs):
    issuance = reconstruct(stored, inputs)
    event = pc.IssuanceAuditEvent(
        tenant_id=issuance.record.tenant_id, sequence_number=issuance.audit_sequence, action=pc.IssueAction,
        resource_type=pc.DecisionResource, resource_id=issuance.record.decision_id,
        actor_type="service", actor_id=issuance.record.issuer_principal_id, issuance_sha256=issuance.issuance_sha256,
    )
    return dict(issuance=issuance, event=event, expected_tenant=event.tenant_id,
                expected_action=event.action, expected_resource_type=event.resource_type,
                expected_resource_id=event.resource_id)


def test_audit_link_matches_exact_actor_record_and_digest(linkage):
    assert pc.validate_audit_link(**linkage)
    assert not pc.validate_audit_link(**dict(linkage, event=None))
    assert not pc.validate_audit_link(**dict(linkage, expected_resource_id=uid(10)))


@pytest.mark.parametrize("changed", [
    {"tenant_id": uid(14)}, {"sequence_number": 27}, {"action": "evidence.other"},
    {"resource_type": "another_type"}, {"resource_id": uid(14)}, {"actor_id": uid(14)},
    {"actor_type": "api_key"}, {"issuance_sha256": "f" * 64},
])
def test_audit_link_mismatch_denies(linkage, changed):
    linkage["event"] = linkage["event"].model_copy(update=changed)
    assert not pc.validate_audit_link(**linkage)


def test_idempotency_binds_operation_context_and_exact_content(inputs):
    from app.gateway.contracts import TrustedContext

    rec = inputs["record"]
    context = TrustedContext(tenant_id=rec.tenant_id, principal_id=rec.requester_principal_id)
    request = pc.IssueRequest(request_id=rec.request_id, evidence_id=rec.evidence_id,
                              expected_content_sha256=rec.content_sha256)
    bound = pc.bind_request(context, request)
    assert bound == pc.bind_request(context, request)
    assert pc.check_retry(bound, (bound,)) is pc.RetryResult.EXACT_RETRY
    assert pc.check_retry(bound, ()) is pc.RetryResult.NEW
    assert pc.check_retry(bound, None) is pc.RetryResult.UNKNOWN
    assert pc.check_retry(bound, (bound, bound)) is pc.RetryResult.UNKNOWN
    conflicting = pc.bind_request(context, request.model_copy(update={"evidence_id": uid(14)}))
    assert pc.check_retry(bound, (conflicting,)) is pc.RetryResult.CONFLICT
    revoked = pc.bind_request(context, pc.RevokeRequest(
        request_id=rec.request_id, decision_id=rec.decision_id, reason_code="OPERATOR_REVOKED",
    ))
    assert revoked.request_sha256 != bound.request_sha256
    assert pc.check_retry(bound, (revoked,)) is pc.RetryResult.UNKNOWN
    with pytest.raises(pc.RegistryError, match="^INVALID_REQUEST$"):
        pc.bind_request(context, request.model_copy(update={"principal_id": uid(99)}))
    for field in ("tenant_id", "principal_id"):
        other = pc.bind_request(context.model_copy(update={field: uid(99)}), request)
        assert other.request_sha256 != bound.request_sha256
        assert pc.check_retry(bound, (other,)) is pc.RetryResult.UNKNOWN


def test_lifecycle_does_not_resurrect_or_extend_history(stored, inputs):
    prior = reconstruct(stored, inputs)
    args = dict(prior=prior, evidence=inputs["evidence"], scope=inputs["scope"],
                current_policy=inputs["policy"], state=inputs["state"], at=inputs["at"])
    evaluate = pc.issuance_lifecycle
    expected = pc.IssuanceLifecycle
    assert evaluate(**args) is expected.DUPLICATE
    assert evaluate(**dict(args, state=None)) is expected.UNKNOWN
    assert evaluate(**dict(args, current_policy=None)) is expected.UNKNOWN
    assert evaluate(**dict(args, scope=None)) is expected.UNKNOWN
    assert evaluate(**dict(args, scope=args["scope"].model_copy(update={"active": False}))) is expected.INACTIVE
    assert evaluate(**dict(args, current_policy=args["current_policy"].model_copy(update={"active": False}))) is expected.INACTIVE
    assert evaluate(**dict(args, at=prior.record.expires_at)) is expected.EXPIRED
    assert evaluate(**dict(args, state=args["state"].model_copy(update={"revoked": True}))) is expected.REVOKED
    higher = args["current_policy"].model_copy(update={"generation": prior.record.policy_generation + 1})
    assert evaluate(**dict(args, current_policy=higher, at=prior.record.expires_at)) is expected.HIGHER_GENERATION


def test_source_dependency_cannot_attest_or_authorize(stored, inputs):
    from app.analysts.classification_authority import evaluate_validity, ValidityResult

    issuance = reconstruct(stored, inputs)
    missing = pc.SourceVerificationRequirement(
        **inputs["evidence"].model_dump(), source_id=inputs["scope"].source_id,
        verification_id=issuance.record.source_verification_id,
    )
    assert missing.status == "SOURCE_VERIFICATION_UNAVAILABLE"
    assert evaluate_validity(**dict(inputs, source=missing)) is ValidityResult.INVALID_STATE


def test_linkage_and_query_construction_do_not_access_io(linkage, monkeypatch):
    import socket

    import psycopg

    from app.analysts.inference import FakeModelProvider

    def forbidden(*args, **kwargs):
        pytest.fail("unexpected I/O or provider call")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(psycopg, "connect", forbidden)
    monkeypatch.setattr(FakeModelProvider, "generate", forbidden)
    assert pc.validate_audit_link(**linkage)
    assert pc.audit_link_lookup(linkage["expected_tenant"], linkage["event"].sequence_number).compile(
        dialect=postgresql.dialect()
    )
