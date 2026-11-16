
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from sqlalchemy.dialects import postgresql

from app.audit.integrity import (
    AUDIT_LOCK_PROTOCOL,
    GENESIS_HASH,
    _audit_advisory_lock_key,
    _record_audit_event_advisory_candidate,
    calculate_audit_hash,
    record_audit_event,
    verify_audit_chain,
)


def audit_hash_inputs():
    return {
        "tenant_id": uuid4(),
        "sequence_number": 1,
        "previous_hash": GENESIS_HASH,
        "actor_type": "api_key",
        "actor_id": uuid4(),
        "action": "evidence.ingested",
        "resource_type": "evidence",
        "resource_id": uuid4(),
        "details": {"evidence_type": "observation"},
        "created_at": datetime(
            2026, 11, 9, 12, 0, 0, tzinfo=timezone.utc
        ),
    }


def test_calculate_audit_hash_is_deterministic():
    inputs = audit_hash_inputs()

    first_hash = calculate_audit_hash(**inputs)
    second_hash = calculate_audit_hash(**inputs)

    assert first_hash == second_hash
    assert len(first_hash) == 64
    assert all(character in "0123456789abcdef" for character in first_hash)


def test_calculate_audit_hash_changes_when_details_change():
    inputs = audit_hash_inputs()

    original_hash = calculate_audit_hash(**inputs)
    modified_inputs = {
        **inputs,
        "details": {"evidence_type": "conclusion"},
    }

    assert original_hash != calculate_audit_hash(**modified_inputs)


def test_calculate_audit_hash_changes_when_previous_hash_changes():
    inputs = audit_hash_inputs()

    original_hash = calculate_audit_hash(**inputs)
    modified_inputs = {
        **inputs,
        "previous_hash": "a" * 64,
    }

    assert original_hash != calculate_audit_hash(**modified_inputs)


def test_calculate_audit_hash_changes_when_sequence_changes():
    inputs = audit_hash_inputs()

    original_hash = calculate_audit_hash(**inputs)
    modified_inputs = {
        **inputs,
        "sequence_number": 2,
    }

    assert original_hash != calculate_audit_hash(**modified_inputs)


def test_genesis_hash_is_64_zeroes():
    assert GENESIS_HASH == "0" * 64


def make_audit_event(sequence_number, previous_hash, tenant_id=None):
    inputs = {
        "tenant_id": tenant_id or uuid4(),
        "sequence_number": sequence_number,
        "previous_hash": previous_hash,
        "actor_type": "api_key",
        "actor_id": uuid4(),
        "action": "evidence.ingested",
        "resource_type": "evidence",
        "resource_id": uuid4(),
        "details": {"evidence_type": "observation"},
        "created_at": datetime(
            2026, 11, 9, 12, sequence_number, 0,
            tzinfo=timezone.utc,
        ),
    }

    entry_hash = calculate_audit_hash(**inputs)

    return SimpleNamespace(
        **inputs,
        entry_hash=entry_hash,
    )


def make_valid_audit_chain(length=2):
    tenant_id = uuid4()
    events = []
    previous_hash = GENESIS_HASH

    for sequence_number in range(1, length + 1):
        event = make_audit_event(
            sequence_number,
            previous_hash,
            tenant_id,
        )
        events.append(event)
        previous_hash = event.entry_hash

    return events


def test_verify_audit_chain_accepts_valid_chain():
    events = make_valid_audit_chain()

    result = verify_audit_chain(events)

    assert result["valid"] is True
    assert result["total"] == 2
    assert result["checked"] == 2
    assert result["first_invalid_sequence"] is None
    assert result["failure_reason"] is None


def test_verify_audit_chain_detects_modified_details():
    events = make_valid_audit_chain()
    events[0].details = {"evidence_type": "conclusion"}

    result = verify_audit_chain(events)

    assert result["valid"] is False
    assert result["first_invalid_sequence"] == 1
    assert result["failure_reason"] == "entry_hash_mismatch"


def test_verify_audit_chain_detects_previous_hash_mismatch():
    events = make_valid_audit_chain()
    events[1].previous_hash = "a" * 64

    result = verify_audit_chain(events)

    assert result["valid"] is False
    assert result["first_invalid_sequence"] == 2
    assert result["failure_reason"] == "previous_hash_mismatch"


def test_verify_audit_chain_detects_sequence_gap():
    events = make_valid_audit_chain()
    events[1].sequence_number = 3

    result = verify_audit_chain(events)

    assert result["valid"] is False
    assert result["first_invalid_sequence"] == 3
    assert result["failure_reason"] == "sequence_mismatch"


def test_verify_audit_chain_cannot_detect_deleted_tail():
    full_chain = make_valid_audit_chain(length=3)

    # Simulate deletion of the newest audit record.
    truncated_chain = full_chain[:2]

    result = verify_audit_chain(truncated_chain)

    # The remaining prefix is internally valid.
    assert result["valid"] is True
    assert result["total"] == 2
    assert result["checked"] == 2


def test_audit_advisory_lock_key_is_stable_domain_separated_signed_bigint():
    tenant_id = UUID("00000000-0000-0000-0000-000000000001")

    key = _audit_advisory_lock_key(tenant_id)

    assert key == -1951576002590208640
    assert -(1 << 63) <= key < (1 << 63)
    assert _audit_advisory_lock_key(tenant_id) == key


class CandidateAuditSession:
    def __init__(self, tenant=True, previous_event=None, lock_error=None):
        self.tenant = object() if tenant else None
        self.previous_event = previous_event
        self.lock_error = lock_error
        self.operations = []
        self.events = []

    def execute(self, statement):
        compiled = statement.compile(dialect=postgresql.dialect())
        self.operations.append(("execute", str(compiled), compiled.params))
        if self.lock_error is not None:
            raise self.lock_error

    def scalar(self, statement):
        compiled = statement.compile(dialect=postgresql.dialect())
        sql = str(compiled)
        self.operations.append(("scalar", sql, compiled.params))
        if "FROM tenants" in sql:
            return self.tenant
        if "FROM audit_logs" in sql:
            return self.previous_event
        raise AssertionError(f"unexpected query: {sql}")

    def add(self, event):
        self.events.append(event)

    def flush(self):
        pass


def record_candidate(session, tenant_id):
    return _record_audit_event_advisory_candidate(
        session,
        tenant_id=tenant_id,
        actor_type="service",
        actor_id=None,
        action="audit.test",
        resource_type="test",
    )


def test_advisory_candidate_locks_before_tenant_and_chain_head_then_links_events():
    tenant_id = uuid4()
    first_session = CandidateAuditSession()

    first = record_candidate(first_session, tenant_id)

    assert first.sequence_number == 1
    assert first.previous_hash == GENESIS_HASH
    assert [operation[0] for operation in first_session.operations] == [
        "execute", "scalar", "scalar",
    ]
    lock_sql, lock_params = first_session.operations[0][1:]
    assert "pg_advisory_xact_lock" in lock_sql
    assert _audit_advisory_lock_key(tenant_id) in lock_params.values()
    assert "FOR NO KEY UPDATE" not in lock_sql

    second_session = CandidateAuditSession(previous_event=first)
    second = record_candidate(second_session, tenant_id)

    assert second.sequence_number == 2
    assert second.previous_hash == first.entry_hash
    assert verify_audit_chain([first, second])["valid"] is True


def test_advisory_candidate_rejects_missing_tenant_before_reading_chain():
    session = CandidateAuditSession(tenant=False)

    with pytest.raises(ValueError, match="audit_tenant_not_found"):
        record_candidate(session, uuid4())

    assert [operation[0] for operation in session.operations] == ["execute", "scalar"]
    assert session.events == []


def test_advisory_candidate_propagates_lock_timeout_without_appending():
    session = CandidateAuditSession(lock_error=RuntimeError("lock timeout"))

    with pytest.raises(RuntimeError, match="lock timeout"):
        record_candidate(session, uuid4())

    assert len(session.operations) == 1
    assert session.events == []


def test_production_audit_writer_keeps_tenant_row_lock_default():
    session = CandidateAuditSession(tenant=False)

    with pytest.raises(ValueError, match="audit_tenant_not_found"):
        record_audit_event(
            session,
            tenant_id=uuid4(),
            actor_type="service",
            actor_id=None,
            action="audit.test",
            resource_type="test",
        )

    assert len(session.operations) == 1
    assert "FOR NO KEY UPDATE" in session.operations[0][1]
    assert AUDIT_LOCK_PROTOCOL == "tenant-row-no-key-update-v1"
