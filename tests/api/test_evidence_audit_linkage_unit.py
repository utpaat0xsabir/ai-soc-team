from uuid import UUID

import pytest
from pydantic import ValidationError

from app.api.v1 import evidence as evidence_route
from app.iam.auth import AuthenticatedPrincipal
from app.schemas import EvidenceCreate


TENANT_ID = UUID("00000000-0000-0000-0000-000000000001")
API_KEY_ID = UUID("00000000-0000-0000-0000-000000000002")
EVIDENCE_ID = UUID("00000000-0000-0000-0000-000000000003")


class FakeSession:
    def __init__(self):
        self.calls = []
        self.record = None

    def add(self, record):
        self.calls.append("add")
        self.record = record

    def flush(self):
        self.calls.append("flush")
        self.record.id = EVIDENCE_ID

    def commit(self):
        self.calls.append("commit")

    def refresh(self, record):
        self.calls.append("refresh")

    def rollback(self):
        self.calls.append("rollback")


def request_data():
    return EvidenceCreate(
        evidence_type="observation",
        source_type="test",
        source_reference="test/evidence-1",
        payload={"observed": True},
    )


def principal():
    return AuthenticatedPrincipal(tenant_id=TENANT_ID, api_key_id=API_KEY_ID)


def test_evidence_uuid_is_flushed_before_tenant_scoped_audit(monkeypatch):
    session = FakeSession()
    audit_calls = []

    def record_audit_event(db, **fields):
        audit_calls.append((db, fields, tuple(session.calls)))

    monkeypatch.setattr(evidence_route, "record_audit_event", record_audit_event)

    evidence = evidence_route.ingest_evidence(request_data(), principal(), session)

    assert evidence.id == EVIDENCE_ID
    assert evidence.tenant_id == TENANT_ID
    assert len(audit_calls) == 1
    db, fields, calls_at_audit = audit_calls[0]
    assert db is session
    assert fields["resource_id"] == evidence.id
    assert fields["tenant_id"] == evidence.tenant_id
    assert calls_at_audit == ("add", "flush")
    assert session.calls == ["add", "flush", "commit", "refresh"]


def test_audit_failure_rolls_back_evidence_without_committing(monkeypatch):
    session = FakeSession()

    def fail_audit(*args, **kwargs):
        session.calls.append("audit")
        raise RuntimeError("audit_write_failed")

    monkeypatch.setattr(evidence_route, "record_audit_event", fail_audit)

    with pytest.raises(RuntimeError, match="audit_write_failed"):
        evidence_route.ingest_evidence(request_data(), principal(), session)

    assert session.record.id == EVIDENCE_ID
    assert session.calls == ["add", "flush", "audit", "rollback"]


def test_evidence_request_cannot_select_another_tenant():
    data = request_data().model_dump()
    data["tenant_id"] = str(UUID("00000000-0000-0000-0000-000000000099"))

    with pytest.raises(ValidationError):
        EvidenceCreate.model_validate(data)
