
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

from app.audit import (
    GENESIS_HASH,
    calculate_audit_hash,
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
