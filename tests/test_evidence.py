from datetime import datetime, timezone

import pytest

from app.evidence import calculate_evidence_hash


def sample_evidence(**overrides):
    data = {
        "evidence_type": "observation",
        "source_type": "wazuh",
        "source_reference": "agent-001/alert-123",
        "collector_name": "wazuh-ingestion",
        "collector_version": "0.1.0",
        "trust_level": "source_verified",
        "payload": {
            "rule_id": "752",
            "description": "Example security event",
        },
        "event_time": datetime(
            2026, 11, 9, 8, 0, tzinfo=timezone.utc
        ),
    }

    data.update(overrides)
    return data


def test_same_evidence_produces_same_hash():
    first = calculate_evidence_hash(**sample_evidence())
    second = calculate_evidence_hash(**sample_evidence())

    assert first == second
    assert len(first) == 64


def test_payload_change_changes_hash():
    first = calculate_evidence_hash(**sample_evidence())

    changed = sample_evidence(
        payload={"rule_id": "750", "description": "Different event"}
    )

    second = calculate_evidence_hash(**changed)

    assert first != second


def test_source_change_changes_hash():
    first = calculate_evidence_hash(**sample_evidence())

    second = calculate_evidence_hash(
        **sample_evidence(source_reference="different-source")
    )

    assert first != second


def test_invalid_evidence_type_rejected():
    with pytest.raises(ValueError):
        calculate_evidence_hash(
            **sample_evidence(evidence_type="invented_observation")
        )


def test_naive_event_timestamp_rejected():
    with pytest.raises(ValueError):
        calculate_evidence_hash(
            **sample_evidence(event_time=datetime(2026, 11, 9, 8, 0))
        )


def test_non_json_payload_rejected():
    with pytest.raises(ValueError):
        calculate_evidence_hash(
            **sample_evidence(payload={"invalid": object()})
        )
