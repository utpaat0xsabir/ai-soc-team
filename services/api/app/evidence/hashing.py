import hashlib
import json
from datetime import datetime, timezone
from typing import Any


ALLOWED_EVIDENCE_TYPES = {
    "observation",
    "interpretation",
    "conclusion",
}

ALLOWED_TRUST_LEVELS = {
    "unverified",
    "source_verified",
    "system_verified",
}


def calculate_evidence_hash(
    *,
    evidence_type: str,
    source_type: str,
    source_reference: str,
    collector_name: str,
    collector_version: str,
    trust_level: str,
    payload: dict[str, Any],
    event_time: datetime | None = None,
) -> str:
    """
    Calculate a deterministic SHA-256 digest for an evidence envelope.

    Collection time and database-generated IDs are deliberately excluded.
    Event time, source metadata, collector metadata and payload are included.
    """

    if evidence_type not in ALLOWED_EVIDENCE_TYPES:
        raise ValueError("Unsupported evidence type")

    if trust_level not in ALLOWED_TRUST_LEVELS:
        raise ValueError("Unsupported trust level")

    if not isinstance(payload, dict):
        raise ValueError("Evidence payload must be a dictionary")

    normalized_event_time = None

    if event_time is not None:
        if event_time.tzinfo is None or event_time.utcoffset() is None:
            raise ValueError("event_time must be timezone-aware")

        normalized_event_time = (
            event_time.astimezone(timezone.utc).isoformat()
        )

    envelope = {
        "evidence_type": evidence_type,
        "source_type": source_type,
        "source_reference": source_reference,
        "collector_name": collector_name,
        "collector_version": collector_version,
        "trust_level": trust_level,
        "event_time": normalized_event_time,
        "payload": payload,
    }

    try:
        canonical = json.dumps(
            envelope,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("Evidence contains non-JSON-compatible data") from exc

    return hashlib.sha256(canonical).hexdigest()
