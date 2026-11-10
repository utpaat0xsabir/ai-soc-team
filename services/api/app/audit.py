
import hashlib
import hmac
import json
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditLog, Tenant


GENESIS_HASH = "0" * 64


def calculate_audit_hash(
    *,
    tenant_id: UUID,
    sequence_number: int,
    previous_hash: str,
    actor_type: str,
    actor_id: UUID | None,
    action: str,
    resource_type: str,
    resource_id: UUID | None,
    details: dict,
    created_at: datetime,
) -> str:
    """Calculate a deterministic SHA-256 hash for an audit event."""

    if created_at.tzinfo is None or created_at.utcoffset() is None:
        raise ValueError("audit_created_at_must_be_timezone_aware")

    canonical_data = {
        "tenant_id": str(tenant_id),
        "sequence_number": sequence_number,
        "previous_hash": previous_hash,
        "actor_type": actor_type,
        "actor_id": str(actor_id) if actor_id else None,
        "action": action,
        "resource_type": resource_type,
        "resource_id": str(resource_id) if resource_id else None,
        "details": details,
        "created_at": created_at.astimezone(timezone.utc).isoformat(),
    }

    serialized = json.dumps(
        canonical_data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    return hashlib.sha256(serialized).hexdigest()


def verify_audit_chain(events: list[AuditLog]) -> dict:
    """Verify sequence continuity, hash links, and event hashes."""

    previous_hash = GENESIS_HASH
    checked = 0

    for expected_sequence, event in enumerate(events, start=1):
        if event.sequence_number != expected_sequence:
            return {
                "valid": False,
                "total": len(events),
                "checked": checked,
                "first_invalid_sequence": event.sequence_number,
                "failure_reason": "sequence_mismatch",
            }

        if not hmac.compare_digest(
            event.previous_hash or "",
            previous_hash,
        ):
            return {
                "valid": False,
                "total": len(events),
                "checked": checked,
                "first_invalid_sequence": event.sequence_number,
                "failure_reason": "previous_hash_mismatch",
            }

        calculated_hash = calculate_audit_hash(
            tenant_id=event.tenant_id,
            sequence_number=event.sequence_number,
            previous_hash=event.previous_hash,
            actor_type=event.actor_type,
            actor_id=event.actor_id,
            action=event.action,
            resource_type=event.resource_type,
            resource_id=event.resource_id,
            details=event.details,
            created_at=event.created_at,
        )

        if not hmac.compare_digest(
            event.entry_hash,
            calculated_hash,
        ):
            return {
                "valid": False,
                "total": len(events),
                "checked": checked,
                "first_invalid_sequence": event.sequence_number,
                "failure_reason": "entry_hash_mismatch",
            }

        previous_hash = event.entry_hash
        checked += 1

    return {
        "valid": True,
        "total": len(events),
        "checked": checked,
        "first_invalid_sequence": None,
        "failure_reason": None,
    }


def record_audit_event(
    db: Session,
    *,
    tenant_id: UUID,
    actor_type: str,
    actor_id: UUID | None,
    action: str,
    resource_type: str,
    resource_id: UUID | None = None,
    details: dict | None = None,
) -> AuditLog:
    """Add a hash-chained audit event to the current transaction."""

    tenant = db.scalar(
        select(Tenant)
        .where(Tenant.id == tenant_id)
        # PostgreSQL FOR NO KEY UPDATE serializes audit writers while allowing
        # evidence FK KEY SHARE locks; FOR UPDATE can deadlock on that upgrade.
        .with_for_update(key_share=True)
    )

    if tenant is None:
        raise ValueError("audit_tenant_not_found")

    previous_event = db.scalar(
        select(AuditLog)
        .where(AuditLog.tenant_id == tenant_id)
        .order_by(AuditLog.sequence_number.desc())
        .limit(1)
    )

    sequence_number = (
        previous_event.sequence_number + 1
        if previous_event is not None
        else 1
    )

    previous_hash = (
        previous_event.entry_hash
        if previous_event is not None
        else GENESIS_HASH
    )

    event_details = details if details is not None else {}
    created_at = datetime.now(timezone.utc)

    entry_hash = calculate_audit_hash(
        tenant_id=tenant_id,
        sequence_number=sequence_number,
        previous_hash=previous_hash,
        actor_type=actor_type,
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=event_details,
        created_at=created_at,
    )

    event = AuditLog(
        tenant_id=tenant_id,
        sequence_number=sequence_number,
        previous_hash=previous_hash,
        entry_hash=entry_hash,
        actor_type=actor_type,
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=event_details,
        created_at=created_at,
    )

    db.add(event)
    db.flush()

    return event
