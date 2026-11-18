"""Offline stored-evidence policy evaluation. Results cannot authorize inference."""

from enum import Enum
import hmac
import json
from typing import Annotated
from uuid import UUID

from pydantic import Field, ValidationError

from app.analysts import contracts
from app.analysts.evidence_adapter import (
    EvidenceRejected,
    VerifiedStoredEvidence,
    _checked_context,
    validate_stored_evidence,
)
from app.gateway.contracts import TrustedContext, _Contract


_Label = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")]


class ClassificationDecision(_Contract):
    """A claim whose issuance must be confirmed against trusted policy state."""

    tenant_id: UUID
    evidence_id: UUID
    content_sha256: contracts.Digest
    classification: contracts.Classification
    authority: _Label
    policy_version: _Label


class AdmissionPolicy(_Contract):
    """Application-owned configuration for one tenant and principal.

    Only trusted composition code supplies the allowlist and issued decisions.
    There is no default authority or production issuance source.
    """

    context: TrustedContext
    policy_version: _Label
    trusted_authorities: tuple[_Label, ...] = ()
    issued_decisions: tuple[ClassificationDecision, ...] = ()


class AdmissionResult(Enum):
    POLICY_MATCH = "POLICY_MATCH"
    INVALID_INPUT = "INVALID_INPUT"
    INVALID_CONTEXT = "INVALID_CONTEXT"
    INVALID_EVIDENCE = "INVALID_EVIDENCE"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    DIGEST_MISMATCH = "DIGEST_MISMATCH"
    UNSUPPORTED_TIER = "UNSUPPORTED_TIER"
    UNSUPPORTED_POLICY_VERSION = "UNSUPPORTED_POLICY_VERSION"
    UNSUPPORTED_CLASSIFICATION = "UNSUPPORTED_CLASSIFICATION"
    UNTRUSTED_AUTHORITY = "UNTRUSTED_AUTHORITY"
    UNCONFIRMED_ISSUANCE = "UNCONFIRMED_ISSUANCE"
    INSUFFICIENT_TRUST = "INSUFFICIENT_TRUST"


def evaluate_admission(
    *,
    evidence: VerifiedStoredEvidence,
    decision: ClassificationDecision,
    tier: contracts.Tier,
    context: TrustedContext,
    policy: AdmissionPolicy,
) -> AdmissionResult:
    """Evaluate an L1 policy match only. Never build an evidence reference."""
    if type(policy) is not AdmissionPolicy or type(decision) is not ClassificationDecision:
        return AdmissionResult.INVALID_INPUT
    try:
        policy = AdmissionPolicy.model_validate(policy)
        decision = ClassificationDecision.model_validate(decision)
    except ValidationError:
        return AdmissionResult.INVALID_INPUT
    try:
        context = _checked_context(context)
        policy_context = _checked_context(policy.context)
    except EvidenceRejected:
        return AdmissionResult.INVALID_CONTEXT

    if type(tier) is not str or tier != "L1":
        return AdmissionResult.UNSUPPORTED_TIER
    if policy.policy_version != "1" or decision.policy_version != policy.policy_version:
        return AdmissionResult.UNSUPPORTED_POLICY_VERSION
    if decision.classification != "OBSERVED":
        return AdmissionResult.UNSUPPORTED_CLASSIFICATION
    if type(evidence) is not VerifiedStoredEvidence:
        return AdmissionResult.INVALID_EVIDENCE
    try:
        evidence = VerifiedStoredEvidence.model_validate(evidence)
        if (evidence.evidence_type != "observation" or evidence.event_time is None
                or evidence.event_time > evidence.collected_at
                or len(evidence.payload_json) > contracts.MAX_INPUT_BYTES):
            return AdmissionResult.INVALID_EVIDENCE
        row = evidence.model_dump()
        row["payload"] = json.loads(row.pop("payload_json"))
        if validate_stored_evidence(row).payload_json != evidence.payload_json:
            return AdmissionResult.INVALID_EVIDENCE
    except (ValueError, RecursionError):
        return AdmissionResult.INVALID_EVIDENCE

    if (context != policy_context or context.tenant_id != evidence.tenant_id
            or decision.tenant_id != evidence.tenant_id or decision.evidence_id != evidence.evidence_id):
        return AdmissionResult.SCOPE_MISMATCH
    if not hmac.compare_digest(decision.content_sha256, evidence.content_sha256):
        return AdmissionResult.DIGEST_MISMATCH
    if decision.authority not in policy.trusted_authorities:
        return AdmissionResult.UNTRUSTED_AUTHORITY
    if decision not in policy.issued_decisions:
        return AdmissionResult.UNCONFIRMED_ISSUANCE
    if evidence.trust_level != "system_verified":
        return AdmissionResult.INSUFFICIENT_TRUST
    return AdmissionResult.POLICY_MATCH
