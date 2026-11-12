"""AI-01: pure analyst proposals, never identity, evidence or execution authority.

Only application code supplies context/task/snapshot and known-secret exclusions.
Models propose AnalystResult only. Hashes establish integrity, not authenticity;
citation membership cannot prove semantic entailment. No inference or I/O occurs.
"""
from datetime import datetime, timezone
import hashlib
import hmac
import json
import re
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from app.evidence.hashing import calculate_evidence_hash
from app.gateway.contracts import _Contract, TrustedContext


Digest = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
Text = Annotated[str, Field(min_length=1, max_length=1024, pattern=r'\S')]
Texts = Annotated[tuple[Text, ...], Field(max_length=16)]
IDs = Annotated[tuple[UUID, ...], Field(max_length=32)]
Tier = Literal['L1', 'L2', 'L3']
Classification = Literal['SYNTHETIC / TEST ONLY', 'OBSERVED']
MAX_INPUT_BYTES = 65536
MAX_OUTPUT_BYTES = 16384


def _utc(value):
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError('invalid_analyst_time')
    return value.astimezone(timezone.utc)


def _bounded(value):
    """Bound raw input before model reconstruction/serialization; reject cycles."""
    nodes, budget = 0, 262144
    def visit(item, depth):
        nonlocal nodes, budget
        nodes += 1
        if depth > 16 or nodes > 4096 or budget < 0:
            raise ValueError('invalid_analyst_input')
        if isinstance(item, _Contract):
            if item.model_extra:
                raise ValueError('invalid_analyst_input')
            visit(item.__dict__, depth + 1)
        elif type(item) is dict:
            if len(item) > 64:
                raise ValueError('invalid_analyst_input')
            for key, child in item.items():
                if type(key) is not str:
                    raise ValueError('invalid_analyst_input')
                visit(key, depth + 1); visit(child, depth + 1)
        elif type(item) in (list, tuple):
            if len(item) > 64:
                raise ValueError('invalid_analyst_input')
            for child in item:
                visit(child, depth + 1)
        elif type(item) is str:
            if len(item) > MAX_INPUT_BYTES:
                raise ValueError('invalid_analyst_input')
            budget -= len(item.encode('utf-8')) * 6 + 2
        elif type(item) is int:
            if item.bit_length() > 64:
                raise ValueError('invalid_analyst_input')
            budget -= 64
        elif type(item) in (UUID, datetime, float, bool) or item is None:
            budget -= 64
        else:
            raise ValueError('invalid_analyst_input')
    visit(value, 0)
    if budget < 0:
        raise ValueError('invalid_analyst_input')


def canonical_bytes(model):
    _bounded(model)
    return json.dumps(model.model_dump(mode='json'), sort_keys=True,
                      separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def _digest(model):
    return hashlib.sha256(canonical_bytes(model)).hexdigest()


def _unique(values):
    if len(set(values)) != len(values):
        raise ValueError('duplicate_analyst_reference')
    return tuple(sorted(values, key=str))


def _pairs(values):
    if len(dict(values)) != len(values):
        raise ValueError('duplicate_payload_key')
    return dict(values)


def _invalid_constant(_):
    raise ValueError('invalid_payload_constant')


class EvidenceReference(_Contract):
    evidence_id: UUID
    tenant_id: UUID
    evidence_type: Literal['observation', 'interpretation', 'conclusion']
    source_type: Literal['wazuh', 'normalized_event', 'tool_result', 'analyst']
    source_reference: Text
    event_time: datetime
    collector_name: Text
    collector_version: Text
    trust_level: Literal['unverified', 'source_verified', 'system_verified']
    classification: Classification
    payload_json: Annotated[str, Field(min_length=2, max_length=8192)]
    content_sha256: Digest

    _time = field_validator('event_time')(_utc)

    @model_validator(mode='after')
    def integrity(self):
        try:
            payload = json.loads(self.payload_json, object_pairs_hook=_pairs,
                                 parse_constant=_invalid_constant)
            if type(payload) is not dict:
                raise ValueError()
            _bounded(payload)
            expected = calculate_evidence_hash(evidence_type=self.evidence_type,
                source_type=self.source_type, source_reference=self.source_reference,
                collector_name=self.collector_name, collector_version=self.collector_version,
                trust_level=self.trust_level, event_time=self.event_time, payload=payload)
            if not hmac.compare_digest(self.content_sha256, expected):
                raise ValueError()
            object.__setattr__(self, 'payload_json', json.dumps(payload, sort_keys=True,
                separators=(',', ':'), ensure_ascii=True, allow_nan=False))
        except Exception:
            raise ValueError('invalid_analyst_evidence') from None
        return self


class EvidenceSnapshot(_Contract):
    snapshot_id: UUID
    tenant_id: UUID
    captured_at: datetime
    evidence: Annotated[tuple[EvidenceReference, ...], Field(min_length=1, max_length=32)]
    snapshot_sha256: Digest

    _time = field_validator('captured_at')(_utc)

    @model_validator(mode='after')
    def integrity(self):
        _unique(tuple(item.evidence_id for item in self.evidence))
        ordered = tuple(sorted(self.evidence, key=lambda item: str(item.evidence_id)))
        object.__setattr__(self, 'evidence', ordered)
        if any(item.tenant_id != self.tenant_id or item.event_time > self.captured_at for item in ordered):
            raise ValueError('invalid_snapshot_scope')
        data = self.model_dump(mode='json'); data.pop('snapshot_sha256')
        expected = hashlib.sha256(json.dumps(data, sort_keys=True, separators=(',', ':'),
            ensure_ascii=True, allow_nan=False).encode('ascii')).hexdigest()
        if not hmac.compare_digest(expected, self.snapshot_sha256) or len(canonical_bytes(self)) > MAX_INPUT_BYTES:
            raise ValueError('invalid_snapshot_integrity')
        return self


def _checked(value, contract):
    _bounded(value)
    if type(value) is not contract:
        raise ValueError('invalid_trusted_contract')
    return contract.model_validate_json(canonical_bytes(value))


def build_snapshot(context: TrustedContext, *, snapshot_id: UUID, captured_at: datetime,
                   evidence: tuple[EvidenceReference, ...]) -> EvidenceSnapshot:
    """Trusted application snapshot builder; not a model-facing authority source."""
    context = _checked(context, TrustedContext)
    _bounded(evidence)
    if type(evidence) is not tuple or not 1 <= len(evidence) <= 32:
        raise ValueError('invalid_snapshot_scope')
    items = tuple(sorted((_checked(item, EvidenceReference) for item in evidence), key=lambda item: str(item.evidence_id)))
    draft = EvidenceSnapshot.model_construct(snapshot_id=snapshot_id, tenant_id=context.tenant_id,
        captured_at=_utc(captured_at), evidence=items, snapshot_sha256='0'*64)
    data = draft.model_dump(mode='json'); data.pop('snapshot_sha256')
    data['snapshot_sha256'] = hashlib.sha256(json.dumps(data, sort_keys=True,
        separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')).hexdigest()
    return EvidenceSnapshot.model_validate_json(json.dumps(data))


class AnalystTask(_Contract):
    task_id: UUID
    tenant_id: UUID
    principal_id: UUID
    tier: Tier
    task_type: Literal['triage', 'investigation', 'hunt']
    objective: Text
    original_evidence_ids: Annotated[IDs, Field(min_length=1)]
    snapshot_id: UUID
    snapshot_sha256: Digest
    policy_reference: Annotated[str, Field(pattern=r'^[a-z][a-z0-9_.:-]{0,95}$')]
    created_at: datetime
    deadline: datetime
    max_input_bytes: Annotated[int, Field(ge=1, le=MAX_INPUT_BYTES)]
    max_output_bytes: Annotated[int, Field(ge=1, le=MAX_OUTPUT_BYTES)]
    classification: Classification

    _times = field_validator('created_at', 'deadline')(_utc)
    _ids = field_validator('original_evidence_ids')(_unique)

    @model_validator(mode='after')
    def scope(self):
        if (self.task_type != {'L1':'triage', 'L2':'investigation', 'L3':'hunt'}[self.tier]
                or not 0 < (self.deadline-self.created_at).total_seconds() <= 86400):
            raise ValueError('invalid_analyst_task')
        return self


class AnalystFinding(_Contract):
    text: Text
    evidence_ids: IDs
    support: Literal['EVIDENCE_LINKED', 'HYPOTHESIS']

    _ids = field_validator('evidence_ids')(_unique)

    @model_validator(mode='after')
    def citations(self):
        if self.support == 'EVIDENCE_LINKED' and not self.evidence_ids:
            raise ValueError('missing_finding_support')
        return self


Findings = Annotated[tuple[AnalystFinding, ...], Field(max_length=16)]


class AnalystResult(_Contract):
    """Untrusted candidate; construction is not assessment acceptance."""
    task_id: UUID
    tier: Tier
    status: Literal['ASSESSED', 'INSUFFICIENT', 'ABSTAINED']
    observations: Findings
    interpretations: Findings
    conclusions: Findings
    severity: Literal['unknown', 'low', 'medium', 'high', 'critical']
    confidence: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
    uncertainty: Annotated[Texts, Field(min_length=1)]
    missing_information: Texts
    limitations: Annotated[Texts, Field(min_length=1)]
    next_steps: Texts
    escalation: Literal['NONE', 'L2', 'L3', 'HUMAN']
    classification: Classification

    @model_validator(mode='after')
    def consistency(self):
        findings = self.observations + self.interpretations + self.conclusions
        if any(item.support != 'EVIDENCE_LINKED' for item in self.observations):
            raise ValueError('unsupported_observation')
        if self.status == 'ASSESSED' and not any(item.support == 'EVIDENCE_LINKED' for item in findings):
            raise ValueError('missing_assessment_support')
        if self.status != 'ASSESSED' and (self.confidence != 0 or self.severity != 'unknown'):
            raise ValueError('contradictory_abstention')
        if any(not item.evidence_ids for item in findings) and self.confidence != 0:
            raise ValueError('unsupported_confidence')
        if self.escalation not in ('NONE','HUMAN',{'L1':'L2','L2':'L3','L3':'HUMAN'}[self.tier]):
            raise ValueError('invalid_escalation')
        return self


class ValidatedAssessment(_Contract):
    task_sha256: Digest
    snapshot_sha256: Digest
    assessment: AnalystResult
    proposed_only: Literal[True] = True
    executable: Literal[False] = False


def validate_inputs(context: TrustedContext, task: AnalystTask, snapshot: EvidenceSnapshot,
                    *, at: datetime) -> tuple[TrustedContext, AnalystTask, EvidenceSnapshot]:
    """Pure trusted application boundary shared by AI-01 and AI-02."""
    context = _checked(context, TrustedContext)
    task = _checked(task, AnalystTask)
    snapshot = _checked(snapshot, EvidenceSnapshot)
    at = _utc(at)
    if (context.tenant_id != task.tenant_id or context.principal_id != task.principal_id
            or snapshot.tenant_id != context.tenant_id or snapshot.snapshot_id != task.snapshot_id
            or snapshot.snapshot_sha256 != task.snapshot_sha256
            or not snapshot.captured_at <= task.created_at <= at < task.deadline):
        raise ValueError('invalid_analyst_inputs')
    if not set(task.original_evidence_ids) <= {item.evidence_id for item in snapshot.evidence}:
        raise ValueError('invalid_analyst_inputs')
    if any(item.classification != task.classification for item in snapshot.evidence):
        raise ValueError('invalid_analyst_inputs')
    if len(canonical_bytes(task)) + len(canonical_bytes(snapshot)) > task.max_input_bytes:
        raise ValueError('invalid_analyst_inputs')
    return context, task, snapshot


def validate_no_secrets(value, *, forbidden_values: tuple[str, ...] = ()):
    """Reject credential markers and trusted canaries; not general DLP."""
    _bounded(value)
    _bounded(forbidden_values)
    if type(forbidden_values) is not tuple or any(type(item) is not str or not item for item in forbidden_values):
        raise ValueError('invalid_secret_exclusions')
    def visit(item):
        if isinstance(item, _Contract):
            visit(item.model_dump(mode='json'))
        elif type(item) is dict:
            for key, child in item.items():
                visit(key); visit(child)
        elif type(item) in (list, tuple):
            for child in item:
                visit(child)
        elif type(item) is str:
            if any(secret in item for secret in forbidden_values) or re.search(
                    r'(?i)(password|api[_-]?key|token|secret)\s*[:=]|bearer\s+\S+|-----BEGIN .*PRIVATE KEY', item):
                raise ValueError('sensitive_analyst_content')
    visit(value)


def validate_assessment(context: TrustedContext, task: AnalystTask, snapshot: EvidenceSnapshot,
                        candidate, *, at: datetime, forbidden_values: tuple[str, ...] = ()) -> ValidatedAssessment:
    """Application-side boundary. Failure exposes a stable reason, never content.

    Known-secret matching supplements structured-field denial; it is not general
    secret detection. Supply minimized, secret-free evidence before reasoning.
    """
    try:
        context, task, snapshot = validate_inputs(context, task, snapshot, at=at)
        allowed = {item.evidence_id for item in snapshot.evidence}
        _bounded(candidate)
        if type(candidate) is AnalystResult:
            result = _checked(candidate, AnalystResult)
        elif type(candidate) is dict:
            result = AnalystResult.model_validate(candidate)
        else:
            raise ValueError()
        if (result.task_id != task.task_id or result.tier != task.tier
                or result.classification != task.classification):
            raise ValueError()
        for finding in result.observations + result.interpretations + result.conclusions:
            if not set(finding.evidence_ids) <= allowed:
                raise ValueError()
            if finding.support == 'EVIDENCE_LINKED' and all(
                    item.evidence_type != 'observation' for item in snapshot.evidence if item.evidence_id in finding.evidence_ids):
                raise ValueError()
        checked = ValidatedAssessment(task_sha256=_digest(task), snapshot_sha256=snapshot.snapshot_sha256, assessment=result)
        encoded = canonical_bytes(checked)
        if len(encoded) > task.max_output_bytes:
            raise ValueError()
        validate_no_secrets(result, forbidden_values=forbidden_values)
        return checked
    except Exception:
        raise ValueError('invalid_analyst_assessment') from None
