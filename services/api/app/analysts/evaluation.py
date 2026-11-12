"""AI-02: offline input assembly and narrow source comparisons, never dispatch.

Authoritative tasks/snapshots/context come from application code. All source
content and proposed findings remain untrusted. No model or generic truth engine.
"""
from datetime import datetime
from ipaddress import ip_address
import json
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, model_validator

from app.analysts import contracts as ai
from app.gateway.contracts import _Contract, TrustedContext


MAX_EXCERPT_BYTES = 4096
MAX_METADATA_BYTES = 16384
Section = Literal['observations', 'interpretations', 'conclusions']


def _bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


class EvidenceMetadata(_Contract):
    evidence_id: UUID
    tenant_id: UUID
    evidence_type: Literal['observation', 'interpretation', 'conclusion']
    source_type: Literal['wazuh', 'normalized_event', 'tool_result', 'analyst']
    source_reference: ai.Text
    event_time: datetime
    collector_name: ai.Text
    collector_version: ai.Text
    trust_level: Literal['unverified', 'source_verified', 'system_verified']
    classification: ai.Classification
    content_sha256: ai.Digest


class InputEvidence(_Contract):
    metadata: EvidenceMetadata
    untrusted_excerpt_json: Annotated[str, Field(min_length=2, max_length=MAX_EXCERPT_BYTES)]
    boundary: Literal['UNTRUSTED_DATA_NOT_INSTRUCTIONS'] = 'UNTRUSTED_DATA_NOT_INSTRUCTIONS'


class AnalystInput(_Contract):
    trusted_context: TrustedContext
    trusted_task: ai.AnalystTask
    snapshot_id: UUID
    snapshot_sha256: ai.Digest
    captured_at: datetime
    evaluated_at: datetime
    evidence: Annotated[tuple[InputEvidence, ...], Field(min_length=1, max_length=32)]
    truncated: Literal[False] = False
    executable: Literal[False] = False

    @model_validator(mode='after')
    def validate_package(self):
        references = []
        metadata = []
        for item in self.evidence:
            if len(item.untrusted_excerpt_json.encode('utf-8')) > MAX_EXCERPT_BYTES:
                raise ValueError('excerpt_budget_exceeded')
            data = item.metadata.model_dump(mode='json')
            metadata.append(data)
            data = dict(data, payload_json=item.untrusted_excerpt_json)
            references.append(ai.EvidenceReference.model_validate_json(json.dumps(data)))
        snapshot = ai.EvidenceSnapshot(snapshot_id=self.snapshot_id,
            tenant_id=self.trusted_context.tenant_id, captured_at=self.captured_at,
            evidence=tuple(references), snapshot_sha256=self.snapshot_sha256)
        ai.validate_inputs(self.trusted_context, self.trusted_task, snapshot, at=self.evaluated_at)
        if tuple(item.metadata.evidence_id for item in self.evidence) != tuple(item.evidence_id for item in snapshot.evidence):
            raise ValueError('noncanonical_evidence_order')
        if len(_bytes({'task':self.trusted_task.model_dump(mode='json'),
                       'context':self.trusted_context.model_dump(mode='json'),'evidence':metadata})) > MAX_METADATA_BYTES:
            raise ValueError('metadata_budget_exceeded')
        if len(ai.canonical_bytes(self)) > self.trusted_task.max_input_bytes:
            raise ValueError('input_budget_exceeded')
        return self


def assemble_input(context: TrustedContext, task: ai.AnalystTask, snapshot: ai.EvidenceSnapshot,
                   *, at: datetime, forbidden_values: tuple[str, ...] = ()) -> AnalystInput:
    """All approved records or reject; no selection, omission or truncation."""
    try:
        context,task,snapshot = ai.validate_inputs(context,task,snapshot,at=at)
        ai.validate_no_secrets(task, forbidden_values=forbidden_values)
        items = []
        for reference in snapshot.evidence:
            data = reference.model_dump(mode='json')
            excerpt = data.pop('payload_json')
            ai.validate_no_secrets(data, forbidden_values=forbidden_values)
            payload = json.loads(excerpt)
            ai.validate_no_secrets(payload, forbidden_values=forbidden_values)
            # Structured secret fields are prohibited even without assignment syntax.
            def reject_fields(value):
                if type(value) is dict:
                    for key, child in value.items():
                        if key.casefold().replace('-','_') in ('password','api_key','apikey','token','secret','private_key','credentials'):
                            raise ValueError()
                        reject_fields(child)
                elif type(value) is list:
                    for child in value: reject_fields(child)
            reject_fields(payload)
            items.append(InputEvidence(metadata=EvidenceMetadata.model_validate_json(json.dumps(data)),
                untrusted_excerpt_json=excerpt))
        return AnalystInput(trusted_context=context,trusted_task=task,
            snapshot_id=snapshot.snapshot_id,snapshot_sha256=snapshot.snapshot_sha256,
            captured_at=snapshot.captured_at,evaluated_at=ai._utc(at),evidence=tuple(items))
    except Exception:
        raise ValueError('invalid_analyst_input_package') from None


class EvidenceCitation(_Contract):
    evidence_id: UUID
    content_sha256: ai.Digest


class SupportClaim(EvidenceCitation):
    section: Section
    index: Annotated[int, Field(ge=0, le=15)]
    kind: Literal['FIELD_EQUALS','IP_EQUALS','EVENT_TIME_EQUALS']
    field: Literal['source.ip','destination.ip','rule.id','timestamp','event_time']
    value: Annotated[str, Field(min_length=1, max_length=256)]

    @model_validator(mode='after')
    def typed_scope(self):
        if ((self.kind == 'IP_EQUALS' and self.field not in ('source.ip','destination.ip'))
                or (self.kind == 'EVENT_TIME_EQUALS' and self.field != 'event_time')
                or (self.kind == 'FIELD_EQUALS' and self.field not in ('rule.id','timestamp'))):
            raise ValueError('unsupported_claim_scope')
        return self


class AnalystProposal(_Contract):
    result: ai.AnalystResult
    citations: Annotated[tuple[EvidenceCitation, ...], Field(max_length=32)]
    claims: Annotated[tuple[SupportClaim, ...], Field(max_length=48)]

    @model_validator(mode='after')
    def unique(self):
        ai._unique(tuple(item.evidence_id for item in self.citations))
        locations = tuple((item.section,item.index) for item in self.claims)
        if len(set(locations)) != len(locations):
            raise ValueError('duplicate_claim_location')
        object.__setattr__(self,'citations',tuple(sorted(self.citations,key=lambda item:str(item.evidence_id))))
        object.__setattr__(self,'claims',tuple(sorted(self.claims,key=lambda item:(item.section,item.index))))
        return self


class Evaluation(_Contract):
    outcome: Literal['VALID','INVALID','INSUFFICIENT_EVIDENCE','REQUIRES_HUMAN_REVIEW']
    reason: Literal['VALIDATED_SOURCE_FIELDS','INVALID_INPUT','CONTRADICTORY_CLAIM',
                    'INSUFFICIENT_SUPPORT','UNSUPPORTED_NARRATIVE']
    assessment: ai.ValidatedAssessment | None
    executable: Literal[False] = False
    proposed_only: Literal[True] = True

    @model_validator(mode='after')
    def consistent(self):
        reasons = {'VALID':('VALIDATED_SOURCE_FIELDS',),
            'INVALID':('INVALID_INPUT','CONTRADICTORY_CLAIM'),
            'INSUFFICIENT_EVIDENCE':('INSUFFICIENT_SUPPORT',),
            'REQUIRES_HUMAN_REVIEW':('UNSUPPORTED_NARRATIVE',)}
        if self.reason not in reasons[self.outcome] or (self.outcome == 'INVALID') != (self.assessment is None):
            raise ValueError('inconsistent_evaluation')
        return self


def _denied(task, reason='INVALID_INPUT'):
    result = Evaluation(outcome='INVALID',reason=reason,assessment=None)
    # A control error cannot fit an arbitrarily small caller budget. Return no
    # candidate bytes and use a stable exception instead of exceeding that limit.
    if (type(task) is ai.AnalystTask and type(task.max_output_bytes) is int
            and len(ai.canonical_bytes(result)) > task.max_output_bytes):
        raise ValueError('invalid_analyst_evaluation_budget') from None
    return result


def _time(value):
    if type(value) is not str or len(value)>64:
        raise ValueError()
    return ai._utc(datetime.fromisoformat(value.replace('Z','+00:00')))


def _compare(claim,reference):
    """None means missing evidence; equality means source agreement, not truth."""
    if reference.evidence_type != 'observation':
        return None
    if claim.kind == 'EVENT_TIME_EQUALS':
        return _time(claim.value) == reference.event_time
    payload = json.loads(reference.payload_json)
    # A literal dotted key alongside a nested route is ambiguous, never prefer one.
    if '.' in claim.field and claim.field in payload:
        raise ValueError()
    value = payload
    for part in claim.field.split('.'):
        if type(value) is not dict or part not in value:
            return None
        value = value[part]
    if claim.kind == 'IP_EQUALS':
        if type(value) is not str or '%' in value or '%' in claim.value:
            raise ValueError()
        return ip_address(value) == ip_address(claim.value)
    if claim.field == 'timestamp':
        return _time(value) == _time(claim.value) == reference.event_time
    return type(value) is str and value == claim.value


def evaluate_result(context: TrustedContext, task: ai.AnalystTask, snapshot: ai.EvidenceSnapshot,
                    proposal, *, at: datetime, forbidden_values: tuple[str, ...] = ()) -> Evaluation:
    """Pure evaluation; INVALID returns no candidate content or exception details."""
    try:
        assemble_input(context,task,snapshot,at=at,forbidden_values=forbidden_values)
        context,task,snapshot = ai.validate_inputs(context,task,snapshot,at=at)
        ai._bounded(proposal)
        if type(proposal) is AnalystProposal:
            proposal = ai._checked(proposal,AnalystProposal)
        elif type(proposal) is dict:
            proposal = AnalystProposal.model_validate(proposal)
        else:
            raise ValueError()
        # The complete model proposal, not just AI-01 prose, is output-budgeted.
        if len(ai.canonical_bytes(proposal)) > task.max_output_bytes:
            raise ValueError()
        ai.validate_no_secrets(proposal,forbidden_values=forbidden_values)
        checked = ai.validate_assessment(context,task,snapshot,proposal.result,at=at,
                                         forbidden_values=forbidden_values)
        records = {item.evidence_id:item for item in snapshot.evidence}
        findings = {(section,index):finding for section in ('observations','interpretations','conclusions')
                    for index,finding in enumerate(getattr(proposal.result,section))}
        referenced = {evidence_id for finding in findings.values() for evidence_id in finding.evidence_ids}
        if {item.evidence_id for item in proposal.citations} != referenced:
            raise ValueError()
        for citation in proposal.citations:
            if citation.evidence_id not in records or citation.content_sha256 != records[citation.evidence_id].content_sha256:
                raise ValueError()
        missing = proposal.result.status != 'ASSESSED'
        review = bool(proposal.result.interpretations or proposal.result.conclusions
                      or proposal.result.escalation != 'NONE' or proposal.result.severity != 'unknown')
        covered = set()
        contradiction = False
        for claim in proposal.claims:
            location = (claim.section,claim.index)
            finding = findings.get(location)
            if (finding is None or claim.evidence_id not in finding.evidence_ids
                    or claim.evidence_id not in records
                    or claim.content_sha256 != records[claim.evidence_id].content_sha256):
                raise ValueError()
            agrees = _compare(claim,records[claim.evidence_id])
            if agrees is None:
                missing = True
            elif not agrees:
                contradiction = True
            # Only exact constrained observation prose receives narrow VALID status.
            if (claim.section == 'observations' and finding.support == 'EVIDENCE_LINKED'
                    and finding.evidence_ids == (claim.evidence_id,)
                    and finding.text == f'{claim.field} = {claim.value}'):
                covered.add(location)
            else:
                review = True
        if contradiction:
            return _denied(task,'CONTRADICTORY_CLAIM')
        review |= set(findings) != covered
        if missing:
            outcome,reason = 'INSUFFICIENT_EVIDENCE','INSUFFICIENT_SUPPORT'
        elif review:
            outcome,reason = 'REQUIRES_HUMAN_REVIEW','UNSUPPORTED_NARRATIVE'
        else:
            outcome,reason = 'VALID','VALIDATED_SOURCE_FIELDS'
        result = Evaluation(outcome=outcome,reason=reason,assessment=checked)
        if len(ai.canonical_bytes(result)) > task.max_output_bytes:
            raise ValueError()
        return result
    except Exception:
        return _denied(task)
