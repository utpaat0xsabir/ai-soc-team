"""Bounded AND-only detection over trusted normalized-event snapshots.

Pure derivation: no storage, clock, rule loading, expression language or I/O.
Tenant context must come from authentication; event/rule objects must originate
from trusted application code. Fingerprints identify inputs, not authenticity.
"""

from datetime import datetime
import hashlib
import json
from typing import Annotated, Literal
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.detection.security_events import EventAgent, EventEndpoint, EventRule, NormalizedSecurityEvent


EventField = Literal[
    'source_system', 'category', 'severity', 'source.ip', 'source.port',
    'destination.ip', 'destination.port', 'agent.id', 'agent.name', 'agent.ip',
    'rule.id', 'rule.level', 'rule.groups',
]
Operator = Literal['eq', 'in', 'gt', 'gte', 'lt', 'lte', 'contains_any']
RuleText = Annotated[str, Field(min_length=1, max_length=256)]
Scalar = RuleText | int
ConditionValue = Scalar | Annotated[tuple[Scalar, ...], Field(min_length=1, max_length=32)]
MatchedGroups = Annotated[tuple[RuleText, ...], Field(min_length=1, max_length=32)]
RuleSchemaVersion = Literal['1.0', '1.1']
NUMERIC_LIMITS = {'severity': 100, 'rule.level': 15, 'source.port': 65535, 'destination.port': 65535}
MAX_RULES = 100
MAX_CONDITIONS = 16
MAX_INPUT_BYTES = 1_048_576
MAX_INPUT_NODES = 20_000
NAMESPACE = UUID('aa94ac7f-1a5e-4480-a851-bd650ae84ba4')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def _fingerprint(model, *, exclude=None):
    return hashlib.sha256(_canonical(model.model_dump(mode='json', exclude=exclude)).encode()).hexdigest()


class _Contract(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra='forbid',
                              hide_input_in_errors=True, revalidate_instances='always')


class DetectionCondition(_Contract):
    field: EventField
    operator: Operator
    value: ConditionValue

    @model_validator(mode='after')
    def validate_comparison(self):
        if (self.field == 'rule.groups') != (self.operator == 'contains_any'):
            raise ValueError('invalid_detection_condition')
        membership = self.operator in ('in', 'contains_any')
        if membership != (type(self.value) is tuple):
            raise ValueError('invalid_detection_condition')
        values = self.value if membership else (self.value,)
        numeric = self.field in NUMERIC_LIMITS
        if not numeric and self.operator not in ('eq', 'in', 'contains_any'):
            raise ValueError('invalid_detection_condition')
        for value in values:
            if numeric:
                if type(value) is not int or not 0 <= value <= NUMERIC_LIMITS[self.field]:
                    raise ValueError('invalid_detection_condition')
            elif type(value) is not str:
                raise ValueError('invalid_detection_condition')
            else:
                value.encode('utf-8')  # Reject invalid Unicode without echoing it.
        if membership:
            if len(set(values)) != len(values):
                raise ValueError('duplicate_detection_members')
            object.__setattr__(self, 'value', tuple(sorted(values)))
        return self


class DetectionRule(_Contract):
    schema_version: RuleSchemaVersion = '1.0'
    rule_id: UUID
    tenant_id: UUID
    version: Annotated[int, Field(ge=1, le=2 ** 31 - 1)]
    name: Annotated[str, Field(min_length=1, max_length=128)]
    conditions: Annotated[tuple[DetectionCondition, ...], Field(min_length=1, max_length=MAX_CONDITIONS)]

    @field_validator('name')
    @classmethod
    def validate_name(cls, value):
        if not value.strip():
            raise ValueError('invalid_detection_rule_name')
        value.encode('utf-8')
        return value

    @field_validator('conditions')
    @classmethod
    def canonical_conditions(cls, conditions):
        if len(set(conditions)) != len(conditions):
            raise ValueError('duplicate_detection_conditions')
        return tuple(sorted(conditions, key=lambda item: _canonical(item.model_dump(mode='json'))))

    @model_validator(mode='after')
    def validate_schema_features(self):
        if self.schema_version == '1.0' and any(
                condition.field == 'rule.groups' for condition in self.conditions):
            raise ValueError('detection_condition_requires_schema_1_1')
        return self


class MatchedCondition(_Contract):
    field: EventField
    operator: Operator
    expected: ConditionValue
    # contains_any records only the sorted distinct intersection, not the entire
    # observed array (which may have 100 strings of up to 4096 characters).
    actual: Scalar | MatchedGroups

    @model_validator(mode='after')
    def validate_group_trace(self):
        if self.field != 'rule.groups':
            if self.operator == 'contains_any' or type(self.actual) is tuple:
                raise ValueError('invalid_detection_group_trace')
            return self
        condition = DetectionCondition(field=self.field, operator=self.operator, value=self.expected)
        if (type(self.actual) is not tuple
                or tuple(sorted(set(self.actual))) != self.actual
                or any(value not in condition.value for value in self.actual)):
            raise ValueError('invalid_detection_group_trace')
        return self


class DetectionMatch(_Contract):
    schema_version: RuleSchemaVersion = '1.0'
    # Semantic evaluation profile, not a binary/build version. V1 rules retain
    # their original profile, serialization and identities in the newer engine.
    engine_version: RuleSchemaVersion = '1.0'
    match_id: UUID
    tenant_id: UUID
    event_id: UUID
    event_fingerprint: Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
    evidence_id: UUID
    evidence_sha256: Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
    source_reference: Annotated[str, Field(min_length=1, max_length=500)]
    rule_id: UUID
    rule_version: Annotated[int, Field(ge=1, le=2 ** 31 - 1)]
    rule_fingerprint: Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
    matched_conditions: Annotated[tuple[MatchedCondition, ...], Field(min_length=1, max_length=MAX_CONDITIONS)]

    @model_validator(mode='after')
    def validate_schema_features(self):
        if self.schema_version != self.engine_version or (
                self.schema_version == '1.0' and any(
                    condition.field == 'rule.groups' for condition in self.matched_conditions)):
            raise ValueError('invalid_detection_match_schema')
        return self


def _bounded_snapshots(event, rules):
    """Copy only known data types, within a shared conservative UTF-8 budget.

    Reconstruct before validation to reject even model_construct/model_copy
    bypasses. No arbitrary object serialization, properties or iterators.
    """
    nodes = 0
    budget = MAX_INPUT_BYTES
    models = (NormalizedSecurityEvent, EventAgent, EventEndpoint, EventRule, DetectionRule, DetectionCondition)

    def plain(value, depth=0):
        nonlocal nodes, budget
        nodes += 1
        budget -= 32
        if nodes > MAX_INPUT_NODES or depth > 12 or budget < 0:
            raise ValueError('invalid_detection_input')
        kind = type(value)
        if kind in models:
            return plain(value.__dict__, depth + 1)
        if kind is dict:
            if len(value) > MAX_INPUT_NODES:
                raise ValueError('invalid_detection_input')
            result = {}
            for key, item in value.items():
                if type(key) is not str:
                    raise ValueError('invalid_detection_input')
                result[plain(key, depth + 1)] = plain(item, depth + 1)
            return result
        if kind in (tuple, list):
            if len(value) > MAX_INPUT_NODES:
                raise ValueError('invalid_detection_input')
            result = [plain(item, depth + 1) for item in value]
            return tuple(result) if kind is tuple else result
        if kind is str:
            if len(value) > 4096:
                raise ValueError('invalid_detection_input')
            budget -= len(value.encode('utf-8'))
            if budget < 0:
                raise ValueError('invalid_detection_input')
            return value
        if kind is int:
            if value.bit_length() > 64:
                raise ValueError('invalid_detection_input')
            return value
        if value is None or kind in (UUID, datetime, bool):
            return value
        raise ValueError('invalid_detection_input')

    return plain(event), plain(rules)


def _field_value(event, field):
    # Field comes only from the Literal allowlist; no arbitrary traversal.
    if '.' not in field:
        return getattr(event, field)
    parent, child = field.split('.')
    value = getattr(event, parent)
    return getattr(value, child) if value is not None else None


def _matches(actual, condition):
    if actual is None:
        return False
    if condition.field == 'rule.groups':
        if (type(actual) is not tuple or len(actual) > 100
                or any(type(value) is not str for value in actual)):
            raise ValueError('invalid_detection_input')
        return any(value in condition.value for value in actual)
    expected_type = int if condition.field in NUMERIC_LIMITS else str
    if type(actual) is not expected_type:
        raise ValueError('invalid_detection_input')
    value = condition.value
    if condition.operator == 'eq':
        return actual == value
    if condition.operator == 'in':
        return actual in value
    if condition.operator == 'gt':
        return actual > value
    if condition.operator == 'gte':
        return actual >= value
    if condition.operator == 'lt':
        return actual < value
    if condition.operator == 'lte':
        return actual <= value
    raise ValueError('invalid_detection_input')


def match_event(event: NormalizedSecurityEvent, rules: tuple[DetectionRule, ...], *,
                tenant_id: UUID) -> tuple[DetectionMatch, ...]:
    """Evaluate one event against at most 100 same-tenant rule revisions.

    Rules may be supplied as a list or tuple, never an unbounded iterable.
    Reject the entire call on invalid ownership/input/duplicate rule IDs before
    evaluation. Missing fields are nonmatches. String matching is exact and
    case-sensitive; ordered comparisons apply only to bounded integer fields.
    Rule/condition/member order is canonical. Collection time is excluded from
    event fingerprints; normalized content and rule content are included.
    Rule schema 1.1 adds contains_any only for rule.groups. Its traces contain
    the sorted distinct intersection, bounded by the 32 configured values.
    Schema 1.0 remains the default and retains its original identity contract.
    """
    try:
        if (type(tenant_id) is not UUID or type(event) is not NormalizedSecurityEvent
                or type(rules) not in (list, tuple) or len(rules) > MAX_RULES
                or any(type(rule) is not DetectionRule for rule in rules)):
            raise ValueError('invalid_detection_input')
        event_data, rule_data = _bounded_snapshots(event, rules)
        event = NormalizedSecurityEvent.model_validate(event_data)
        validated = tuple(DetectionRule.model_validate(data) for data in rule_data)
        if (event.tenant_id != tenant_id or any(rule.tenant_id != tenant_id for rule in validated)
                or len({rule.rule_id for rule in validated}) != len(validated)):
            raise ValueError('invalid_detection_input')
        event_digest = _fingerprint(event, exclude={'ingested_at'})
        results = []
        for rule in sorted(validated, key=lambda item: item.rule_id):
            actuals = tuple(_field_value(event, condition.field) for condition in rule.conditions)
            if not all(_matches(actual, condition) for actual, condition in zip(actuals, rule.conditions)):
                continue
            rule_digest = _fingerprint(rule)
            results.append(DetectionMatch(
                schema_version=rule.schema_version, engine_version=rule.schema_version,
                match_id=uuid5(NAMESPACE, f'{rule.schema_version}:{tenant_id}:{event_digest}:{rule_digest}'),
                tenant_id=tenant_id, event_id=event.event_id, event_fingerprint=event_digest,
                evidence_id=event.evidence_id, evidence_sha256=event.evidence_sha256,
                source_reference=event.source_reference, rule_id=rule.rule_id,
                rule_version=rule.version, rule_fingerprint=rule_digest,
                matched_conditions=tuple(MatchedCondition(
                    field=condition.field, operator=condition.operator,
                    expected=condition.value,
                    actual=(tuple(sorted({value for value in actual if value in condition.value}))
                            if condition.field == 'rule.groups' else actual),
                ) for actual, condition in zip(actuals, rule.conditions)),
            ))
        return tuple(results)
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
        raise ValueError('invalid_detection_input') from None
