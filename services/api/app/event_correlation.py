"""Pure batch correlation with fixed UTC windows and explicit provenance.

Groups describe only the supplied batch, not a completed stream or confirmed
incident. No clock, persistence, watermark, I/O or AI inference is involved.
Inputs and authenticated tenant context must come from trusted application code.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import json
from typing import Annotated, Literal
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_serializer, model_validator

from app.detection_rules import DetectionCondition, DetectionMatch, DetectionRule, MatchedCondition, match_event
from app.security_events import EventAgent, EventEndpoint, EventRule, NormalizedSecurityEvent


GroupField = Literal['source_system', 'category', 'agent.id', 'agent.name', 'agent.ip',
                     'source.ip', 'destination.ip', 'rule.id']
GroupValue = Annotated[str, Field(min_length=1, max_length=4096)]
Digest = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
Count = Annotated[int, Field(ge=0, le=100)]
Version = Annotated[int, Field(ge=1, le=2 ** 31 - 1)]
SchemaVersion = Literal['1.0', '1.1']
MAX_EVENTS = 100
MAX_MATCHES = 100
MAX_POLICIES = 1
MAX_RESULTS = 50
MAX_INPUT_BYTES = 2_097_152
MAX_INPUT_NODES = 30_000
MAX_MATCH_TRACE_BYTES = 65_536
MAX_TRACE_BYTES = 1_048_576
MAX_EXPLANATION_BYTES = 4096
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
NAMESPACE = UUID('2387a291-0906-4e09-bd1d-e871548721c4')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def _digest(model, *, exclude=None):
    return hashlib.sha256(_canonical(model.model_dump(mode='json', exclude=exclude)).encode()).hexdigest()


def _utc(value):
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError('invalid_correlation_timestamp')
    return value.astimezone(timezone.utc)


class _Contract(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra='forbid',
                              hide_input_in_errors=True, revalidate_instances='always')


class CorrelationPolicy(_Contract):
    schema_version: SchemaVersion = '1.0'
    policy_id: UUID
    tenant_id: UUID
    version: Version
    name: Annotated[str, Field(min_length=1, max_length=128)]
    detection_rule: DetectionRule
    group_by: Annotated[tuple[GroupField, ...], Field(min_length=1, max_length=3)]
    window_seconds: Annotated[int, Field(ge=1, le=86400)]
    min_events: Annotated[int, Field(ge=2, le=MAX_EVENTS)]

    @field_validator('name')
    @classmethod
    def validate_name(cls, value):
        if not value.strip():
            raise ValueError('invalid_correlation_policy_name')
        value.encode('utf-8')
        return value

    @field_validator('group_by')
    @classmethod
    def canonical_keys(cls, value):
        if len(set(value)) != len(value):
            raise ValueError('duplicate_correlation_key')
        return tuple(sorted(value))

    @model_validator(mode='after')
    def validate_ownership(self):
        if self.tenant_id != self.detection_rule.tenant_id:
            raise ValueError('invalid_correlation_policy_ownership')
        if self.schema_version == '1.0' and 'rule.id' in self.group_by:
            raise ValueError('correlation_key_requires_schema_1_1')
        return self


class CorrelationMember(_Contract):
    event_time: datetime
    match: DetectionMatch

    _event_utc = field_validator('event_time')(_utc)


class CorrelationExplanation(_Contract):
    schema_version: Literal['1.0'] = '1.0'
    reason_code: Literal['shared_keys_rule_window_threshold'] = 'shared_keys_rule_window_threshold'
    window_semantics: Literal['utc_epoch_tumbling_half_open'] = 'utc_epoch_tumbling_half_open'
    statement: Literal[
        'Distinct evidence-backed events matched the configured detection rule, '
        'shared all grouping values, and met the threshold within one fixed UTC window.'
    ] = ('Distinct evidence-backed events matched the configured detection rule, '
         'shared all grouping values, and met the threshold within one fixed UTC window.')
    group_fields: Annotated[tuple[GroupField, ...], Field(min_length=1, max_length=3)]
    minimum_distinct_events: Annotated[int, Field(ge=2, le=MAX_EVENTS)]
    observed_distinct_events: Annotated[int, Field(ge=2, le=MAX_EVENTS)]
    detection_rule_id: UUID
    detection_rule_version: Version
    detection_rule_fingerprint: Digest


class CorrelationGroup(_Contract):
    schema_version: SchemaVersion = '1.0'
    engine_version: SchemaVersion = '1.0'
    # group_id identifies the logical bucket; result_id identifies its members.
    group_id: UUID
    result_id: UUID
    tenant_id: UUID
    policy_id: UUID
    policy_version: Version
    policy_fingerprint: Digest
    group_key: Annotated[tuple[tuple[GroupField, GroupValue], ...], Field(min_length=1, max_length=3)]
    window_start: datetime
    window_end: datetime
    first_event_time: datetime
    last_event_time: datetime
    event_count: Annotated[int, Field(ge=2, le=MAX_EVENTS)]
    members: Annotated[tuple[CorrelationMember, ...], Field(min_length=2, max_length=MAX_EVENTS)]
    explanation: CorrelationExplanation | None = None

    _times_utc = field_validator('window_start', 'window_end', 'first_event_time', 'last_event_time')(_utc)

    @model_serializer(mode='wrap')
    def preserve_v1_serialization(self, handler):
        result = handler(self)
        if self.schema_version == '1.0':
            result.pop('explanation', None)
        return result

    @model_validator(mode='after')
    def validate_membership(self):
        if (self.schema_version != self.engine_version
                or (self.schema_version == '1.0' and (self.explanation is not None
                                                     or any(field == 'rule.id' for field, _ in self.group_key)))
                or (self.schema_version == '1.1' and self.explanation is None)):
            raise ValueError('invalid_correlation_group_schema')
        if (self.event_count != len(self.members)
                or len({member.match.event_id for member in self.members}) != self.event_count
                or len({member.match.evidence_id for member in self.members}) != self.event_count
                or len({member.match.match_id for member in self.members}) != self.event_count
                or any(member.match.tenant_id != self.tenant_id for member in self.members)
                or self.members != tuple(sorted(self.members, key=lambda item: (item.event_time, item.match.event_id)))
                or self.first_event_time != self.members[0].event_time
                or self.last_event_time != self.members[-1].event_time):
            raise ValueError('invalid_correlation_membership')
        if (len({field for field, _ in self.group_key}) != len(self.group_key)
                or self.group_key != tuple(sorted(self.group_key))
                or any(not value.strip() for _, value in self.group_key)):
            raise ValueError('invalid_correlation_key')
        width = self.window_end - self.window_start
        if (width.microseconds or not 1 <= width.total_seconds() <= 86400
                or _window(self.window_start, int(width.total_seconds())) != (self.window_start, self.window_end)
                or any(not self.window_start <= member.event_time < self.window_end for member in self.members)):
            raise ValueError('invalid_correlation_window')
        if self.explanation is not None:
            reason = self.explanation
            if (reason.observed_distinct_events != self.event_count
                    or reason.minimum_distinct_events > self.event_count
                    or reason.group_fields != tuple(field for field, _ in self.group_key)
                    or any((member.match.rule_id, member.match.rule_version, member.match.rule_fingerprint)
                           != (reason.detection_rule_id, reason.detection_rule_version,
                               reason.detection_rule_fingerprint) for member in self.members)):
                raise ValueError('invalid_correlation_explanation')
        expected_group_id = uuid5(NAMESPACE, _canonical([
            self.schema_version, str(self.tenant_id), self.policy_fingerprint,
            self.window_start.isoformat(), self.group_key]))
        member_digest = hashlib.sha256(_canonical([
            member.model_dump(mode='json') for member in self.members]).encode()).hexdigest()
        if (self.group_id != expected_group_id
                or self.result_id != uuid5(NAMESPACE, f'{self.schema_version}:{expected_group_id}:{member_digest}')):
            raise ValueError('invalid_correlation_identity')
        return self


class CorrelationResult(_Contract):
    schema_version: SchemaVersion = '1.0'
    engine_version: SchemaVersion = '1.0'
    tenant_id: UUID
    policy_id: UUID
    policy_version: Version
    policy_fingerprint: Digest
    received_count: Count
    unique_event_count: Count
    replay_count: Count
    matched_event_count: Count
    nonmatched_event_count: Count
    missing_group_key_count: Count
    below_threshold_event_count: Count
    groups: Annotated[tuple[CorrelationGroup, ...], Field(max_length=MAX_RESULTS)]
    received_match_count: Count = 0
    unique_match_count: Count = 0
    match_replay_count: Count = 0

    @model_serializer(mode='wrap')
    def preserve_v1_serialization(self, handler):
        result = handler(self)
        if self.schema_version == '1.0':
            for field in ('received_match_count', 'unique_match_count', 'match_replay_count'):
                result.pop(field, None)
        return result

    @model_validator(mode='after')
    def validate_accounting(self):
        if (self.schema_version != self.engine_version
                or any((group.schema_version, group.tenant_id, group.policy_id,
                        group.policy_version, group.policy_fingerprint)
                       != (self.schema_version, self.tenant_id, self.policy_id,
                           self.policy_version, self.policy_fingerprint) for group in self.groups)):
            raise ValueError('invalid_correlation_result_schema')
        members = tuple(member for group in self.groups for member in group.members)
        if (self.received_count != self.unique_event_count + self.replay_count
                or self.unique_event_count != self.matched_event_count + self.nonmatched_event_count
                or self.matched_event_count != self.missing_group_key_count + self.below_threshold_event_count + len(members)
                or len({member.match.event_id for member in members}) != len(members)
                or len({member.match.evidence_id for member in members}) != len(members)
                or len({group.group_id for group in self.groups}) != len(self.groups)
                or self.groups != tuple(sorted(self.groups, key=lambda item: (
                    item.window_start, item.window_end, item.group_key)))):
            raise ValueError('invalid_correlation_accounting')
        if self.schema_version == '1.0' and any((
                self.received_match_count, self.unique_match_count, self.match_replay_count)):
            raise ValueError('invalid_correlation_match_accounting')
        if self.schema_version == '1.1' and (
                self.received_match_count != self.unique_match_count + self.match_replay_count
                or self.unique_match_count != self.matched_event_count):
            raise ValueError('invalid_correlation_match_accounting')
        return self


def _snapshot_inputs(events, policy, matches):
    """Bound the entire batch before validation/serialization; reject objects.

    Known model dictionaries are copied recursively so validation cannot be
    bypassed by model_construct/model_copy. Counts include keys and containers.
    """
    nodes = 0
    budget = MAX_INPUT_BYTES
    models = (NormalizedSecurityEvent, EventAgent, EventEndpoint, EventRule,
              DetectionRule, DetectionCondition, DetectionMatch, MatchedCondition, CorrelationPolicy)

    def plain(value, depth=0):
        nonlocal nodes, budget
        nodes += 1
        budget -= 32
        if nodes > MAX_INPUT_NODES or depth > 12 or budget < 0:
            raise ValueError('invalid_correlation_input')
        kind = type(value)
        if kind in models:
            return plain(value.__dict__, depth + 1)
        if kind is dict:
            if len(value) > MAX_INPUT_NODES:
                raise ValueError('invalid_correlation_input')
            result = {}
            for key, item in value.items():
                if type(key) is not str:
                    raise ValueError('invalid_correlation_input')
                result[plain(key, depth + 1)] = plain(item, depth + 1)
            return result
        if kind in (tuple, list):
            if len(value) > MAX_INPUT_NODES:
                raise ValueError('invalid_correlation_input')
            result = [plain(item, depth + 1) for item in value]
            return tuple(result) if kind is tuple else result
        if kind is str:
            if len(value) > 4096:
                raise ValueError('invalid_correlation_input')
            budget -= len(value.encode('utf-8'))
            if budget < 0:
                raise ValueError('invalid_correlation_input')
            return value
        if kind is int:
            if value.bit_length() > 64:
                raise ValueError('invalid_correlation_input')
            return value
        if value is None or kind in (UUID, datetime, bool):
            return value
        raise ValueError('invalid_correlation_input')

    return plain(events), plain(policy), plain(matches)


def _group_key(event, fields):
    values = []
    for field in fields:
        if '.' in field:
            parent, child = field.split('.')
            parent = getattr(event, parent)
            value = getattr(parent, child) if parent is not None else None
        else:
            value = getattr(event, field)
        if value is None:
            return None
        if type(value) is not str or not value.strip():
            raise ValueError('invalid_correlation_input')
        values.append((field, value))
    return tuple(values)


def _window(timestamp, seconds):
    delta = timestamp - EPOCH
    microseconds = (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds
    width = seconds * 1_000_000
    start = EPOCH + timedelta(microseconds=(microseconds // width) * width)
    return start, start + timedelta(seconds=seconds)


def _encoded_size(value, limit):
    """Count canonical JSON bytes incrementally; never truncate trace content."""
    size = 0
    encoder = json.JSONEncoder(sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
    for chunk in encoder.iterencode(value):
        size += len(chunk.encode('utf-8'))
        if size > limit:
            raise ValueError('invalid_correlation_input')
    return size


def _verified_matches(unique, policy, supplied, tenant_id):
    """Validate every claim against a recomputed deterministic detection match.

    Schema 1.0 keeps its original convenience mode when supplied is None. Schema
    1.1 requires explicit history: absent claims are never silently generated.
    One event has at most one match for the single pinned detection rule.
    """
    verified = {}
    by_id = {}
    trace_bytes = 0
    if supplied is None:
        # Internal iteration is bounded by MAX_EVENTS. Stream legacy generated
        # traces so the byte budget stops work before materializing every match.
        supplied = (detection for event, _ in unique.values()
                    for detection in match_event(event, (policy.detection_rule,), tenant_id=tenant_id))
        recompute = False
    else:
        recompute = True
    received = 0
    for detection in supplied:
        received += 1
        if detection.tenant_id != tenant_id or detection.event_id not in unique:
            raise ValueError('invalid_correlation_input')
        previous = by_id.get(detection.match_id)
        if previous is not None:
            if previous != detection:
                raise ValueError('invalid_correlation_input')
            continue
        if detection.event_id in verified:
            raise ValueError('invalid_correlation_input')
        if recompute:
            event = unique[detection.event_id][0]
            expected = match_event(event, (policy.detection_rule,), tenant_id=tenant_id)
            if len(expected) != 1 or expected[0] != detection:
                raise ValueError('invalid_correlation_input')
        trace_bytes += _encoded_size(detection.model_dump(mode='json'), MAX_MATCH_TRACE_BYTES)
        if trace_bytes > MAX_TRACE_BYTES:
            raise ValueError('invalid_correlation_input')
        by_id[detection.match_id] = detection
        verified[detection.event_id] = detection
    return verified, received


def correlate_events(events: tuple[NormalizedSecurityEvent, ...], policy: CorrelationPolicy, *,
                     tenant_id: UUID, matches: tuple[DetectionMatch, ...] | None = None) -> CorrelationResult:
    """Correlate at most 100 events under one immutable, same-tenant policy.

    Lists/tuples only, at most 100 matches and one policy. Schema 1.1 requires
    explicit matches, verified against the normalized events and pinned rule;
    schema 1.0 retains automatic matching when matches is None. Repeated claims
    count once; conflicting event/evidence/match IDs reject the whole batch.
    Missing keys exclude a match from grouping with an explicit count. Windows
    are epoch-anchored, half-open [start,end), not rolling. Separate calls do not
    accumulate progress, and late arrivals may change membership/result_id.

    Limits: 1..86400 seconds, 1..3 grouping dimensions, 2..100 distinct events,
    50 output groups, 2 MiB conservative input budget and 30000 input nodes.
    Traces: 64 KiB per match, 1 MiB total accepted match traces and serialized
    result, 4 KiB per structured explanation; oversized calls fail, never truncate.
    Complexity: O(B + E*C*G*V + (E+M) log(E+M) + T), with input bytes/nodes B,
    E events, M matches, at most C=16 conditions, G=100 observed groups, V=32
    configured values, and trace bytes T. No event-pair Cartesian product.
    """
    try:
        if (type(tenant_id) is not UUID or type(policy) is not CorrelationPolicy
                or type(events) not in (tuple, list) or len(events) > MAX_EVENTS
                or any(type(event) is not NormalizedSecurityEvent for event in events)
                or (matches is not None and (type(matches) not in (tuple, list)
                    or len(matches) > MAX_MATCHES
                    or any(type(detection) is not DetectionMatch for detection in matches)))):
            raise ValueError('invalid_correlation_input')
        event_data, policy_data, match_data = _snapshot_inputs(events, policy, matches)
        policy = CorrelationPolicy.model_validate(policy_data)
        if policy.schema_version == '1.1' and matches is None:
            raise ValueError('invalid_correlation_input')
        validated = tuple(NormalizedSecurityEvent.model_validate(data) for data in event_data)
        supplied = None if matches is None else tuple(DetectionMatch.model_validate(data) for data in match_data)
        if policy.tenant_id != tenant_id or any(event.tenant_id != tenant_id for event in validated):
            raise ValueError('invalid_correlation_input')
        unique = {}
        evidence_ids = {}
        for event in validated:
            digest = _digest(event, exclude={'ingested_at'})
            previous = unique.get(event.event_id)
            if previous is not None:
                if previous[1] != digest:
                    raise ValueError('invalid_correlation_input')
                continue
            if event.evidence_id in evidence_ids:
                raise ValueError('invalid_correlation_input')
            evidence_ids[event.evidence_id] = event.event_id
            _window(event.event_time, policy.window_seconds)  # Validate even unselected event windows.
            unique[event.event_id] = (event, digest)
        verified, received_matches = _verified_matches(unique, policy, supplied, tenant_id)
        fingerprint = _digest(policy)
        buckets = {}
        matched = missing = 0
        for event, _ in unique.values():
            detection = verified.get(event.event_id)
            if detection is None:
                continue
            matched += 1
            key = _group_key(event, policy.group_by)
            if key is None:
                missing += 1
                continue
            start, end = _window(event.event_time, policy.window_seconds)
            buckets.setdefault((start, end, key), []).append(
                CorrelationMember(event_time=event.event_time, match=detection))
        groups = []
        below = 0
        for (start, end, key), members in sorted(buckets.items()):
            if len(members) < policy.min_events:
                below += len(members)
                continue
            members = tuple(sorted(members, key=lambda member: (member.event_time, member.match.event_id)))
            group_id = uuid5(NAMESPACE, _canonical([
                policy.schema_version, str(tenant_id), fingerprint, start.isoformat(), key]))
            member_digest = hashlib.sha256(_canonical([
                member.model_dump(mode='json') for member in members]).encode()).hexdigest()
            explanation = None
            if policy.schema_version == '1.1':
                explanation = CorrelationExplanation(
                    group_fields=policy.group_by, minimum_distinct_events=policy.min_events,
                    observed_distinct_events=len(members), detection_rule_id=policy.detection_rule.rule_id,
                    detection_rule_version=policy.detection_rule.version,
                    detection_rule_fingerprint=members[0].match.rule_fingerprint,
                )
                _encoded_size(explanation.model_dump(mode='json'), MAX_EXPLANATION_BYTES)
            groups.append(CorrelationGroup(
                schema_version=policy.schema_version, engine_version=policy.schema_version,
                group_id=group_id, result_id=uuid5(NAMESPACE, f'{policy.schema_version}:{group_id}:{member_digest}'),
                tenant_id=tenant_id, policy_id=policy.policy_id, policy_version=policy.version,
                policy_fingerprint=fingerprint, group_key=key, window_start=start, window_end=end,
                first_event_time=members[0].event_time, last_event_time=members[-1].event_time,
                event_count=len(members), members=members, explanation=explanation,
            ))
        result = CorrelationResult(
            schema_version=policy.schema_version, engine_version=policy.schema_version,
            tenant_id=tenant_id, policy_id=policy.policy_id, policy_version=policy.version,
            policy_fingerprint=fingerprint, received_count=len(validated), unique_event_count=len(unique),
            replay_count=len(validated) - len(unique), matched_event_count=matched,
            nonmatched_event_count=len(unique) - matched, missing_group_key_count=missing,
            below_threshold_event_count=below, groups=tuple(groups),
            received_match_count=received_matches if policy.schema_version == '1.1' else 0,
            unique_match_count=len(verified) if policy.schema_version == '1.1' else 0,
            match_replay_count=received_matches - len(verified) if policy.schema_version == '1.1' else 0,
        )
        _encoded_size(result.model_dump(mode='json'), MAX_TRACE_BYTES)
        return result
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
        raise ValueError('invalid_correlation_input') from None
