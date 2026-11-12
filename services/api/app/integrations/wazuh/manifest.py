"""TG-04B-PRE2: offline development manifest clearance, never live authority.

Authentication context, authority configuration and independent verification must
arrive through trusted application-side boundaries, never model/manifest text.
The receipt represents a separately verified assertion; this module performs no
signature, identity-provider, CA, role, database or network verification. Digests
bind inputs, not issuer authenticity. PASS is offline-only and never executable.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from app.gateway.disclosure_policy import Destination
from app.gateway.contracts import _Contract, ToolRequest, TrustedContext


Identifier = Annotated[str, Field(pattern=r'^[a-z][a-z0-9_.:-]{0,95}$')]
Digest = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
CredentialReference = Annotated[str, Field(pattern=r'^env:[A-Z][A-Z0-9_]{0,63}$')]
MAX_INPUT_BYTES = 32768
Reason = Literal['OFFLINE_VALIDATED', 'INVALID_INPUT', 'MISSING_VERIFICATION',
    'AUTHORITY_UNVERIFIED', 'INTEGRITY_UNVERIFIED', 'SOURCE_AUTHORITY_UNVERIFIED',
    'VERIFICATION_STALE', 'MANIFEST_STALE', 'IDENTITY_MISMATCH', 'INACTIVE_INTEGRATION',
    'UNRESOLVED_ALIAS', 'AMBIGUOUS_SOURCE', 'PARAMETER_MISMATCH', 'INVALID_LIMITS',
    'DESTINATION_MISMATCH', 'CREDENTIAL_MISMATCH', 'CA_MISMATCH', 'EVIDENCE_INCOMPLETE']
Evidence = Literal['VALID_CONTRACTS', 'ISSUER_VERIFICATION', 'MANIFEST_INTEGRITY',
    'SOURCE_AUTHORITY', 'FRESH_VERIFICATION', 'CURRENT_MANIFEST', 'TRUSTED_IDENTITY',
    'EXACT_SOURCE', 'APPROVED_QUERY', 'RESOURCE_LIMITS', 'DESTINATION', 'CREDENTIAL_REFERENCE', 'CA_PROVENANCE']


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def _hash(value):
    return hashlib.sha256(_canonical(value).encode('ascii')).hexdigest()


def _aware(value):
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError('invalid_time')
    return value.astimezone(timezone.utc)


def _millis(value):
    delta = value - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return delta.days * 86400000 + delta.seconds * 1000 + delta.microseconds // 1000


class SourceIndex(_Contract):
    name: Annotated[str, Field(pattern=r'^wazuh-alerts-[a-z0-9][a-z0-9._-]{0,95}$')]
    index_uuid: Annotated[str, Field(pattern=r'^[A-Za-z0-9_-]{1,64}$')]
    kind: Literal['CONCRETE', 'ALIAS']


class OrganizationScope(_Contract):
    mode: Literal['DEDICATED', 'SHARED']
    field: Identifier | None
    value: Identifier | None
    mapping_type: Literal['keyword'] | None
    server_enforced: bool


class QueryBounds(_Contract):
    window_start: datetime
    window_end: datetime
    size: Annotated[int, Field(ge=1, le=2)]
    max_pages: Literal[1]
    require_timestamp: Literal[True]

    @field_validator('window_start', 'window_end')
    @classmethod
    def millisecond_times(cls, value):
        value = _aware(value)
        if value.microsecond % 1000:
            raise ValueError('ambiguous_time_precision')
        return value


class ResourceCeilings(_Contract):
    max_input_bytes: Annotated[int, Field(ge=1, le=32768)]
    max_pages: Literal[1]
    max_fetched_hits: Annotated[int, Field(ge=1, le=3)]
    max_result_bytes: Annotated[int, Field(ge=1, le=2048)]
    max_wire_bytes: Annotated[int, Field(ge=1, le=65536)]
    request_timeout_ms: Annotated[int, Field(ge=1, le=5000)]
    overall_deadline_ms: Annotated[int, Field(ge=1, le=15000)]
    max_requests: Literal[3]
    max_retries: Literal[0]
    max_memory_mib: Annotated[int, Field(ge=1, le=128)] = 128
    max_cpu_ms: Annotated[int, Field(ge=1, le=5000)] = 1000


class DevelopmentManifest(_Contract):
    manifest_id: UUID
    environment: Literal['development'] = 'development'
    tenant_id: UUID
    principal_id: UUID
    integration_id: UUID
    active: bool
    indices: Annotated[tuple[SourceIndex, ...], Field(min_length=1, max_length=4)]
    organization: OrganizationScope
    destination: Destination
    credential_reference: CredentialReference
    ca_reference: Annotated[str, Field(pattern=r'^ca-ref:[a-z][a-z0-9_-]{0,63}$')]
    ca_sha256: Digest
    issuer_id: Identifier
    provenance_reference: Identifier
    issued_at: datetime
    expires_at: datetime
    approved_query: QueryBounds
    ceilings: ResourceCeilings
    capability_id: Literal['wazuh.alerts.search'] = 'wazuh.alerts.search'
    capability_version: Literal['1.0'] = '1.0'
    policy_version: Literal['1.0'] = '1.0'

    _times = field_validator('issued_at', 'expires_at')(_aware)

    @field_validator('indices')
    @classmethod
    def canonical_indices(cls, values):
        if len({item.name for item in values}) != len(values) or len({item.index_uuid for item in values}) != len(values):
            raise ValueError('conflicting_index_identity')
        return tuple(sorted(values, key=lambda item: item.name))


class VerificationAuthority(_Contract):
    """Trusted allowlist configuration, supplied independently of the manifest."""
    issuer_id: Identifier
    verifier_id: Identifier
    destination: Destination
    credential_reference: CredentialReference
    ca_sha256: Digest


class IndependentVerification(_Contract):
    """Receipt from trusted verifier code; never parsed from an untrusted claim."""
    issuer_id: Identifier
    verifier_id: Identifier
    manifest_sha256: Digest
    evidence_reference: Identifier
    verified_at: datetime
    valid_until: datetime
    issuer_validated: bool | None
    integrity_validated: bool | None
    source_authority_validated: bool | None
    destination_validated: bool | None
    credential_reference_validated: bool | None
    ca_provenance_validated: bool | None

    _times = field_validator('verified_at', 'valid_until')(_aware)


class _Blocked(ValueError):
    pass


def _block(reason, evidence):
    raise _Blocked(reason, evidence)


def _snapshot(value, contract):
    allowed = (TrustedContext, ToolRequest, Destination, SourceIndex, OrganizationScope,
        QueryBounds, ResourceCeilings, DevelopmentManifest, VerificationAuthority, IndependentVerification)
    nodes = 0
    def data(item, depth=0):
        nonlocal nodes
        nodes += 1
        if depth > 8 or nodes > 2048:
            _block('INVALID_LIMITS', 'RESOURCE_LIMITS')
        if type(item) in allowed:
            if item.model_extra or set(item.__dict__) != set(type(item).model_fields):
                _block('INVALID_INPUT', 'VALID_CONTRACTS')
            return {key: data(val, depth + 1) for key, val in item.__dict__.items()}
        if type(item) is tuple and len(item) <= 16:
            return tuple(data(val, depth + 1) for val in item)
        if type(item) is str and len(item) <= 1024:
            return item
        if item is None or type(item) in (UUID, datetime, int, bool):
            return item
        _block('INVALID_INPUT', 'VALID_CONTRACTS')
    if type(value) is not contract:
        _block('INVALID_INPUT', 'VALID_CONTRACTS')
    return contract.model_validate(data(value))


def manifest_digest(manifest: DevelopmentManifest) -> str:
    """Integrity binding only: this digest does not establish issuer authority."""
    return _hash(_snapshot(manifest, DevelopmentManifest).model_dump(mode='json'))


def query_parameters(manifest: DevelopmentManifest) -> tuple:
    """Build proposal parameters, with no authorization or execution effects."""
    manifest = _snapshot(manifest, DevelopmentManifest)
    query = manifest.approved_query
    values = (('pages', str(query.max_pages)), ('policy_version', manifest.policy_version),
        ('size', str(query.size)), ('timestamp_required', 'true' if query.require_timestamp else 'false'),
        ('window_end_ms', str(_millis(query.window_end))), ('window_start_ms', str(_millis(query.window_start))))
    context = _hash({'manifest_sha256': manifest_digest(manifest), 'parameters': values})
    return tuple(sorted((*values, ('query_context', context))))


def _validate_scope(manifest, request):
    query, limits, organization = manifest.approved_query, manifest.ceilings, manifest.organization
    if not manifest.active:
        _block('INACTIVE_INTEGRATION', 'CURRENT_MANIFEST')
    if any(item.kind != 'CONCRETE' for item in manifest.indices):
        _block('UNRESOLVED_ALIAS', 'EXACT_SOURCE')
    if organization.mode == 'DEDICATED':
        if any(value is not None for value in (organization.field, organization.value, organization.mapping_type)) or organization.server_enforced:
            _block('AMBIGUOUS_SOURCE', 'SOURCE_AUTHORITY')
    elif (organization.field != 'organization.id' or not organization.value
            or organization.mapping_type != 'keyword' or not organization.server_enforced):
        _block('AMBIGUOUS_SOURCE', 'SOURCE_AUTHORITY')
    if (_millis(query.window_start) < 0
            or not timedelta(0) < query.window_end - query.window_start <= timedelta(minutes=15)):
        _block('PARAMETER_MISMATCH', 'APPROVED_QUERY')
    if (query.size + 1 > limits.max_fetched_hits or limits.max_pages != query.max_pages
            or limits.max_wire_bytes < limits.max_result_bytes
            or limits.overall_deadline_ms < limits.request_timeout_ms * limits.max_requests):
        _block('INVALID_LIMITS', 'RESOURCE_LIMITS')
    if (request.tenant_id != manifest.tenant_id or request.principal_id != manifest.principal_id
            or request.target != str(manifest.integration_id) or request.capability_id != manifest.capability_id
            or request.capability_version != manifest.capability_version or request.operation != 'query'):
        _block('IDENTITY_MISMATCH', 'TRUSTED_IDENTITY')
    if request.parameters != query_parameters(manifest):
        _block('PARAMETER_MISMATCH', 'APPROVED_QUERY')


def _filter(manifest):
    query = manifest.approved_query
    filters = [{'exists': {'field': 'timestamp'}}, {'range': {'timestamp': {
        'gte': _millis(query.window_start), 'lt': _millis(query.window_end), 'format': 'epoch_millis'}}}]
    if manifest.organization.mode == 'SHARED':
        filters.append({'term': {'organization.id': manifest.organization.value}})
    return _canonical({'bool': {'filter': filters}})


def _manifest_time(manifest, at):
    if (not manifest.issued_at <= at < manifest.expires_at
            or manifest.expires_at - manifest.issued_at > timedelta(hours=1)):
        _block('MANIFEST_STALE', 'CURRENT_MANIFEST')
    if manifest.approved_query.window_end > at:
        _block('PARAMETER_MISMATCH', 'APPROVED_QUERY')


class QueryPlan(_Contract):
    manifest: DevelopmentManifest
    request: ToolRequest
    verification_sha256: Digest
    evaluated_at: datetime
    source_filter_json: Annotated[str, Field(max_length=2048)]
    pagination_scope_sha256: Digest
    pit_open_path: Annotated[str, Field(max_length=512)]
    search_path: Literal['/_search'] = '/_search'
    pit_close_path: Literal['/_search/point_in_time'] = '/_search/point_in_time'
    fetch_size: Annotated[int, Field(ge=2, le=3)]
    executable: Literal[False] = False
    plan_sha256: Digest

    _time = field_validator('evaluated_at')(_aware)

    @model_validator(mode='after')
    def verify_plan(self):
        _manifest_time(self.manifest, self.evaluated_at)
        _validate_scope(self.manifest, self.request)
        expected_path = '/' + ','.join(item.name for item in self.manifest.indices) + '/_search/point_in_time'
        if (self.source_filter_json != _filter(self.manifest) or self.pit_open_path != expected_path
                or self.fetch_size != self.manifest.approved_query.size + 1
                or self.pagination_scope_sha256 != dict(self.request.parameters)['query_context']):
            raise ValueError('invalid_query_plan')
        data = self.model_dump(mode='json'); claimed = data.pop('plan_sha256')
        if not hmac.compare_digest(_hash(data), claimed):
            raise ValueError('invalid_plan_digest')
        return self


class Clearance(_Contract):
    status: Literal['PASS', 'BLOCKED', 'UNVERIFIED']
    reasons: Annotated[tuple[Reason, ...], Field(min_length=1, max_length=8)]
    missing_evidence: Annotated[tuple[Evidence, ...], Field(max_length=8)]
    evaluated_at: datetime | None
    plan: QueryPlan | None
    executable: Literal[False] = False
    operational_clearance: Literal['UNVERIFIED'] = 'UNVERIFIED'

    @field_validator('evaluated_at')
    @classmethod
    def aware_or_absent(cls, value):
        return None if value is None else _aware(value)

    @model_validator(mode='after')
    def consistent(self):
        passed = self.status == 'PASS'
        if (passed != (self.plan is not None) or passed != (self.reasons == ('OFFLINE_VALIDATED',))
                or passed != (not self.missing_evidence)
                or passed and self.evaluated_at != self.plan.evaluated_at):
            raise ValueError('invalid_clearance')
        return self


def assess_manifest(context: TrustedContext, manifest: DevelopmentManifest, request: ToolRequest, *,
                    authority=None, verification=None, at: datetime) -> Clearance:
    """Compile only after independent trusted receipt checks. Never dispatch."""
    evaluated_at = None
    try:
        evaluated_at = _aware(at)
        context = _snapshot(context, TrustedContext)
        manifest = _snapshot(manifest, DevelopmentManifest)
        request = _snapshot(request, ToolRequest)
        if authority is None or verification is None:
            _block('MISSING_VERIFICATION', 'ISSUER_VERIFICATION')
        authority = _snapshot(authority, VerificationAuthority)
        verification = _snapshot(verification, IndependentVerification)
        if (authority.issuer_id == authority.verifier_id or verification.verifier_id != authority.verifier_id
                or manifest.issuer_id != authority.issuer_id or verification.issuer_id != authority.issuer_id
                or verification.issuer_validated is not True):
            _block('AUTHORITY_UNVERIFIED', 'ISSUER_VERIFICATION')
        if verification.integrity_validated is not True or not hmac.compare_digest(manifest_digest(manifest), verification.manifest_sha256):
            _block('INTEGRITY_UNVERIFIED', 'MANIFEST_INTEGRITY')
        if verification.source_authority_validated is not True:
            _block('SOURCE_AUTHORITY_UNVERIFIED', 'SOURCE_AUTHORITY')
        if (not manifest.issued_at <= verification.verified_at <= evaluated_at < verification.valid_until
                or evaluated_at - verification.verified_at > timedelta(minutes=5)
                or verification.valid_until - verification.verified_at > timedelta(minutes=5)):
            _block('VERIFICATION_STALE', 'FRESH_VERIFICATION')
        _manifest_time(manifest, evaluated_at)
        if (context.tenant_id != manifest.tenant_id or context.principal_id != manifest.principal_id):
            _block('IDENTITY_MISMATCH', 'TRUSTED_IDENTITY')
        if manifest.destination != authority.destination or manifest.destination.audience != 'TENANT_LOCAL':
            _block('DESTINATION_MISMATCH', 'DESTINATION')
        if manifest.credential_reference != authority.credential_reference:
            _block('CREDENTIAL_MISMATCH', 'CREDENTIAL_REFERENCE')
        if manifest.ca_sha256 != authority.ca_sha256:
            _block('CA_MISMATCH', 'CA_PROVENANCE')
        _validate_scope(manifest, request)
        inputs = [context, manifest, request, authority, verification]
        if len(_canonical([item.model_dump(mode='json') for item in inputs]).encode('ascii')) > min(MAX_INPUT_BYTES, manifest.ceilings.max_input_bytes):
            _block('INVALID_LIMITS', 'RESOURCE_LIMITS')
        missing = []
        for check, evidence in (('destination_validated', 'DESTINATION'),
            ('credential_reference_validated', 'CREDENTIAL_REFERENCE'), ('ca_provenance_validated', 'CA_PROVENANCE')):
            value = getattr(verification, check)
            if value is False:
                _block('EVIDENCE_INCOMPLETE', evidence)
            if value is None:
                missing.append(evidence)
        if missing:
            return Clearance(status='UNVERIFIED', reasons=('EVIDENCE_INCOMPLETE',),
                missing_evidence=tuple(missing), evaluated_at=evaluated_at, plan=None)
        draft = QueryPlan.model_construct(manifest=manifest, request=request,
            verification_sha256=_hash(verification.model_dump(mode='json')), evaluated_at=evaluated_at,
            source_filter_json=_filter(manifest), pagination_scope_sha256=dict(request.parameters)['query_context'],
            pit_open_path='/' + ','.join(item.name for item in manifest.indices) + '/_search/point_in_time',
            fetch_size=manifest.approved_query.size + 1, plan_sha256='0' * 64)
        data = draft.model_dump(mode='json'); data.pop('plan_sha256'); data['plan_sha256'] = _hash(data)
        plan = QueryPlan.model_validate_json(_canonical(data))
        return Clearance(status='PASS', reasons=('OFFLINE_VALIDATED',), missing_evidence=(),
                         evaluated_at=evaluated_at, plan=plan)
    except _Blocked as error:
        reason, evidence = error.args
    except Exception:
        reason, evidence = 'INVALID_INPUT', 'VALID_CONTRACTS'
    return Clearance(status='BLOCKED', reasons=(reason,), missing_evidence=(evidence,),
                     evaluated_at=evaluated_at, plan=None)
