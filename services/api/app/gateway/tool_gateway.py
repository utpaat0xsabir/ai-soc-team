"""TG-01/TG-03B: mock dispatch requires grants and offline disclosure assessment.

Only trusted application code may supply context, grants, registry and sinks.
Request/model text cannot establish authority. No authentication, persistence,
clock, external adapter, plugin discovery or implicit configuration is provided.
Sinks are caller-owned test-only lists: reuse them for local replay detection;
they are not concurrent/durable audit logs or the application's evidence store.
"""

import hashlib
import hmac
import json
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, model_validator

from app.gateway.contracts import _Contract, _Operation, Parameter, Parameters, Text, ToolRequest, TrustedContext
from app.gateway import disclosure_policy
from app.integrations.wazuh import gateway as wazuh_gateway

Digest = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
MAX_INPUT_BYTES = 32768
MAX_OUTPUT_BYTES = 2048
MAX_GRANTS = 32
MAX_SINK_ITEMS = 1000


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


class ToolCapability(_Contract):
    capability_id: Text
    version: Text
    operation: Text
    risk: Text
    read_only: bool
    external_disclosure: bool
    synthetic: bool


class ToolGrant(_Operation):
    grant_id: UUID
    risk: Text
    read_only: bool
    # Explicit False means no third-party disclosure is consented to in TG-01.
    disclosure_consent: bool


class ToolObservation(_Contract):
    target: Annotated[str, Field(min_length=1, max_length=45)]
    source: Literal['mock.ip_reputation'] = 'mock.ip_reputation'
    label: Literal['SYNTHETIC / TEST ONLY'] = 'SYNTHETIC / TEST ONLY'
    verdict: Literal['unknown'] = 'unknown'


class ToolResult(ToolRequest):
    source: Literal['mock.ip_reputation'] = 'mock.ip_reputation'
    label: Literal['SYNTHETIC / TEST ONLY'] = 'SYNTHETIC / TEST ONLY'
    verdict: Literal['unknown'] = 'unknown'
    request_sha256: Digest
    result_sha256: Digest

    @model_validator(mode='after')
    def verify_digests(self):
        data = self.model_dump(mode='json')
        request = {key: data[key] for key in ToolRequest.model_fields}
        claimed = data.pop('result_sha256')
        if (not hmac.compare_digest(self.request_sha256, _digest(request))
                or not hmac.compare_digest(claimed, _digest(data))):
            raise ValueError('invalid_result_digest')
        return self


class GatewayAudit(_Contract):
    tenant_id: UUID | None
    principal_id: UUID | None
    request_id: UUID | None
    request_sha256: Digest | None
    outcome: Literal['allowed', 'denied']
    code: Literal['mock_completed', 'synthetic_search_completed', 'gateway_denied']
    source_references: Annotated[tuple[Annotated[str, Field(max_length=128)], ...], Field(max_length=2)] = ()


MOCK_CAPABILITY = ToolCapability(capability_id='mock.ip_reputation', version='1.0',
    operation='lookup', risk='passive', read_only=True, external_disclosure=False, synthetic=True)
MOCK_DESTINATION = disclosure_policy.Destination(provider_id='mock', provider_version='1.0',
    account_id='synthetic', destination_id='in-process', audience='TENANT_LOCAL')
WAZUH_ALERT_SEARCH = ToolCapability(capability_id='wazuh.alerts.search', version='1.0',
    operation='query', risk='R1', read_only=True, external_disclosure=False, synthetic=True)
WAZUH_FAKE_DESTINATION = disclosure_policy.Destination(provider_id='wazuh-fake', provider_version='1.0',
    account_id='synthetic', destination_id='in-process', audience='TENANT_LOCAL')


class GatewayError(ValueError):
    """Bounded error: never includes input values or adapter exceptions."""


def mock_ip_reputation(target: str) -> ToolObservation:
    """Deterministic unknown verdict; no lookup or real threat claim is made."""
    return ToolObservation(target=target)


def _checked(value, contract):
    if type(value) is not contract or value.model_extra:
        raise ValueError('invalid_contract')
    # Reconstruct even model_construct/model_copy instances; preserve extra keys
    # so forged authority cannot disappear through serialization.
    return contract.model_validate(dict(value.__dict__))


def _check_history(trusted, request, audit, evidence):
    if len(audit) >= MAX_SINK_ITEMS or len(evidence) >= MAX_SINK_ITEMS:
        raise ValueError('sink_limit')
    events = tuple(_checked(item, GatewayAudit) for item in audit)
    records = tuple(_checked(item, wazuh_gateway.WazuhSearchResult
        if type(item) is wazuh_gateway.WazuhSearchResult else ToolResult) for item in evidence)
    if any((item.tenant_id, item.principal_id, item.request_id) ==
           (trusted.tenant_id, trusted.principal_id, request.request_id)
           for item in events + records):
        raise ValueError('request_replayed')


def execute(context: TrustedContext, request: ToolRequest, *, registry=None, policy=None,
            audit_sink, evidence_sink, disclosure=None, wazuh_bindings=None,
            wazuh_client=None) -> ToolResult | wazuh_gateway.WazuhSearchResult:
    """One mocked operation. Missing authority denies; sinks never perform I/O.

    Pre-dispatch denials call no adapter. Output validation happens after the
    adapter returns and before either successful evidence or audit is appended.
    Replay identity is (tenant, principal, request_id) within the supplied sinks.
    Missing disclosure inputs deny. An offline ALLOW is necessary but does not
    itself authorize dispatch; only explicit local synthetic adapters are eligible.
    """
    trusted = snapshot = None
    audit_tenant = audit_principal = None
    request_hash = None
    try:
        if (type(audit_sink) is not list or type(evidence_sink) is not list
                or audit_sink is evidence_sink or len(audit_sink) >= MAX_SINK_ITEMS
                or len(evidence_sink) >= MAX_SINK_ITEMS):
            raise ValueError('invalid_sinks')
        trusted = _checked(context, TrustedContext)
        audit_tenant, audit_principal = trusted.tenant_id, trusted.principal_id
        snapshot = _checked(request, ToolRequest)
        if (type(registry) is not tuple or not 1 <= len(registry) <= 2
                or type(policy) is not tuple or not 1 <= len(policy) <= MAX_GRANTS):
            raise ValueError('missing_authority')
        registrations = tuple(_checked(item, ToolCapability) for item in registry)
        if (len({item.capability_id for item in registrations}) != len(registrations)
                or any(item not in (MOCK_CAPABILITY, WAZUH_ALERT_SEARCH) for item in registrations)):
            raise ValueError('unregistered_capability')
        capability, = tuple(item for item in registrations if item.capability_id == snapshot.capability_id
                            and item.version == snapshot.capability_version)
        grants = tuple(_checked(grant, ToolGrant) for grant in policy)
        inputs = [trusted.model_dump(mode='json'), snapshot.model_dump(mode='json'),
                  [item.model_dump(mode='json') for item in registrations],
                  [grant.model_dump(mode='json') for grant in grants]]
        if len(_canonical(inputs)) > MAX_INPUT_BYTES:
            raise ValueError('input_limit')
        request_hash = _digest(snapshot.model_dump(mode='json'))
        if (snapshot.tenant_id != trusted.tenant_id or snapshot.principal_id != trusted.principal_id
                or snapshot.capability_id != capability.capability_id
                or snapshot.capability_version != capability.version
                or snapshot.operation != capability.operation
                or capability == MOCK_CAPABILITY and snapshot.parameters != (('dataset', 'synthetic-v1'),)):
            raise ValueError('request_denied')
        identities, authorizations = set(), set()
        matched = False
        for grant in grants:
            authorization = tuple(getattr(grant, key) for key in _Operation.model_fields)
            if (grant.grant_id in identities or authorization in authorizations
                    or grant.tenant_id != trusted.tenant_id or grant.principal_id != trusted.principal_id
                    or grant.risk != capability.risk or grant.read_only is not True
                    or grant.disclosure_consent is not False):
                raise ValueError('ambiguous_policy')
            identities.add(grant.grant_id)
            authorizations.add(authorization)
            matched |= all(getattr(grant, key) == getattr(snapshot, key) for key in _Operation.model_fields)
        if not matched:
            raise ValueError('missing_grant')
        source = None
        if capability == WAZUH_ALERT_SEARCH:
            if type(wazuh_bindings) is not tuple or len(wazuh_bindings) != 1:
                raise ValueError('ambiguous_source_binding')
            source = _checked(wazuh_bindings[0], wazuh_gateway.WazuhSourceBinding)
            wazuh_gateway._parse_search(snapshot, source)
            if (type(wazuh_client) is not wazuh_gateway.FakeWazuhClient
                    or wazuh_gateway._binding(wazuh_client.binding) != source):
                raise ValueError('unapproved_synthetic_client')
            inputs.append(source.model_dump(mode='json'))
        elif wazuh_bindings is not None or wazuh_client is not None:
            raise ValueError('unexpected_source_binding')
        _check_history(trusted, snapshot, audit_sink, evidence_sink)
        enforcement = disclosure_policy._snapshot(disclosure, disclosure_policy.DisclosureInputs)
        if enforcement.intent.request != snapshot:
            raise ValueError('disclosure_request_mismatch')
        before = _canonical([*inputs, enforcement.model_dump(mode='json')])
        if len(before) > MAX_INPUT_BYTES:
            raise ValueError('input_limit')
        decision = _checked(disclosure_policy.evaluate_disclosure(trusted, enforcement.intent,
            policies=enforcement.policies, providers=enforcement.providers,
            consents=enforcement.consents, usage=enforcement.usage, at=enforcement.at),
            disclosure_policy.EgressDecision)
        after_inputs = [trusted.model_dump(mode='json'), snapshot.model_dump(mode='json'),
            [item.model_dump(mode='json') for item in registrations],
            [grant.model_dump(mode='json') for grant in grants]]
        if source is not None:
            after_inputs.append(source.model_dump(mode='json'))
        after = _canonical([*after_inputs, enforcement.model_dump(mode='json')])
        if (not hmac.compare_digest(before, after) or decision.outcome != 'ALLOW'
                or decision.executable is not False or decision.evaluated_at != enforcement.at):
            raise ValueError('disclosure_denied')
        expected_digest = hashlib.sha256(disclosure_policy._evaluation_bytes(trusted,
            enforcement.intent, policies=enforcement.policies, providers=enforcement.providers,
            consents=enforcement.consents, usage=enforcement.usage, at=enforcement.at)).hexdigest()
        if not hmac.compare_digest(decision.evaluation_sha256, expected_digest):
            raise ValueError('disclosure_binding_mismatch')
        common_eligible = (not capability.external_disclosure and capability.synthetic
            and capability.read_only and enforcement.intent.category == 'LOCAL_READ'
            and len(enforcement.policies) == 1
            and not enforcement.consents and enforcement.usage is None)
        if capability == MOCK_CAPABILITY:
            dispatch_eligible = (enforcement.intent.profile == 'mock_lookup' and enforcement.intent.risk == 'R0'
                and enforcement.intent.destination == MOCK_DESTINATION and enforcement.providers == (MOCK_DESTINATION,))
        else:
            dispatch_eligible = (enforcement.intent.profile == 'local_query' and enforcement.intent.risk == 'R1'
                and enforcement.intent.destination == WAZUH_FAKE_DESTINATION
                and enforcement.providers == (WAZUH_FAKE_DESTINATION,))
        if not common_eligible or not dispatch_eligible:
            raise ValueError('dispatch_ineligible')
        _check_history(trusted, snapshot, audit_sink, evidence_sink)
        if capability == MOCK_CAPABILITY:
            observation = _checked(mock_ip_reputation(snapshot.target), ToolObservation)
            if observation.target != snapshot.target:
                raise ValueError('invalid_adapter_target')
            data = {**snapshot.model_dump(mode='json'),
                    **observation.model_dump(mode='json'), 'request_sha256': request_hash}
            data['result_sha256'] = _digest(data)
            result = ToolResult.model_validate_json(json.dumps(data))
            code, references = 'mock_completed', ()
        else:
            result = _checked(wazuh_gateway._search_alerts(wazuh_client, source, snapshot),
                              wazuh_gateway.WazuhSearchResult)
            if (result.request_sha256 != request_hash
                    or any(getattr(result, key) != getattr(snapshot, key) for key in ToolRequest.model_fields)):
                raise ValueError('synthetic_request_mismatch')
            code = 'synthetic_search_completed'
            references = tuple(alert.source_reference for alert in result.alerts)
        output_limit = min(MAX_OUTPUT_BYTES, enforcement.intent.expected_output_bytes,
                           enforcement.policies[0].ceilings.max_output_bytes)
        if len(_canonical(result.model_dump(mode='json'))) > output_limit:
            raise ValueError('output_limit')
        _check_history(trusted, snapshot, audit_sink, evidence_sink)
        event = GatewayAudit(tenant_id=trusted.tenant_id, principal_id=trusted.principal_id,
            request_id=snapshot.request_id, request_sha256=request_hash,
            outcome='allowed', code=code, source_references=references)
    except Exception:
        if type(audit_sink) is list and audit_sink is not evidence_sink and len(audit_sink) < MAX_SINK_ITEMS:
            audit_sink.append(GatewayAudit(
                tenant_id=audit_tenant,
                principal_id=audit_principal,
                request_id=snapshot.request_id if snapshot is not None else None,
                request_sha256=request_hash, outcome='denied', code='gateway_denied'))
        raise GatewayError('gateway_denied') from None
    evidence_sink.append(result)
    audit_sink.append(event)
    return result
