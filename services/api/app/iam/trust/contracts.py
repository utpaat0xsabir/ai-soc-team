"""Immutable offline descriptions. No signature, identity or authority is verified."""
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, field_validator, model_validator
from pydantic_core import PydanticCustomError

from app.iam import contracts as iam

Counter = Annotated[int, Field(ge=1, le=9223372036854775807)]
Revision = Annotated[int, Field(ge=0, le=9223372036854775807)]
RootOperation = Literal['bootstrap', 'rotate', 'revoke', 'recover', 'approve-profile']


def reject(code):
    raise PydanticCustomError(code, code)


def _uuid(value):
    if type(value) is not UUID or value.int == 0:
        reject('INVALID_IDENTIFIER')
    return value


def _flags(value):
    # Existing Literal[False] accepts numeric zero; never normalize that claim.
    failures = set()
    def visit(item, code):
        if isinstance(item, dict):
            if 'executable' in item and item['executable'] is not False:
                failures.add(code)
            for key, child in item.items():
                visit(child, 'INVALID_AUTHORITY_SCOPE' if key == 'authority_scope' else code)
        elif isinstance(item, (tuple, list)):
            for child in item:
                visit(child, code)
    visit(value, 'MALFORMED_PROVENANCE_ENVELOPE')
    if failures:
        reject('INVALID_AUTHORITY_SCOPE' if 'INVALID_AUTHORITY_SCOPE' in failures
               else 'MALFORMED_PROVENANCE_ENVELOPE')


class StructuralContract(iam.IAMContract):
    schema_version: Literal['trust02.1'] = 'trust02.1'

    @model_validator(mode='before')
    @classmethod
    def strict_flags(cls, value):
        _flags(value)
        return value


class TrustBinding(StructuralContract):
    trust_domain_id: UUID
    deployment_id: UUID
    tenant_id: UUID
    deployment_type: Literal['SELF_HOSTED_ENTERPRISE', 'MANAGED_SAAS']
    customer_authority_id: UUID
    provider_identity_id: UUID | None
    _identifiers = field_validator('trust_domain_id', 'deployment_id', 'customer_authority_id')(_uuid)

    @field_validator('tenant_id')
    @classmethod
    def tenant(cls, value):
        if value.int == 0: reject('INVALID_TENANT_BINDING')
        return value

    @model_validator(mode='after')
    def separation(self):
        provider = self.provider_identity_id
        if ((self.deployment_type == 'MANAGED_SAAS') != (provider is not None)
                or provider is not None and (provider.int == 0 or provider == self.customer_authority_id)):
            reject('INVALID_DEPLOYMENT_IDENTITY')
        return self


class TrustAnchorReference(StructuralContract):
    """A public-material digest is a reference, not a key or independent trust pin."""
    anchor_id: iam.Identifier
    public_material_digest: iam.Digest


class RootCustodian(StructuralContract):
    custodian_id: iam.Identifier
    kind: Literal['CUSTOMER', 'PROVIDER_RECOVERY']
    anchor: TrustAnchorReference
    delegation_ref: iam.TenantReference | None

    @model_validator(mode='after')
    def delegation(self):
        if (self.kind == 'PROVIDER_RECOVERY') != (self.delegation_ref is not None):
            reject('INVALID_PROVIDER_DELEGATION')
        return self


class RootTrustPolicy(StructuralContract):
    schema_version: Literal['trust02.1']
    binding: TrustBinding
    root_policy_id: iam.Identifier
    root_policy_version: Counter
    required_quorum: Annotated[int, Field(ge=2, le=2)]
    custodians: tuple[RootCustodian, ...]

    @field_validator('custodians', mode='before')
    @classmethod
    def three_custodians(cls, value):
        if type(value) is not tuple or len(value) != 3:
            reject('INVALID_QUORUM_CONFIGURATION')
        return value

    @model_validator(mode='after')
    def distinct_custodians(self):
        for values in ((c.custodian_id for c in self.custodians),
                       (c.anchor.anchor_id for c in self.custodians),
                       (c.anchor.public_material_digest for c in self.custodians)):
            if len(set(values)) != 3: reject('DUPLICATE_CUSTODIAN')
        providers = tuple(c for c in self.custodians if c.kind == 'PROVIDER_RECOVERY')
        if len(providers) > 1 or providers and self.binding.deployment_type != 'MANAGED_SAAS':
            reject('INVALID_PROVIDER_DELEGATION')
        for custodian in providers:
            if custodian.delegation_ref.reference_id.int == 0:
                reject('INVALID_PROVIDER_DELEGATION')
            if custodian.delegation_ref.tenant_id != self.binding.tenant_id:
                reject('INVALID_TENANT_BINDING')
        object.__setattr__(self, 'custodians', tuple(sorted(self.custodians, key=lambda c:c.custodian_id)))
        return self


class TimedDescription(StructuralContract):
    issued_at: datetime
    expires_at: datetime
    _times = field_validator('issued_at', 'expires_at')(iam._utc)

    @model_validator(mode='after')
    def window(self):
        if self.expires_at <= self.issued_at: reject('INVALID_TIMESTAMP')
        return self


class RecoveryProposal(TimedDescription):
    """Proposed transition only: references neither authorize nor execute recovery."""
    schema_version: Literal['trust02.1']
    binding: TrustBinding
    operation_id: UUID
    operation: RootOperation
    root_policy_id: iam.Identifier
    root_policy_version: Counter
    proposed_state_digest: iam.Digest
    checkpoint_ref: iam.TenantReference | None
    recovery_journal_ref: iam.TenantReference | None
    _operation_id = field_validator('operation_id')(_uuid)

    @model_validator(mode='after')
    def references(self):
        if self.operation != 'bootstrap' and self.checkpoint_ref is None:
            reject('INVALID_CHECKPOINT_REFERENCE')
        if self.operation == 'recover' and self.recovery_journal_ref is None:
            reject('INVALID_RECOVERY_JOURNAL_REFERENCE')
        for ref in (self.checkpoint_ref, self.recovery_journal_ref):
            if ref is not None and ref.tenant_id != self.binding.tenant_id:
                reject('INVALID_TENANT_BINDING')
            if ref is not None and ref.reference_id.int == 0:
                reject('INVALID_IDENTIFIER')
        return self


class ProvenanceEnvelope(TimedDescription):
    """Description of future evidence, not cryptographically verified provenance."""
    schema_version: Literal['trust02.1']
    binding: TrustBinding
    payload_id: UUID
    issuer_ref: iam.TenantReference
    subject_ref: iam.TenantReference
    source_ref: iam.TenantReference
    operation: Literal['issue-authority', 'revoke-authority']
    authority_scope: iam.PermissionScope
    authority_revision: Revision
    provenance_ref: iam.TenantReference
    root_policy_id: iam.Identifier
    root_policy_version: Counter
    _payload_id = field_validator('payload_id')(_uuid)

    @field_validator('authority_scope', mode='before')
    @classmethod
    def scope_flags(cls, value):
        try:
            _flags(value.model_dump() if isinstance(value, iam.PermissionScope) else value)
        except ValueError:
            reject('INVALID_AUTHORITY_SCOPE')
        return value

    @model_validator(mode='after')
    def bindings(self):
        for ref in (self.issuer_ref, self.subject_ref, self.source_ref, self.provenance_ref):
            if ref.tenant_id != self.binding.tenant_id: reject('INVALID_TENANT_BINDING')
            if ref.reference_id.int == 0: reject('INVALID_IDENTIFIER')
        if self.authority_scope.tenant_id != self.binding.tenant_id:
            reject('INVALID_TENANT_BINDING')
        return self


RECORD_TYPES = (RootTrustPolicy, RecoveryProposal, ProvenanceEnvelope)
