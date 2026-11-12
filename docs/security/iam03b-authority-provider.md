# IAM-03B — protected authority-provider conformance

Schema/interface version 1.0, offline development milestone, 2026-11-12.
No production provider, authentication dependency, endpoint, database connection,
role issuance, audit write, live model or gateway execution is enabled.

## Scope and interface

`iam_authority_provider.py` defines `AuthorityProvider` with just two read-only
operations:

- `read(authenticated, request, at=...) -> ProviderSnapshot`: obtain one complete,
  consistent authorization state for the exact operation.
- `is_current(epoch) -> bool`: check that the same authorization state is still
  current before and after IAM admission/policy evaluation.

ProviderSnapshot reuses IAM-03A AuthoritySnapshot for tenant, API-key/principal,
roles, assignments, memberships, resource metadata, policy, issuance, revocations
and approval. It adds provider UUID and a consistent-read epoch. Ten component
references (tenant, api_key, principals, roles, memberships, resources, policy,
revocations, issuance, approval) must each exist exactly once and match that epoch.
The approval component is required even when its value is absent, so absence must
be observed in the same read. Contracts are strict, frozen, versioned, bounded,
canonical and executable=False; they retain SYNTHETIC / TEST ONLY classification.

There are no write, grant, membership, approval or provisioning methods. This is
not another identity service, admission system or permission engine.

## Protected construction and origin

Trusted test/application construction explicitly supplies:

1. ProviderRegistration, holding the exact already-authenticated object, provider
   object, separately configured ProviderAuthority and IAM-03A issuer anchors.
2. Independent SyntheticProviderOrigins registrations binding the exact provider
   object to the exact response objects delivered by its protected synthetic channel.
3. A ProtectedAuthorityBridge created with `for_tests`; no global/default source
   is registered by importing the module or through application configuration.

ProviderAuthority binds exact tenant, provider UUID, source reference, record-type
scope and finite validity/revocation. Maximum authority duration is 300 seconds.
Record scopes use IAM-03A's SNAPSHOT, VERIFIER, ROLE_ASSIGNMENT, TEAM_MEMBERSHIP,
TEAM_SCOPE and APPROVAL categories. Scope must cover the actual response purposes.
Issuers still need independent, exact tenant/source/record-type authority checked
inside IAM-03A. Ordinary roles or analyst tiers establish neither provider nor
issuer trust.

The request cannot select provider IDs, URLs, origin verifiers or anchors. Identity
selection comes exclusively from the protected authenticated-object registration.
Version 1.0 deliberately requires one complete authorization-state provider per
tenant. Multiple registered authorities for that tenant deny, rather than merge
records or choose a winner. Unknown, unregistered, expired, revoked or wrong-scope
providers deny before admission. Only the implemented SyntheticProvider is eligible
in this milestone; implementing the Protocol alone does not enable a live provider.

Response metadata, matching hashes, copied objects, claimed source identities and
verification flags cannot register origin. After independent provider-origin and
scope checks, the bridge feeds that state into IAM-03A's existing synthetic origin
channel. It cannot admit arbitrary caller records through that conversion.

**The registrations establish synthetic provenance only.** They are not production
signatures or proof of a real authenticated external source. Trusted Python setup
can construct these test fixtures, and code able to modify that setup is inside the
trust boundary. No cryptographic keys, operational credentials, production trust
anchors or real source verifier exist here. A real provider needs independent
operational provenance verification and a separately approved eligibility change.

## Authentication and exact request binding

The unchanged IAM-03A bridge maps principal_id = api_key_id only after the registered
authenticated object and independently supplied current APIKeyState agree on tenant,
key UUID, active/unrevoked validity and principal reference. IAM principal identity,
API_KEY authentication reference and tenant active status must also agree. No raw
key or key hash enters these contracts, and matching IDs alone grant nothing.

IAM-03A checks canonical request digest (including correlation, operation, action,
resource, executor, parameter digest and policy version) and exact ProposedOperation
digest, including the authoritative resource's team, owner, classification and
allowed scopes. Resource/action/policy/operation substitutions deny. The registered
provider response binds this state and epoch together; mixed reads are rejected.
A replacement policy must advance the provider epoch, even when the textual policy
version is unchanged. The response/state also carries canonical policy content,
which IAM-03A/IAM-02 bind by digest.

Existing auth.py, API-key hashing, FastAPI dependencies, tenant models and audit
writers remain unchanged. This milestone does not use actual ORM instances, open
sessions or verify any operational key record.

## Consistency, revocation and failures

The bridge checks epoch currency immediately before admission and again after
IAM-03A returns. If either check fails or raises, any result is discarded and an
ADMISSION_DENIED outcome is returned with no admitted snapshot or policy decision.
Epoch changes must cover identity/key/tenant status, memberships, role assignments,
resource scope/classification, policy, approvals, issuer/provider authority and
revocation state. Providers may not silently rewrite timestamps or reuse an epoch
for changed authorization state.

IAM-03A's maximum 60-second snapshot window, exact evaluation-time binding and
maximum 15-second revocation observation age are unchanged. All current grants,
issuers, principals, memberships and approvals retain IAM-01/02/03A validity and
revocation checks. Provider authority revocation in the response's revocation set
also denies. Conflicting/duplicate revocation references and mixed component epochs
deny; stale state is never combined with fresh data.

SyntheticProvider has deterministic response, epoch-sequence and failure fixtures,
plus invocation counters. Simulated TIMEOUT and FAILURE raise immediately; no real
clock waits, I/O, threads, retries or runtime deadline mechanism is implemented.
Only a literal True currency result is accepted. Provider exceptions never echo
raw exception text or source payloads.

The epoch checks are necessary optimistic consistency checks, not atomic execution
or immediate revocation guarantees. A change after the final check can invalidate
a decision. Independent processes, source configuration changes, transactional
revocation and later resource execution require future operational controls.
Identical request/time re-evaluation remains deterministic; no durable replay cache
or one-time token is introduced.

## Admission, policy and audit semantics

The only successful flow is protected provider resolution -> independent origin/
registration checks -> consistent state -> IAM-03A admit -> IAM-02 evaluate -> final
epoch check. IAM-02's permission mapping is not copied or changed. A provider response
alone cannot stand in for AdmissionOutcome; the bridge revalidates the returned
contract. IAM-03A retains snapshot validation and all approval requirements, and
IAM-02 alone decides whether the exact action is permitted.

Existing immutable AdmissionOutcome statuses are retained:

- ADMISSION_DENIED: provider registration/origin, state consistency, admission or
  evaluation failed. No usable policy allowance is returned.
- POLICY_DENY: admission succeeded but IAM-02 denied; e.g. missing execute approval
  or absent role permission. The exact policy denial remains in policy_decision.
- POLICY_ALLOW: admission and IAM-02 succeeded and the epoch remained current.
  This is non-executable and cannot bypass gateway/disclosure/runtime eligibility.

The bridge reuses AdmissionAudit rather than creating a competing audit schema.
Known trusted tenant/principal, exact request/correlation/action/resource and supplied
evaluation time are included on failures; unestablished issuer/policy/snapshot
metadata is null. Successful admission retains IAM-03A policy/snapshot digests and
issuer/verifier references. Stable existing reason categories distinguish invalid
input, unverified origin, invalid records, inconsistent revocation/current state,
and policy-processing failure. No raw keys, authentication objects, prompts, source
records or provider exception strings are logged or persisted. ProviderSnapshot
itself can be canonically serialized for later separately approved trace handling;
this module performs no persistence.

## Verification and next prerequisites

Focused conformance fixtures cover registration, spoofed metadata/digests/flags,
provider and issuer revocation, current API-key mapping, tenant/principal state,
missing/expired/revoked grants and memberships, resource/classification substitution,
request/operation/policy binding, epoch consistency, race checks, simulated timeout,
approval absence/revocation/reuse, policy allowance/denial, mandatory IAM-03A and
IAM-02 calls, immutable deterministic audit metadata and forbidden I/O/dispatch.
These are synthetic guarantees, not operational provider-authentication evidence.

Before database-backed IAM work is approvable, independently establish:

1. Separate explicit authorization and a verified isolated ai_soc_test target, with
   no protected ai_soc access and no operational credentials in fixtures/output.
2. Reviewed tenant-qualified IAM schema/constraints and authoritative sources for
   identities, current API-key ownership, grants, memberships, resources, issuers,
   policy and approvals. Current contract validity does not provision those records.
3. A real protected provider construction/origin-verification mechanism, scoped
   issuer authority and trusted authenticated-principal delivery; no model input
   may choose or populate those channels.
4. Read-only least-privilege access, coherent transactional reads and a monotonic
   authorization generation/revocation protocol, including policy replacements.
5. Explicit freshness, deadline, race handling and failure semantics, with separately
   reviewed durable audit integration preserving existing append-only hash chains.
6. Approved migration/recovery and isolated conformance plans if schema changes are
   required. No API enforcement, RLS or runtime execution is implied.

Recommended next milestone: separately approved offline database-provider design
and query/transaction conformance using injected sessions, before any database-backed
implementation, migrations, real API enforcement or operational IAM provisioning.
Real Ollama inference and live Wazuh remain blocked; IAM-03B stops here.
