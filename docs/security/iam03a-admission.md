# IAM-03A — synthetic trusted admission, schema 1.0

Implemented 2026-11-12. Backend-only, pure, deterministic and non-executable.
No application dependency or production source registers this module. No operational
authentication, database reads, signatures, role provisioning, audit writes, network,
model execution, gateway dispatch or API enforcement is implemented.

## Trust architecture

`admit(authenticated, request, authority=..., at=...)` accepts an explicitly injected
`SyntheticAuthority.for_tests` source. It does not accept caller snapshots, trust
flags, issuer lists, approval flags or model records as request arguments. It obtains
records exclusively from that in-memory source, validates admission, constructs
IAM-02 TrustedVerification internally and calls the unchanged IAM-02 evaluator.

Three independently configured inputs are necessary for this test channel:

1. The exact authenticated identity object registered by trusted test setup.
2. A separate SyntheticOriginRegistry containing the exact authoritative snapshot
   object delivered through the synthetic source channel.
3. Independent IssuerAuthority anchors scoped to exact tenant, source and record
   types, with current validity and revocation state.

Matching content hashes, copied objects, provenance labels, role names and
`verified=True` fields do not register origin. Anchors cannot be supplied in snapshot
records; unknown fields fail closed. No authority is inferred from human or AI roles.
IssuerAuthority distinguishes SNAPSHOT, VERIFIER, ROLE_ASSIGNMENT, TEAM_MEMBERSHIP,
TEAM_SCOPE and APPROVAL authority. Duplicate issuer/source/type authority entries
fail closed; current snapshots cannot self-declare their issuer trusted.

**This is synthetic origin validation, not real-world source authentication.** The
registry is an independently injected in-memory object-identity channel, not a
signature, secret, unforgeable Python capability or operational trust anchor. Code
able to construct the source, replace its configuration or mutate Python internals
is inside the test trust boundary. Arbitrary application/model inputs must never
be mapped into those constructors. No production provider exists, and an unknown
provider is denied. A future production provider must establish authenticated origin
independently; copying this synthetic registry into production is prohibited.

## Contracts

All records reuse IAM-01 strict/frozen, extra-fields-forbidden schema 1.0 contracts
and remain executable=False:

- IssuerAuthority: tenant, issuer, exact source, record-type scopes, finite validity
  and revocation state. Maximum validity 300 seconds for this synthetic milestone.
- APIKeyState: independently sourced current API-key UUID, tenant, exact principal
  reference, active state, validity and revocation. No key value or hash is stored.
- RevocationState: tenant, state UUID, observed-at time and unique revoked references.
- AuthoritySnapshot: source/issuer/verifier, snapshot UUID, issue/expiry time, exact
  evaluation time, canonical request and operation digests, current API-key state,
  complete IAM-01 graph, explicit IAM-02 policy, issuance receipts, revocations and
  optional human approval. Explicit SYNTHETIC / TEST ONLY classification.
- AdmittedSnapshot: trusted principal/authentication, source/issuer/verifier,
  snapshot identity/digests, policy identity/digest, request/operation digests,
  correlation UUID, validity/evaluation time, assignment/membership/resource-scope
  references, revocation and approval references, complete target metadata/action.
- AdmissionOutcome and AdmissionAudit: separate admission/policy outcomes and
  sanitized audit-ready references. No durable audit or executable token.

Canonical serialization and digest validation reuse IAM-01, including bounded
collections, recursion and 64 KiB per-contract serialization. Records are not fetched,
expanded or silently truncated. All nested contracts and copied instances are
revalidated; duplicates, unsupported versions and malformed metadata deny.

## Authentication bridge

Existing AuthenticatedPrincipal(tenant_id, api_key_id), auth.py, API-key hashing and
FastAPI dependencies are unchanged. The synthetic source registers the exact trusted
authentication object; matching attributes in another object do not authenticate it.
The bridge reads only tenant_id and api_key_id and requires UUIDs. It maps
principal_id = api_key_id, then independently checks current APIKeyState ownership,
active/unrevoked validity and authoritative API_KEY_SERVICE principal state. The
IAM authentication reference must also equal that key UUID and use API_KEY method.
No permission or role is issued by this mapping.

This intentionally supports only API-key admission. HUMAN/SYSTEM/AI authentication
bridges are not implemented. Human approvers and control-plane issuers may appear
as independently sourced IAM records. The module does not import auth/db/config,
ORM models or FastAPI; tests register synthetic immutable authentication objects.
A future live bridge must supply the real authenticated object from protected code
and independently read current API-key ownership/revocation from an approved control
plane, with consistent authoritative role and resource records. Existing auth.py
checks key revocation but does not establish those IAM records or issuer authority.

## Freshness and revocation

Trusted evaluation time is required and must be timezone-aware. Snapshot validity
is at most 60 seconds; issuance in the future is forbidden (zero clock skew).
The evaluation time must exactly equal the snapshot's bound evaluation time.
Revocation observation age is at most 15 seconds and cannot be future-dated.
Issuer anchors and issuance evidence have maximum 300-second windows. Every
assignment, membership, issuer and acting principal is also validated by IAM-01
for current validity, revocation and graph consistency.

Missing/duplicate/conflicting revocation evidence, revoked principals, issuers,
verifiers, grants, memberships, scopes, receipts or approvals deny. An inactive or
revoked API key denies even if the IAM principal remains ACTIVE. Source-origin
registration covers the complete snapshot and revocation state together; changing
one field by making a copied object does not preserve that registration.

No live freshness retrieval, durable anti-replay cache or immediate revocation
promise exists. The exact request/correlation/operation/time binding rejects reuse
for a different request or evaluation time. Identical input repeated at the identical
supplied time yields the identical decision; this is not one-time consumption.
Copying or extending timestamps cannot authenticate a new source record. A future
live source must provide fresh, consistent revocation observations and enforce any
stronger replay/transaction guarantees independently.

## Exact binding and evaluation

Tenant validation precedes issuer/grant evaluation wherever a trusted tenant is
available. All snapshot/reference tenants must match. Anchors must match tenant,
source and issuer for the specific record purpose. IAM-01 validates bidirectional
memberships, record provenance, issuance hashes, current statuses and scope links.
The registered complete source bundle establishes synthetic provenance for tenant,
API-key, principal, resource, policy, approval and revocation records.

The request digest includes correlation UUID, operation UUID, action, target tenant/
UUID/type, executor, parameters digest and policy version. The independently bound
ProposedOperation digest additionally covers full authoritative resource metadata:
team, owner, classification and scope references. Substitutions fail before IAM-02.
Approval origin requires independent APPROVAL authority; IAM-01 checks exact operation,
resource, human identity, validity and separation. IAM-02 independently verifies
approver permissions, execution permission and all action/classification/team rules.
Missing approval can pass admission but IAM-02 then denies the requested operation.

Only IAM-02 determines policy allowance:

| Outcome | Meaning |
| --- | --- |
| ADMISSION_DENIED | Origin, identity, authority, freshness, graph or request binding failed; no usable admitted snapshot or policy decision returned. |
| POLICY_DENY | Admission succeeded; IAM-02 returned DENY. |
| POLICY_ALLOW | Admission succeeded; IAM-02 returned ALLOW; still not an executable capability. |

Unexpected evaluator errors fail closed as POLICY_FAILURE. No policy fallback,
role inheritance, retries, durable grants or dispatch path is introduced. Gateway,
disclosure, consent and explicit runtime eligibility remain separate requirements.
Real Ollama inference and live Wazuh remain blocked.

## Audit and verification

AdmissionAudit carries known trusted tenant/principal, correlation, action/resource,
policy/snapshot digests, issuer/verifier, evaluation time, admission status, stable
reason and optional IAM decision. Metadata not yet established is null. Admission
failures never echo exception text, raw authentication objects, keys, prompts or
source contents. POLICY_DENY retains IAM-02's specific sanitized denial reason in
its immutable policy decision. No existing append-only audit writer/hash changes.

Tests use deterministic synthetic fixtures for origin copies/digest spoofing,
authentication-object substitution, separate current API-key state, issuer/verifier
scope/revocation/expiry, graph conflicts, stale/expired/revoked memberships and grants,
revocation observations, exact request/operation/time/team binding, human approval
provenance, policy denial after admission, mandatory IAM-02 invocation, immutability,
canonical audit metadata and forbidden I/O/gateway dispatch. These tests cannot
prove operational authentication, source authenticity or prompt-injection immunity
of a real model.

Recommended separately approved IAM-03B: specify a real protected authority-provider
and authentication-admission integration boundary, with authenticated issuer
provenance, consistent revocation reads, least-privilege access and durable audit
requirements. Start with offline provider conformance tests; database/API/runtime
integration and provisioning need their own explicit authorization.
