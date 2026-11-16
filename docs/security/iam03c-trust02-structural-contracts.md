# IAM-03C-TRUST-02 structural trust contracts

2026-11-15. Limited offline implementation for self-hosted enterprise and managed
SaaS. **Structural validity never establishes identity, cryptographic trust,
currently trusted authority or an authorized operation.** All operational and
production deployment decisions remain NO-GO.

## Authorization and existing contracts

The owner's TRUST-02 instruction authorizes A01/A04 only as design assumptions
for this offline structural milestone. Customer authority is separate from provider
infrastructure; proposed recovery is two of three independent custodians. Optional
provider assistance requires explicit customer authorization. This code only
represents a delegation reference: it cannot establish that authorization.

A01/A04 production approval and verification remain pending; A02/A03/A05 remain
pending in full. The [approval register](iam03c-owner-approval-register.md) is
unchanged. Its earlier PENDING entries remain accurate for production. No key,
credential, database, production crypto, recovery ceremony or environment is approved.
The old handoff's task-specific scope is historical; this milestone's explicit
allowed paths govern these additions, without expanding any live approval gate.

[TRUST-01](iam03c-trust-contracts.md) remains the broader proposed architecture.
This implementation is a bounded subset, not implementation of its production
RootManifest/v1, RecoveryAuthorization/v1 or VerifiedAuthorityRead/v1. In particular,
its proposed signed frame, complete-state verification, runtime attestation,
external journal/checkpoint protocol and final execution gate remain unavailable.
No existing interface conflict or operational integration was required.

Reuse `iam/contracts.py:IAMContract`, Identifier, Digest, TenantReference,
PermissionScope and the aware-time normalization utility. Existing IAM-01 hashes,
role/action definitions, IAM-02 evaluator, IAM-03A admission and IAM-03B provider
interfaces are unchanged. The PostgreSQL adapter still yields no authoritative
snapshot; `is_current()` remains False. No new package import is added to any
operational path or compatibility export.

## Files and implemented types

All implementation paths below are within `services/api/app/iam/trust/`.

| File / type | Implemented structural meaning |
| --- | --- |
| `__init__.py` | Isolated package description; no automatic operational registration or exports |
| `contracts.py:StructuralContract` | Existing frozen/strict/extra-forbidden base, new schema family trust02.1, executable=False; numeric false aliases rejected |
| `TrustBinding` | Required trust-domain, deployment, tenant and customer-authority UUIDs, deployment type and explicit nullable provider UUID |
| `TrustAnchorReference` | Bounded anchor identifier and existing public-material Digest; no key bytes, private material or trusted pin |
| `RootCustodian` | Custodian identifier, CUSTOMER or PROVIDER_RECOVERY description, anchor reference and explicit nullable customer delegation reference |
| `RootTrustPolicy` | Policy identifier/version, exact binding, three distinct custodian IDs/anchor IDs/material digests and required quorum exactly two; no signatures or quorum verification |
| `RecoveryProposal` | Bounded root operation, operation UUID, policy/version, proposed state digest, checkpoint/journal references and finite issuance/expiry window; no recovery permission or journal I/O |
| `ProvenanceEnvelope` | Payload UUID, tenant-scoped issuer/subject/source/provenance references, operation, existing PermissionScope, bounded revision, root policy/version and finite issuance/expiry window |
| `denials.py` | StructuralCode and sanitized StructuralError; separate from IAM authorization reasons |
| `validation.py` | Explicit context/issuer-registry comparisons, revalidation and immutable StructuralAssessment with fixed STRUCTURAL_ONLY status |
| `canonical.py` | Bounded TRUST02-JSON-1 canonical bytes and strict canonical parsing |

Additional authorized files: `tests/iam/test_trust_structural.py` and this document.
No existing source, test, configuration, approval document, Git index or tracked
change is modified. No database/schema change is made.

Identifiers reuse the existing ASCII Identifier grammar where named; UUID fields
use UUID values with nil deployment/domain/tenant/customer identities rejected.
Policy versions are strict positive BIGINT-range integers; authority revisions are
strict nonnegative BIGINT-range integers. Revision zero describes a possible genesis
number only; it never confers privileges. Booleans, floats and numeric strings are
not counters. References use existing tenant UUID/reference UUID contracts.

`RecoveryProposal` purposes are bootstrap, rotate, revoke, recover, approve-profile.
Every non-bootstrap proposal requires a checkpoint reference; recover additionally
requires a recovery journal reference. The nullable fields must still be explicitly
supplied. All supplied references must match the binding tenant. These are symbolic
references, not verified checkpoint contents, existing files or freshness evidence.

Provenance operations are issue-authority and revoke-authority, protocol purposes
rather than new IAM permissions. Scope structure uses the unchanged IAM catalog,
resource/classification/team constraints and duplicate rejection. This does not
approve the restricted MVA-1 profile or enable any action, including catalog-valid
administrative actions. Source/profile/policy authorization remains future work.

## Structural validation and identity boundaries

`validate_structure(record_type, data, expected_binding=..., issuer_ids=...)` accepts
only the three top-level record types above. It revalidates supplied model copies
and constructed/nested instances, including extras hidden from model_dump. Immutable
results contain the validated record and fixed STRUCTURAL_ONLY status, with no
trusted, authorized, ALLOW, verified signature, execution token or snapshot result.
Constructors are Pydantic structural constructors; the boundary function supplies
sanitized structural errors and explicit context comparisons.

The caller must independently supply expected binding and issuer UUID registry.
Unknown issuer UUIDs reject. A registry match is **only structural registration**,
not authenticated identity, issuer scope, signature verification or trust. Comparing
an attacker-selected context with itself proves nothing. Canonical parsing alone
does not perform these context/registry comparisons; call validate_structure for
those checks. Neither function looks up a key, source, database or identity provider.

Self-hosted enterprise requires provider_identity_id=None; no vendor/root credential
or vendor identity is necessary. Managed SaaS requires a distinct, nonnil provider
identity, different from customer_authority_id. Deployment kind, trust domain,
deployment UUID, customer UUID and tenant must match the explicit expected context.
A provider platform identity conveys no tenant role, issuer permission or root right.

The candidate three-custodian structure permits at most one PROVIDER_RECOVERY
custodian, and only in managed SaaS with an explicit same-tenant delegation reference.
The other custodians remain customer descriptions. Customer-only SaaS recovery is
also representable. Provider-assisted self-hosted recovery is outside this bounded
profile. A CUSTOMER label cannot prove that a person is independent or controlled
by the customer. Distinct digests cannot prove distinct keys/custodians either.
Actual enrollment, delegation authorization, independence and custody require later
approved evidence. No universal vendor identity, default issuer or default tenant
exists in the contracts.

All expiry fields are required and timezone-aware with issuance strictly before
expiry. Aware instants normalize to UTC. No wall clock is read: structural validity
of the interval says nothing about its current expiry, freshness or revocation.

## Canonical serialization: TRUST02-JSON-1

This is a new **offline serialization profile**, not a production signature protocol.
It does not implement TRUST-01's proposed domain-separated signed frame or claim
production signature compatibility. Existing IAM canonical bytes and audit hashes
are unchanged.

- Supported top-level schema_version is explicitly required as trust02.1. Nested
  new records use the same fixed schema; nested reused IAM records retain 1.0.
- Sort object keys; ASCII JSON using standard escaping, compact separators, explicit
  nulls and all model fields, including fixed executable=False. No extra metadata.
- UUIDs serialize lowercase with hyphens. Named IDs and digests retain existing
  exact grammar. Aware times serialize UTC, six fractional digits and +00:00.
- Arrays represent tuples. Custodians sort by unique custodian ID; reused IAM scope
  sets keep their existing deterministic unique ordering. Duplicates reject.
- Integers remain strict bounded integers; no floats, exponent aliases, bool counters,
  NaN or Infinity. Invalid values never silently become valid contracts.
- `canonical_bytes(record)` revalidates before serialization; `parse_canonical(type,
  bytes)` rejects payloads over 65,536 bytes, duplicate decoded object keys, invalid
  ASCII/JSON, excessive nesting and any byte difference after strict reconstruction.
- The decoder converts only declared UUID/time field representations and JSON arrays
  to typed values; strict model validation follows. Alternative spellings, missing
  default/null fields, escaped semantic aliases, reordered keys, offsets, whitespace
  and duplicate keys cannot pass the exact canonical byte comparison.

Python construction expects typed UUID/datetime/tuple values; it does not accept
UUID/time strings or lists as substitutes. JSON parsing is the explicit bounded
wire-decoding entry point. Missing/unknown fields and unsupported versions reject.
Nested model input is bounded to depth 16 at the validation boundary. There is no
file loading, key discovery, signature algorithm negotiation or external dependency.

## Stable structural rejection codes

StructuralError contains only a StructuralCode value; no input, validation message,
source record, token, driver text or exception chain is exposed by the boundary.
Direct Pydantic construction remains ordinary local validation, not the sanitized
public boundary. Codes are new structural diagnostics, not additions to existing
IAM/admission denial enums or TRUST-01's proposed production TRUST_* reasons.

| Code | Structural rejection |
| --- | --- |
| MISSING_REQUIRED_FIELD | Required field absent |
| UNSUPPORTED_SCHEMA_VERSION | New or nested unsupported schema version |
| INVALID_IDENTIFIER | Invalid named/UUID identifier or root reference grammar |
| INVALID_DEPLOYMENT_TYPE | Unknown deployment kind |
| INVALID_DEPLOYMENT_IDENTITY | Missing/conflicting provider/customer identity combination |
| INVALID_DEPLOYMENT_BINDING | Deployment/domain/customer context differs |
| INVALID_TENANT_BINDING | Invalid or inconsistent tenant/reference binding |
| INVALID_ISSUER_REFERENCE | Malformed/unknown issuer or invalid explicit registry |
| INVALID_QUORUM_CONFIGURATION | Anything other than three custodians and threshold two |
| DUPLICATE_CUSTODIAN | Repeated custodian ID, anchor ID or material digest |
| INVALID_ROOT_POLICY_VERSION | Nonpositive, malformed or out-of-range version |
| INVALID_PROVIDER_DELEGATION | Missing, unsupported or contradictory provider-recovery description |
| INVALID_CHECKPOINT_REFERENCE | Malformed or required checkpoint absent/null |
| INVALID_RECOVERY_JOURNAL_REFERENCE | Malformed or required recovery journal absent/null |
| INVALID_TIMESTAMP | Invalid time, naive time or impossible interval |
| INVALID_AUTHORITY_SCOPE | Unsupported/malformed/duplicate scope claims |
| INVALID_AUTHORITY_REVISION | Invalid or out-of-range counter |
| UNSUPPORTED_OPERATION | Operation outside the structural purpose vocabulary |
| MALFORMED_PROVENANCE_ENVELOPE | Invalid shape, unexpected metadata, bypassed extra fields or non-scope executable claim |
| NONCANONICAL_REPRESENTATION | Invalid/duplicate/oversize JSON or byte alias |

Validation stages are explicit: expected context, candidate shape/models, candidate
binding comparison (tenant first), issuer registry. Field failures select the first
applicable code in StructuralCode declaration order, independently of input key
ordering. Numeric executable aliases are rejected in an earlier prevalidation stage;
if both scope and other numeric flags occur, scope flag failure takes precedence.
Canonical parse rejects JSON syntax/duplicates/size before model validation and
byte comparison. No code is an authorization decision or a cryptographic denial.

## Tests, compatibility and verification

The 98-case focused file covers immutable construction/nested mutation, round trips,
permuted sets/keys, missing fields, schema versions, strict counters and identifiers,
root/deployment/tenant confusion, issuer registry, quorum/anchor duplicates, recovery
references, scope catalog/metadata, timestamp/numeric/JSON aliases, model-copy extras,
provider separation and explicit delegation. Import/runtime guards prohibit network,
process, storage and crypto integration; operational source files must not import
this package. No production signature verifier exists or is invoked. Final boundary cases also
reject nil provider-delegation references, provider-as-issuer inference and identical
UUIDs presented under the other deployment model.

The unchanged established offline selection and the new focused file were
executed. Initial red collection failed because the new contracts did not exist.
Intermediate codec/fixture/diagnostic failures were corrected without weakening
assertions or changing any existing tests.

| Check | Result |
| --- | --- |
| Unchanged selected offline baseline | 1,936 passed in 80.25 seconds |
| Final focused structural file | 98 passed in 0.73 seconds |
| Selected existing IAM modules plus those 90 new cases | 492 passed in 20.33 seconds (402 existing IAM + 90 new) |
| Final selected regression plus all 98 new cases | 2,034 passed in 76.63 seconds; increase of 98 |
| Compilation of services/api, tests and scripts | Passed; caches redirected to /tmp/trust02-compile |
| Whitespace and source/index preservation | Passed; only the five package files, one test file and this document added |

Exact test invocations (Python selection avoids shell expansion and never discovers
unselected modules):

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -p no:cacheprovider tests/iam/test_trust_structural.py
```

The baseline used this runner without the final focused-file argument; the final
regression used it exactly as shown:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 - <<'PYCODE'
import json, subprocess, sys
selection = json.load(open('tests/offline-selection.json'))
raise SystemExit(subprocess.call([sys.executable, '-m', 'pytest', '-p', 'no:cacheprovider',
                                 *selection, 'tests/iam/test_trust_structural.py']))
PYCODE
```

Focused IAM used the same runner with `selection` restricted to existing manifest
entries starting with `tests/iam/`, plus the new focused file. The manifest itself
was never changed. Compatibility checks include its API route/OpenAPI regression,
audit, tenant, IAM policy/admission/provider, import compatibility and fake-session
PostgreSQL denial coverage. Preexisting file hashes and the Git index digest were
compared against the entry manifest; this also verifies unchanged IAM-01/02/03A/B,
adapter, routes, audit implementation and security configuration.

```bash
PYTHONPYCACHEPREFIX=/tmp/trust02-compile python3 -m compileall -q services/api tests scripts
git diff --check
```

New untracked files also receive explicit whitespace checks because git diff
--check alone does not inspect untracked additions. The 214 previously excluded cases are not selected; there is no unrestricted
pytest or database/service connection. Compilation writes caches outside the repo.

## Unimplemented guarantees and next authorization

This milestone does not verify signatures/quorum, issuer enrollment or authorization,
root trust pins, customer delegation, human authentication/session state, checkpoint
existence/completeness/currency, rollback, complete-state commitment, persistent
revisions, revocation races, audit atomicity or any protected execution. Structural
models and hashes cannot supply those guarantees. Fake or fabricated inputs never
become operational authority through this package.

A01 still needs production custody/threshold/algorithm/rotation/recovery and independent
journal/pin/witness approval. A04 still needs production proof framing, key delivery,
complete-state/projection verification and reviewed admission/gate contracts. A02
human identity, A03 isolated target/privileges and A05 schema/profile remain pending.
The existing approval register and database schema are unchanged.

Recommend a separately authorized TRUST-03 design/verification plan for the missing
independent anchor and verifier boundary, actual customer delegation evidence and
production signature/canonicalization choices. It must resolve the outstanding
production approvals before implementing real crypto, keys or recovery. Database
and final execution-gate work still require their separate IAM-03D/IAM-04 approvals.

**IAM-03C-TRUST-02: COMPLETE**  
**STRUCTURAL CONTRACTS: IMPLEMENTED**  
**A01: LIMITED OFFLINE SCOPE AUTHORIZED — PRODUCTION PENDING**  
**A04: LIMITED OFFLINE SCOPE AUTHORIZED — PRODUCTION PENDING**  
**A02/A03/A05: PENDING**  
**CRYPTOGRAPHIC ROOT TRUST: NO-GO**  
**DATABASE SCHEMA IMPLEMENTATION: NO-GO**  
**OPERATIONAL IAM: NO-GO**  
**PRODUCTION DEPLOYMENT: NO-GO**
