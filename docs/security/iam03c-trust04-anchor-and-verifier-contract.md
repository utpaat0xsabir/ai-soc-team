# TRUST-04 independent TEST anchors and verifier contract

2026-11-16. **PROPOSED FREEZE; no implementation or root establishment.**
[Wire specification](iam03c-trust04-root-policy-wire-spec.md),
[errors/vectors](iam03c-trust04-vector-and-error-matrix.md),
[G1 review](iam03c-trust04-g1-readiness-review.md).

## 1. Five different trust meanings

1. Untrusted signed claims are bytes and names; they cannot select/register keys.
2. ExpectedTestContext comes from explicitly registered test-harness composition,
   outside those bytes; matching it establishes context consistency only.
3. TestAnchorSnapshot comes from the separately selected read-only fixture source,
   with reviewed public key/pin provenance; its TEST designation is not production
   authenticity. The unit-test assumption is explicit and limited to that fixture.
4. SignatureEvidence reports that the pinned TEST keys endorsed the exact frame
   under the chosen verification profile. It cannot prove real-person independence.
5. Current operational authority requires additional authenticated production sources,
   live revision/revocation/checkpoint/identity and admission/final-gate enforcement.
   It is unavailable here and cannot be represented by SignatureEvidence.

No trusted=True/verified=True field, type name, DB row, object identity, signature
on a candidate key or fixture label turns (1) into (3) or (4) into (5).

## 2. Pure proposed interface and exact context

Conceptual signatures only, not code to implement now:

- TestAnchorSource.read(expected_context) -> immutable TestAnchorSnapshot or
  Unavailable. Called at most once, after bounded parse/context/canonical/domain/
  algorithm checks. No lookup using candidate key URLs or attacker-selected tenant.
- assess_root_policy(proof_bytes; expected_context, test_anchor_source) ->
  SignatureEvidence or SignatureRejection. No clock, filesystem, network, DB,
  environment/settings, role policy, audit writer, signer or callback dependency.

The harness registers one explicit TEST source and context. TestAnchorSource returns
preloaded immutable fixtures only; its selection is not a wire field and it cannot
perform discovery. No production implementation of this port is approved. New code
must not import operational IAM/provider/auth modules to identify fixture classes;
the protected input_classification is checked before parsing. Wrong runtime input
classes fail closed; none may become a production provider.

ExpectedTestContext is a closed canonical object with these **nine** required fields:

| Field | Type / value |
| --- | --- |
| context_version | expected-test-context.1 |
| classification | TEST_SIGNATURE_REQUEST |
| binding | Exact existing serialized TrustBinding, copied independently of proof |
| environment_id, environment_kind | U and TEST |
| operation_id | U, exact independently expected test intent |
| test_time | T, explicit protected fixture evaluation time, never implicit now |
| anchor_fixture_id | ID, exact registered TEST source fixture |
| input_classification | TEST_WIRE_FIXTURE; negative fixtures may supply SYNTHETIC_IAM or PRODUCTION_BOUNDARY to exercise rejection |

Type names U/ID/D/N/T and all canonical encodings come from the wire document.
Non-TEST input classification yields SYNTHETIC_SOURCE, not an operational fallback.
PRODUCTION environment yields DOMAIN_MISMATCH. Missing/invalid expected context
fails STRUCTURE_INVALID without key lookup or evidence. There is no default fixture,
tenant, issuer, trust domain, operation or time.

## 3. Exact TestAnchorSnapshot

All fields required; no arbitrary extra data. It is input to a TEST-only component,
not a serialized public authentication certificate. Canonical bytes count against
the anchor/combined budgets; caller-supplied opaque booleans are not accepted.

| Field | Type / meaning |
| --- | --- |
| snapshot_version | test-anchor-snapshot.1 |
| classification | OFFLINE_TEST_ANCHOR |
| fixture_id | ID, exact expected anchor_fixture_id |
| root_policy | Exact unchanged RootTrustPolicy, CUSTOMER-only, required quorum 2; its binding matches context |
| root_policy_payload_sha256 | D of root_policy's exact TRUST02-JSON-1 bytes, pins the complete inner policy |
| environment_id, environment_kind | U and TEST, exact expected context |
| root_generation | N, independently accepted TEST generation |
| root_set_digest, manifest_digest | Two separate D pins, computed from the approved fixture objects with the wire DAG |
| test_pin_ref | ID, exact independently registered manifest pin reference |
| signature_profile_id | ED25519-PURE-1 |
| allowed_root_purposes | Array exactly [ROOT_POLICY] |
| required_quorum | Integer 2 |
| custodians | Exactly three AnchorCustodian entries sorted by manifest_entry.custodian_id |
| pin_provenance | Exact PinProvenance object below |
| observed_at, valid_until | Two T fields; observed_at < valid_until; explicit observation window |
| root_status | ACTIVE or REVOKED; latter rejects every candidate |

Grouped rows denote separate fields: the snapshot has **19** fields. The source
must supply internally consistent root policy, fingerprints, key/pin maps and
fixture registration. Unknown/malformed/oversize/inconsistent source data or source
exception returns ANCHOR_UNAVAILABLE (a directly observed hard budget violation is
LIMIT_EXCEEDED). Neither source exceptions nor supplied key inventory are exposed.
There is no "accept candidate manifest as source" route.

Each AnchorCustodian has exactly manifest_entry, current_status, current_revoked_at.
manifest_entry is the complete independently approved ManifestCustodian object
from the wire document, including exact public bytes, enrollment, lifecycle and
anchor reference. current_status is ACTIVE or REVOKED; current_revoked_at is null
iff ACTIVE, otherwise T no earlier than manifest_entry.valid_from. A REVOKED signed
manifest entry cannot be made active by this observation. A current revocation may
be stricter than the pinned manifest; source inconsistency fails ANCHOR_UNAVAILABLE.
Any recorded signed/current revocation timestamp must be <= observed_at; the
observation cannot claim a future event already happened.

PinProvenance has exactly registration_ref:ID, artifact_sha256:D,
review_record_ref:ID and origin. origin is PUBLISHED_ALGORITHM_VECTOR or
PROJECT_FRAME_VECTOR. The referenced artifact is the independently reviewed key/
pin catalog or published vector, **not the containing snapshot's own bytes**.
Registration/review IDs are fixture provenance, not production owner approvals.
No actual approval record, reference or public key is invented here.

After source acquisition, compare exact context/fixture and independently pinned
policy/version/generation/root-set/manifest/full payload digest/test_pin_ref. Candidate
internal contradictions have already failed before lookup; a coherent but different
candidate policy/pin returns POLICY_STALE, for both older and unapproved newer sets.
Candidate keys must match the pinned material exactly, not merely a claimed ID.
Current root/key revocation is never overridden by signed ACTIVE. observed_at <=
test_time < valid_until is mandatory, but is a fixture freshness assertion only,
not a claim that a current production authority service was consulted.

## 4. ED25519-PURE-1 candidate acceptance profile

Use pure Ed25519 over the exact full frame, without application prehash, Ed25519ph,
Ed25519ctx, extra context or double hashing. A frame digest is output/audit binding
only and is not signature input. Public keys are exact raw 32-byte canonical
compressed Edwards points; signatures are exact 64-byte R||S. No PEM/DER/X.509,
base64, curve fallback, profile negotiation or try-another-key path.

The strict acceptance requirements for approved test material are:

- Canonical point encodings for public key A and signature R; on-curve points,
  canonical scalar S with 0 <= S < group order L; reject noncanonical encodings.
- A must be a nonidentity point of the prime-order subgroup. R must be in the
  prime-order subgroup; the identity is not rejected solely for being identity if
  the standard equation and all other requirements hold. Reject other torsion/
  small-order or mixed-order inputs. These are acceptance restrictions, not custom
  implementations of point arithmetic.
- Verify the standard pure Ed25519 equation on the exact frame, with pinned A;
  reject invalid signatures. Never relax acceptance to ZIP-215, a cofactor-only
  permissive variant, or a corpus's ambiguous "acceptable" status by default.
- Known malformed lengths/hex are STRUCTURE_INVALID during parsing; well-shaped
  points/scalars/equations failing the frozen strict profile are SIGNATURE_INVALID.
  Invalid fixture key material also blocks registration/implementation acceptance;
  do not trust a key constructor's length check as proof of point validity.

Recommend **PyCA cryptography** as a candidate, not a selected/installed dependency.
Expected API is Ed25519PublicKey.from_public_bytes followed by verify(signature,
full_frame): success has no authorization return; InvalidSignature means rejection.
Map malformed/provider/backend failures to fixed diagnostics, never raw errors or
fallback. API surface/behavior is a requirement to validate against the selected
version, not an assertion that those calls alone enforce all subgroup rules.

Before any implementation authorization, select exact supported package/backend
versions and distribution hashes, review license/advisories/support/API changes,
and approve dependency provenance. Later cryptographic acceptance must demonstrate
the strict positive/adversarial acceptance set and cross-implementation agreement.
PyCA/backend point acceptance may differ by version; if no established vetted API
can enforce the frozen acceptance set, **STOP for review**. Do not write curve math,
maintain a homemade bad-point blacklist or weaken the profile to make a test pass.
This unresolved compatibility evidence is an implementation acceptance gate.

Published sources to acquire only in a separately authorized future activity:
RFC 8032 section 7.1 vectors and the Wycheproof Ed25519 adversarial corpus; see the
vector document for provenance/selection and independent project-frame generation.
No source was fetched, library installed/imported, version security status checked,
key generated or cryptographic vector executed in TRUST-04. No FIPS validation is
claimed. P-256 and RSA-PSS are unsupported by this first verifier.

## 5. Quorum, lifecycle and exact outcomes

All three custodians and distinct public keys must correspond to the independently
registered customer-only root. Signature metadata is matched by exact custodian/key
pair; neither an entry's algorithm nor its key ID establishes trust. The candidate
cannot lower two-of-three. Duplication anywhere in candidate set/entries is a
SIGNER_DUPLICATE rejection, not deduplication. Duplicate/inconsistent source maps
are ANCHOR_UNAVAILABLE, not evidence about real custodians.

| Supplied signatures | Exact candidate result, assuming earlier checks passed |
| --- | --- |
| Zero | QUORUM_INSUFFICIENT; no crypto |
| One known eligible entry, regardless of its mathematical signature | QUORUM_INSUFFICIENT after metadata/time checks; no crypto, so invalid signature is not diagnosed |
| Two eligible valid entries | SignatureEvidence TEST diagnostic only |
| Three eligible valid entries | SignatureEvidence TEST diagnostic only |
| Two valid plus one invalid | SIGNATURE_INVALID; return no partial evidence even if first two verified |
| Duplicate custodian/key/material entries | SIGNER_DUPLICATE before known-signer/revocation/crypto checks |
| Reordered distinct entries | Same logical result; use sorted custodian order for checks/output, frame unchanged |
| Unknown custodian/key pair | SIGNER_UNKNOWN; no alternate key search or crypto |
| Any supplied revoked signer, or revoked root | KEY_REVOKED before quorum/crypto; do not ignore a third revoked entry |
| Malformed signer record/length/hex | STRUCTURE_INVALID during closed-schema validation |
| Consistent but different policy/version/root set/manifest | POLICY_STALE before signer checks or crypto |

Time requirements: finite canonical intervals, active source observation, root/body
window and supplied-key coverage; no current-time lookup. Revocation checks precede
TIME_INVALID. At least two eligible entries are required before any signature math.
With sufficient eligible entries, verify in custodian_id order; any failure rejects
all evidence. No ordering-dependent first-two shortcut. All supplied entries must
pass for success; no claim is made about mathematical validity of entries after an
earlier rejection stage. Metadata decisions use fixed code priority, never list order.

A signature proves possession/endorsement by a key, not independent people,
customer control or the correctness of a displayed intent. Customer enrollment,
custody and trusted signer display remain independent assumptions. Two compromised
customer keys can produce a valid test quorum; this verifier cannot detect collusion.

## 6. Smallest non-authorizing output

Success SignatureEvidence is a proposed frozen immutable object with exactly:

| Field | Type / fixed meaning |
| --- | --- |
| evidence_version | signature-evidence-test.1 |
| classification | TEST_SIGNATURE_DIAGNOSTIC |
| result | SIGNATURES_VALID_TEST_ONLY |
| executable | false |
| frame_sha256, payload_sha256, root_set_digest, manifest_digest | Four D fields bound to exact accepted data/pins |
| expected_context | Exact ExpectedTestContext, including independent operation/environment/fixture/test_time |
| anchor_fixture_id, test_pin_ref | Two ID fields matching the approved TEST source |
| signature_profile_id | ED25519-PURE-1 |
| signers | Sorted tuple of exact {custodian_id:ID, key_id:ID}, one per verified supplied signer, length 2 or 3 |

No ALLOW, AUTHORIZED, CURRENT_AUTHORITY, PRODUCTION_TRUSTED, verified/trusted bool,
issuer authority, role, permission grant, authority epoch, current checkpoint,
production principal authentication or executable capability is returned. Rejection
returns only SignatureRejection with rejection_version=signature-rejection-test.1
and one code from the error document. No partial evidence, arbitrary message,
foreign inventory, raw input/signature/key/exception or audit-success assertion.

Pure outputs can be fabricated by a caller; consumers must not treat the class or
constructor as an authenticated production verifier service. Existing IAM admission/
providers must not import or accept these outputs. A later service needs a separately
approved authenticated source, production evidence format, current-state verification
and admission/final-gate contracts. No conversion or signing of this TEST diagnostic
makes it production evidence. Unit-test pins are not synthetic IAM promotion.

## 7. Dependency and side-effect boundaries

Only approved strict parsing, unchanged TRUST-02 structure/canonical checks, SHA-256
and selected established Ed25519 verification APIs are contemplated in a later phase.
No roles, policy evaluation, mutation, key generation/signing, key discovery, audit
write, recovery action, checkpoint service, session/IdP, DB or operational import.
Root revocation is supplied TEST state, not fetched operational state. No production
source is required or invented for this purpose; absence of one still blocks all
production purposes. Private material must never enter this component or reports.
