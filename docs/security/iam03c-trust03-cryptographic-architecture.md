# IAM-03C-TRUST-03 cryptographic trust architecture

2026-11-15. **PROPOSED design only.** No algorithm, trust anchor, root ceremony,
verifier, checkpoint store or production approval is established by this document.
Self-hosted enterprise and managed SaaS remain operationally disabled.

Companions: [threat model](iam03c-trust03-threat-model.md) and
[verification plan](iam03c-trust03-verification-plan.md).
Sources: [D01–D04](iam03c-d01-d04-decision-package.md),
[approval register](iam03c-owner-approval-register.md),
[TRUST-01 contracts](iam03c-trust-contracts.md),
[TRUST-01 cases](iam03c-trust-verification-matrix.md),
[TRUST-02 implementation record](iam03c-trust02-structural-contracts.md),
[minimum schema](iam03c-minimum-authority-schema-review.md),
[schema proposal](iam03c-authority-schema-design.md),
[persistence threats](iam03c-authority-threat-model.md) and
[isolated DB plan](iam03d-isolated-verification-plan.md).

## 1. Recommendation and approval boundary

Recommend three customer-controlled independent offline custodians, with two
ordinary digital signatures over the same exact intent. This is application-level
quorum, **not** a new threshold-signature algorithm. Default to pure Ed25519;
provide a separately approved P-256/SHA-256 profile where validated hardware/module
requirements demand it. Do not negotiate algorithms with a request.

Retain two-of-three as the only initial root profile in both deployments. A future
configurable threshold requires a new reviewed policy/profile version, old-policy
quorum, owner approval and independently pinned activation. No runtime threshold
parameter, one-of-one fallback or automatic availability downgrade is recommended.
Routine root-authorized issuance uses separately scoped keys; root quorum is not
required for each metadata read and never substitutes for IAM policy or approval.

Customer-controlled roots, no vendor master root, and optional expressly delegated
provider assistance are design directions. A01/A04 were authorized **only as offline
structural design assumptions in TRUST-02**, not production approval. The choices
and refinements here require further explicit approval; they are not assumed trusted
inputs. A02/A03/A05 remain pending. Existing approval records remain untouched.

## 2. Established source facts and compatibility assessment

Paths below refer to actual code, not proposed schema facts.

| Existing source / symbols | Established boundary and design consequence |
| --- | --- |
| `services/api/app/iam/trust/contracts.py`: TrustBinding, RootTrustPolicy, RootCustodian, TrustAnchorReference | Strict immutable descriptions; fixed three custodians/two threshold; distinct reference digests do not establish independent people, keys or signatures |
| Same file: RecoveryProposal, ProvenanceEnvelope | Finite aware time windows, explicit checkpoint/journal references, scope/revision and issuer/subject/source binding; no authenticated issuer, current state or recovery approval |
| `services/api/app/iam/trust/canonical.py`: canonical_bytes, parse_canonical, MAX_PAYLOAD_BYTES | TRUST02-JSON-1 ASCII sorted compact JSON; exact re-encoding; duplicate decoded keys rejected; 65,536-byte limit; no signing frame |
| `services/api/app/iam/trust/validation.py`: checked, validate_structure, StructuralAssessment | Model-copy/extras revalidation, explicit structural context/issuer registry; result fixed STRUCTURAL_ONLY; registry is not a trust-anchor store |
| `services/api/app/iam/trust/denials.py`: StructuralCode | Twenty structural diagnostics, no crypto or IAM ALLOW |
| `tests/iam/test_trust_structural.py` | Fixtures cover canonical aliases, immutability, SaaS boundaries, duplicate references and no operational import/I/O; they do not test signatures |
| `services/api/app/iam/contracts.py`: canonical_bytes, contract_digest, validate_snapshot, ApprovalRecord | Existing record hashes/graph/approval semantics must remain byte-for-byte unchanged |
| `services/api/app/iam/admission.py`: admit, SyntheticAuthority, SyntheticOriginRegistry | Exact synthetic-only admission; production evidence cannot enter by relabeling or registering DB objects as fixtures |
| `services/api/app/iam/authority_provider.py`: ProtectedAuthorityBridge, ProviderSnapshot | Synthetic source and coherent epoch checks are not crypto provenance or operational enforcement |
| `services/api/app/iam/postgres_authority.py`: PostgresAuthorityProvider.read/is_current | Reader cannot construct authoritative snapshots; currency always False; preserved dedicated read rollback/caller close |

**Compatibility finding:** TRUST-02 bytes can be embedded unchanged in a separate
versioned signing wrapper. Their present format is insufficient as a complete
production signed protocol: it lacks domain framing, signatures/public keys,
independent root pins, environment/incarnation, issuer-purpose authorization and
current checkpoint/revocation evidence. Its structural issuer registry authenticates
nothing. No incompatible TRUST-02 change is necessary for this proposal; existing
records remain structural forever, even when their bytes appear inside a proof.

New RootManifest/transition/issuance/checkpoint sidecars must describe missing
production evidence. They are not new role/grant models and must reuse existing
IAM payload hashes/scopes. Neither RootTrustPolicy nor RecoveryProposal is silently
promoted into its proposed verified counterpart. Interoperability and production
signing suitability remain unverified pending the future cases.

## 3. Root enrollment, independent custody and bootstrap

The trust domain is customer-owned; the deployment and environment are explicit
scopes within it. Initial pins must be installed through a separately approved,
owner-authenticated out-of-band ceremony, not a PostgreSQL row, API claim, Git
file, IdP administrator claim or root signature that chooses its own verifying key.

The ceremony inventory must bind each named person to one custodian ID, key ID,
public-key encoding/fingerprint, allowed algorithm, device/custody location and
incident/replacement route. Confirm public fingerprints through two independent
channels and proof of key possession over a fresh enrollment challenge. Neither
fingerprint matching nor possession proves ownership without this owner identity
process. Never bootstrap root identity through an IdP whose authority depends on
the root being installed. Record nonsecret owner approval and ceremony digests.

Three independently controlled devices/accounts/media and recovery locations are
required by the candidate policy. Separate people using one laptop, one unlocked
HSM session or one shared backup are not independent custody. Prefer hardware-backed
non-exportable keys where the chosen profile is supported; otherwise separately
protected offline media under an explicitly accepted risk model. Custodians review
tenant, deployment, operation, intent digest and proposed key changes on a trusted
signing path. A compromised common display can deceive two honest signers.

Outside PostgreSQL and its restore/admin boundary retain:

- Root private keys and recovery material; no routine application or vendor access.
- Authenticated current root/public-key manifest and minimum accepted policy/root
  generation pins, custodian mapping, algorithm/profile and issuer ceilings.
- Independent latest checkpoint/high-water mark and pending recovery journal.
- Owner approval/custody/recovery records and verifier build/configuration pins.

Public manifests may be distributed with DB records as evidence, but must match
these independent pins. Public keys are not secrets; changing their trusted meaning
is a privileged act. Root private keys, raw credentials and recovery codes are never
Git, audit, application configuration or DB fields.

## 4. Quorum and provider-assisted recovery

Quorum verification uses the **independently current old root policy**, not the
candidate policy's lower threshold. Select keys from its authenticated root set.
Require exactly two or three supplied entries, all valid for the identical frame;
reject any malformed, unknown, revoked, expired, duplicate or invalid extra signer
even if two others pass. Count distinct enrolled custodians, not signatures or key
aliases. Repeated key IDs/public material or two keys assigned to one person cannot
supply two votes. A missing signature is distinct from insufficient distinct quorum.
The signed root-set digest and current policy/version pin prevent stale-policy use.

Default three customer custodians avoids provider participation. An optional SaaS
variant needs a separately approved, signed customer delegation established while
two customer custodians can authorize it. It must name provider custodian/key,
exact deployment/environment/tenant, purpose, proposed destination/root digests,
expiry and revocation/checkpoint binding. TRUST-02's delegation_ref is only a pointer;
it is not that evidence. No platform-operator login or provider infrastructure key
qualifies, and no vendor key is shared as a universal recovery root.

Recommended scope refinement, still pending A01/A04: with two customer custodians
and one provider recovery custodian, the provider may count only for an exact
restore-to-approved-customer-state operation and at least one customer signature
is mandatory. Replacing custodians, changing root policy/keys, enabling issuers or
broadening permissions still requires both customer custodians. This purpose-specific
eligibility is a future signed-manifest restriction, not expressible or verified by
TRUST-02's generic quorum structure. If not approved/implemented, provider assistance
remains disabled. A provider cannot delegate authority to itself.

One lost/compromised key leaves two custodians needed for replacement. Two lost
keys cause loss of quorum; two compromised/colluding/coerced custodians defeat the
quorum's security. Shared devices/administrators reduce effective independence.
There is no safe automatic quorum reduction or cryptographic way to identify honest
signers after quorum compromise. Availability and these residual risks need explicit
owner acceptance. Break-glass is a separately governed recovery route, not a bypass.

## 5. Algorithm comparison and candidate profiles

Standards references are listed in section 12 for later review. No network lookup,
library/provider inventory, certificate validation or crypto benchmarking occurred.
These are established mechanism comparisons, not assertions of current certification.

| Mechanism | Properties / offline interoperability | Hardware / enterprise cost | Recommendation |
| --- | --- | --- | --- |
| Pure Ed25519 (RFC 8032) | Approximate 128-bit classical security; deterministic signing; 32-byte raw public key, 64-byte signature; explicit strict point/scalar and length validation by an established library | Library support is mature; actual HSM/token/module support and validation vary. A valid algorithm name does not certify an implementation | Initial candidate ED25519-PURE-1; no Ed25519ph/ctx substitution |
| ECDSA P-256 with SHA-256 | Approximate 128-bit classical security; widely interoperable; nonce quality is crucial. Require library deterministic nonce generation where supported, or approved module RNG | Common enterprise HSM support; encoding/low-S behavior must be checked with actual device/provider | Alternative P256-SHA256-P1363-LOW-S-1 after approved interoperability evidence |
| RSA-PSS with RSA-3072/SHA-256 | Approximate 128-bit classical security; established offline verification; larger 384-byte signatures and public keys | Often available in existing enterprise hardware, but more transport/custody/configuration complexity | Deferrable alternative; not an automatic fallback or initially accepted profile |

For Ed25519, sign the complete frame directly with pure Ed25519; do not prehash it
and call that Ed25519 or accept alternate curve/encoding variants. Require strict
library verification, including malformed/small-order/noncanonical key/signature
cases selected from published adversarial vectors. Do not write curve arithmetic.

For P-256, hash the exact frame once with SHA-256 using the established signature
API; do not double hash. Pin the named curve and public-key encoding (uncompressed
SEC1, 65 bytes), and signature encoding (fixed 64-byte r||s, each 32 bytes, canonical
low-S). DER is not an alternative wire encoding. Established library conversion
and any signer low-S normalization need device vectors; no permissive parser or
custom arithmetic. Hardware that cannot meet the profile requires a separately
reviewed encoding profile, not a verifier fallback.

If RSA-PSS is later approved, pin RSA-3072, SHA-256, MGF1-SHA-256, salt length 32,
trailer convention and exact key/signature representation. Reject PKCS#1 v1.5,
variable/automatic salt policy and attacker-selected parameters. Its key transport
encoding remains a decision to finish before that optional profile is implemented.

For Python, recommend evaluating the established PyCA cryptography asymmetric
APIs with a reviewed supported backend for the initial offline verifier; exact
package/backend versions, strict-verification behavior, dependency review and test
vector results must be approved before implementation. A hardware-backed profile
must use the selected module's supported signing/provider interface, with the same
fixed wire profile and independent verifier vectors. No package is installed,
imported, benchmarked or selected as FIPS-validated here; a library/provider mismatch
is a blocked profile, not a reason to implement signature arithmetic.

Algorithm agility means owner-approved root transition, versioned algorithm IDs,
distinct key purpose and overlap/retirement proof. No "try every algorithm", mixed
profile quorum, unsigned algorithm negotiation or rollback to an old accepted
profile. P-256/RSA signing depends on good entropy; Ed25519 also needs secure key
seeds. All candidates need protected generation and side-channel-safe maintained
libraries. None provides post-quantum security.

FIPS-sensitive deployments require a suitably validated **module**, approved mode,
key generation/import path, hardware/service boundary and actual deployment
configuration review. FIPS 186-5 describes ECDSA, RSA and EdDSA; it does not make an
arbitrary Ed25519 library validated. Prefer the P-256 alternative when the selected
validated hardware/module supports it. Obtain exact certificate/security-policy
and procurement evidence later; make no blanket FIPS-compliance claim now.

## 6. Canonical signed-message proposal

### 6.1 Immutable inner bytes

Keep TRUST02-JSON-1 exactly as implemented: ASCII compact sorted-key JSON, explicit
null/default fields, strict bounded integers, lower UUIDs/digests, UTC timestamps
with six fractional digits/+00:00, sorted unique semantic sets and exact re-encoding.
Existing IAM contract_digest and audit hashes also remain unchanged. Never parse,
modify/retimestamp and then claim an old signature authenticates the modified record.

The production wrapper must pin the structural schema AND canonicalization profile;
it cannot accept a new serializer or changed defaults under the same ID. Cross-language
vectors are mandatory. TRUST02 is not claimed to implement RFC 8785/JCS: its strict
BIGINT-range integers require exact integer parsers, not IEEE-754 rounding, and its
date/UUID/set rules are application rules. JS-like consumers need a lossless parser.

### 6.2 Exact wrapper and framing

Candidate protocol IAM-TRUST-SIGNED-1, canonicalization IAM-TRUST-ASCII-1. A canonical
body has exactly the fields in this table; per-purpose context is a closed schema.
All are signed. These are proposed specifications, not Python fields added here.

| Body field | Required meaning |
| --- | --- |
| protocol_version, canonicalization_id, signature_profile_id | Exact independently allowed IDs; no fallback/default negotiation |
| purpose | ROOT_POLICY, ROOT_TRANSITION, ISSUANCE or CHECKPOINT; identity/session proofs need a future separately approved purpose |
| binding | Exact TRUST-02 TrustBinding, including customer and nullable platform identity |
| environment_id, environment_kind | Independent nonnil environment UUID and TEST or PRODUCTION; pin together with deployment, never infer from hostname |
| root_policy_id, root_policy_version, root_set_digest | Current independently pinned policy/name/version and digest of exact authorized custodian/key/purpose/profile set |
| operation_id | Immutable intent UUID; idempotency is a later durable protocol, not a replay exemption |
| issued_at, expires_at | Required finite UTC interval; externally supplied protected evaluation time, not a local implicit now |
| payload_type, payload_hex, payload_sha256 | Exact closed payload type/version, lowercase hex of immutable canonical payload bytes and SHA-256 of those bytes; check consistency before signature verification |
| purpose_context | Closed required fields specified below; no generic metadata dictionary |

Candidate purpose-specific payload/context mapping:

| Purpose | Payload and additional signed context |
| --- | --- |
| ROOT_POLICY | Canonical RootTrustPolicy bytes; new RootManifest sidecar in purpose_context binds public key encodings/algorithms, custodian enrollment evidence, key lifecycle, issuer/verifier/checkpoint ceilings, source/incarnation, approved policy/profile/schema digests, current checkpoint and owner-approval references. Initial root requires independent ceremony pins; a self-signed manifest cannot create them |
| ROOT_TRANSITION | Canonical RecoveryProposal bytes; old manifest/policy/checkpoint, exact intent/request digest, next manifest/root-set/epoch/incarnation or deployment destination, reason code and proposed state digest. Require old-set quorum and new-set acknowledgement for rotation; both arrays sign the same frame |
| ISSUANCE | Canonical ProvenanceEnvelope bytes; exact issued IAM record digest/purpose, source/provider/incarnation, persistent revision/epoch, policy/profile/schema digests, original issuance evidence and bounded runtime projection digest/window where applicable. Root-authorized issuer identity and ceiling checked independently |
| CHECKPOINT | New closed AuthorityState/Checkpoint canonical payload, not an invented TRUST-02 record; source/incarnation, full-state/group-manifest digest, revision/epoch/event digest, audit prefix sequence/hash, checkpoint generation/previous digest and authenticated pending-intent identity. Explicit root/policy/schema/profile/environment binding |

The future key-map schema must define each anchor's public_material_digest as
SHA-256 of its exact profile-specific canonical public-key bytes, compared to the
unchanged structural reference. Key IDs are opaque identifiers, not proof. Define
root_set_digest over a separate closed canonical key-set record (binding, policy/
generation, custodian/key/public material, allowed profiles/purposes and lifecycle),
excluding its own digest and signatures. It must not hash an enclosing body that
contains root_set_digest. The independent manifest pin covers the full approved
manifest, including routine issuer ceilings; a matching root-key set alone cannot
approve a different manifest or extra issuer.

Transition wrapper policy/version/root-set fields identify the **old authorizing
set**. Proposed destination/new-set fields are separate purpose_context claims;
new acknowledgement signatures bind the same transition frame. A standalone
new ROOT_POLICY cannot declare itself current: independent pin activation must
verify the authorized transition and destination manifest digest first. No digest
cycle or mixed old/new authority interpretation is permitted.

Manifest sidecar and CHECKPOINT byte schemas/group-manifest inclusions must be
field-frozen under A01/A04/A05 before implementation of those purposes. The table
specifies their security requirements, not a completed wire schema. A first verifier
prototype may support only a field-frozen ROOT_POLICY test subset after separate
approval; unsupported purposes must reject. This is an outstanding implementation
gate, not permission to add arbitrary metadata or fabricate complete-state evidence.

For each purpose use its distinct fixed ASCII label, respectively
AI-SOC-IAM-ROOT-POLICY-1, AI-SOC-IAM-ROOT-TRANSITION-1,
AI-SOC-IAM-ISSUANCE-1, AI-SOC-IAM-CHECKPOINT-1.
The signed frame is the exact label followed by one NUL byte, eight-byte unsigned
big-endian canonical-body byte length, then that body's bytes. Length excludes
label/NUL/length bytes. Verify exact length, label/purpose agreement and no trailing
bytes. Hash the **whole frame** for the proof/audit frame digest; payload_sha256 hashes
only the separate inner bytes. Neither digest includes itself or signature arrays.

Proposed bounds: inner structural payload <=24,576 bytes, body <=65,536 bytes,
combined proof/complete-state assessment <=262,144 bytes, depth <=16 and <=3 root
signature entries. The narrower signable inner subset leaves existing TRUST-02's
65,536 structural limit untouched; an oversized structural record remains structural
only and cannot be silently truncated. These budget refinements need owner review
and future cap/cap+1 vectors. Larger state needs a separately approved design; no
partial-state acceptance to fit a budget. Routine issuer/checkpoint evidence uses
exactly one scoped signer; root purposes require quorum, with rotation acknowledgements
in a second separate <=3 array. All arrays count toward the combined byte budget.

### 6.3 Encoding, headers and unsigned data

Canonical body bytes are ASCII, hence a valid strict UTF-8 subset: no BOM, invalid
UTF-8 or raw non-ASCII. Keys and current identifiers are closed ASCII vocabulary;
reject decoded non-ASCII strings in the new wrapper, rather than normalize Unicode.
No NFC/NFKC/case-folding. Inner payload hex decodes to exact already-canonical bytes.
Future opaque Unicode identity fields need a separate explicit profile/version;
never normalize OIDC subjects as if they were names. Duplicate keys are checked
**after escape decoding**; escaped key aliases, numeric aliases, omitted nulls,
whitespace or alternate UUID/time spellings reject on byte comparison.

The wrapper's signature arrays contain only key_id, custodian_id where applicable,
algorithm_id and exact-length lowercase-hex signature bytes. They are outside the
signed body to avoid self-reference, but IDs/profile must match independently
selected manifest keys and the body's signed root-set/profile/purpose. No key URL,
embedded certificate chain or header can establish its own trust. Alias keys/public
material are rejected in the anchor map, not counted twice. Every supplied entry
must pass; there is no ignored extra signature. Old/new rotation arrays are distinct
and bind the same transition frame. Signatures/arrays are not IAM permissions.

Only explicitly allowed display/transport correlation data may remain unsigned;
it cannot affect tenant, issuer, algorithm, intent, subject, scope, expiry, audit
actor or trust outcome. Unknown signed fields/versions reject, even with a valid
signature. Unknown wrapper headers also reject. There is no unsigned critical flag.

## 7. Provenance-verifier boundary and failure stages

Proposed isolated, non-authorizing component; no code or process created now.

Inputs: bounded untrusted proof bytes; protected expected deployment/tenant/
environment/request; independently authenticated current anchor/key/policy view;
explicit evaluation time with uncertainty; current checkpoint/pending observations;
known purpose schema/profile. Dependencies are injected trusted composition inputs,
not caller-supplied verified booleans or network discovery from a payload.

| Stage | Evidence required | Failure / output boundary |
| --- | --- | --- |
| B1 Structure and bounds | Closed schemas, strict types, supported versions, no synthetic origin; early expected tenant/environment mismatch precheck | STRUCTURE_INVALID, LIMIT_EXCEEDED, SYNTHETIC_SOURCE or BINDING_MISMATCH; no key access or effect |
| B2 Canonical payload/frame | Exact inner/outer bytes, length/domain/digest/profile binding | CANONICAL_MISMATCH or DOMAIN_MISMATCH; no reserialization acceptance |
| B3 Anchor lookup | Protected current root manifest/policy pin and exact key purpose/profile | ANCHOR_UNAVAILABLE, POLICY_STALE or KEY_REVOKED; candidate cannot register its own anchor |
| B4 Signature | Established strict library, exact independently selected key/algorithm/frame | ALGORITHM_UNSUPPORTED, SIGNER_UNKNOWN or SIGNATURE_INVALID; no alternate algorithm/key search |
| B5 Quorum and issuer scope | Distinct enrolled eligible custodians or exact routine signer purpose/ceiling; valid customer delegation if provider participates | SIGNER_DUPLICATE, QUORUM_INSUFFICIENT or ISSUER_UNAUTHORIZED |
| B6 Full semantic binding | Recheck verified domain/deployment/environment/tenant/issuer/subject/operation/scope/source/policy content, not just outer IDs | BINDING_MISMATCH; one valid signature is never a role grant |
| B7 Currency/state | Fresh protected root/revocations/time, current external checkpoint/journal, full-state completeness and fresh primary head | TIME_UNTRUSTED, EXPIRED, REVISION_STALE, CHECKPOINT_CONFLICT, RECOVERY_INCOMPLETE, ROLLBACK_DETECTED or STATE_INCOMPLETE |
| B8 Evidence handoff | Immutable digest-bound verified content, source/verifier profile, exact assumptions/as-of observation and independent proof evidence | Non-executable VerifiedProvenanceEvidence proposal, never ALLOW or authority mutation |

Names above are **proposed private verifier reasons**, not new implemented enums
or changes to TRUST-02's twenty codes, existing IAM reasons or TRUST-01 diagnostics.
Within each stage freeze reason precedence for combined faults before coding;
binding prechecks never expose a foreign tenant's key inventory. Lookup may reject
known-revoked/stale pins before signature math. Post-signature checks re-establish
all claimed bindings. Failed time/state branches cannot return current evidence.

A genuinely offline verifier may output only a SignatureEvidence diagnostic bound
to exact bytes/key/context when current state cannot be independently established.
It cannot assert B7 passed. No chain of structural/synthetic fixture results may be
converted to production evidence. Evidence is immutable data, not an object-identity
capability or a public trusted=True assertion; future production composition must
authenticate the verifier source and validate the evidence again at its boundary.

The verifier does not assign roles, create issuers, approve/recover operations,
mutate records, fetch arbitrary URLs or execute responses. Library/provider/version
and build/configuration are pinned and reviewed later; malformed inputs yield fixed
sanitized codes without raw payload/key/driver messages. Bounded resource use and
crash isolation are required. A separate process reduces parser blast radius, but
same-host administration is not independent trust against a compromised host.

A future reviewed production admission entry point must authenticate evidence,
reuse unchanged IAM graph/scope/issuer/request/approval checks and IAM-02 evaluation,
then require a separately implemented execution gate. Never feed it through
SyntheticOriginRegistry/for_tests. No HUMAN principal is forced through api_key_id.
A02 identity/session proof and A04 bridge evolution remain blocked. Existing
admit, providers, API routes, authentication and is_current are unchanged.

Audit verification/denial/root lifecycle events with bounded tenant/actor/intent,
frame/key/policy digests, outcome and protected time/observation refs, never private
keys, raw signatures/payloads, secrets or unauthenticated foreign-tenant actors.
Offline reports remain diagnostics until a trusted emitter supplies attribution.
Authority/audit atomicity remains the existing future transaction design; crypto
verification itself cannot guarantee that an audit record was committed.

## 8. Key lifecycle and recovery

| Lifecycle | Proposed requirements and fail-closed response |
| --- | --- |
| Generation | Separately authorized offline ceremony; established library/HSM approved generation and RNG/seed handling; unique root/issuer/checkpoint/verifier/test/tenant keys. Never derive a universal customer root from a provider master secret |
| Distribution | Authenticated public manifest with algorithm/key encoding/purpose/custodian/current pin; fingerprint matched out of band; no trust-on-first-use from DB or request |
| Routine issuance | Root-authorized bounded tenant/source/purpose/role ceiling, finite validity, current key lifecycle and authenticated issuer identity; no self-escalation or raw verifier secret in snapshots |
| Rotation/replacement | Old eligible quorum signs exact transition; new keys acknowledge identical frame in separate array; independent pin activation and checkpoint publication; retired versions never become current again. Root generation/revision never reset |
| Revocation | Exact key/custodian/issuer and dependent receipt scope, signed incident/transition, durable epoch/revision/checkpoint update and atomic audit. Suspend new evidence/gates during incomplete propagation; old signatures may remain historical but cannot establish current authority |
| Expiration | Explicit valid interval and protected clock/uncertainty; no automatic renewal or signature retimestamp. Existing runtime snapshot/revocation/issuer ceilings remain unchanged |
| Backup | Separately controlled encrypted custody backup, tested inventory/recovery process and independent pin/checkpoint copies. Backups do not create additional custodians; avoid all shares/devices in one administrative failure domain |
| Recovery | Authenticate exact incident/intent/current independent checkpoint and new state/destination. Two eligible uncompromised custodians authorize the bounded operation, not an ordinary IAM admin login. No new roles, revoked-right resurrection or counter reset |
| Quorum unavailable/compromised | Quarantine. If no trustworthy independent quorum remains, existing crypto cannot bless its replacement. A separately approved owner-authenticated re-establishment ceremony, incident evidence and fresh independently pinned root/incarnation are mandatory; otherwise remain unavailable |

Recovery can inspect independent public manifests/checkpoints and owner records
while PostgreSQL is unavailable, but cannot declare the restored DB complete or
current until separately verified against them. Restoring keys/database does not
restore authority automatically. A migration/recovery transition must name old and
new deployment/environment/incarnation, checkpoint/state/policy digests and revoke
or fence the old deployment before the destination can execute. New-custodian proof
alone is not authorization to change customer trust.

## 9. Rollback resistance and transaction limits

Revisions in PostgreSQL, signatures on old rows, a hash chain or signed checkpoint
alone do **not** detect replay of an entire old image. A separately current,
rollback-resistant high-water mark is essential. A signature authenticates an old
checkpoint's content; it does not prove that checkpoint is latest.

Candidate profiles requiring owner acceptance:

- Self-hosted, limited-host threat model: protected off-DB pins, single-writer signed
  pending journal/latest checkpoint, independently administered backup/storage.
  Customer accepts that compromise/co-restore of host, pins and journal defeats
  rollback detection. A local file or hardware signing key is not a monotonic store.
- Stronger/SaaS candidate: customer-controlled or independently administered witness
  outside provider DB/backup administration, serializing compare-and-append against
  the previously pinned checkpoint and retaining independently protected high-water
  state. Customer authentication of witness identity/current head is required.
  Availability partitions fail closed. Witness compromise/co-rollback is still a
  stated trust assumption, not solved by another signature on an old head.

Recommend independent customer/witness storage for SaaS if provider-admin compromise
is within the required rollback threat model. Witness role does not assign grants:
it authenticates an authorized transition chain/state commitment. Full-state assembler
and signed mutation source must be trusted independently of DB rows; a witness
blindly signing caller-provided subsets proves neither completeness nor authorization.
No witness service or full-state assembler exists in the repository.

Retain the prior publication protocol: serialize writers; verify latest root/head/
checkpoint; durably persist signed pending intent **before** authority DML; commit
authority/revision/event/audit atomically; verify commit, publish/fsync independent
next checkpoint; clear/fsync pending; only then acknowledge completed mutation.
No atomicity across DB and external storage is claimed. A required missing,
unavailable, inconsistent or pending journal denies new current evidence/gates.
Missing operation/old head after uncertain commit is ambiguous with restore; do not
clear pending automatically or assume rollback. Independent incident recovery is
required. Equal revision with different authenticated state/head is a fork/conflict.

Complete-state digest includes all authority records, required existing tenant/key/
resource identity and revocation facts, typed objects and retained tombstones, not
just requested grants. Exclude audit rows, signature/self-hash fields and external
journal/checkpoints to avoid cycles; an outer event binds the existing audit prefix
sequence/hash and revision. It does not prove a later unrelated audit tail survived.
A04/A05 must freeze exact row groups/encodings before implementing state verification.

Observe a fresh committed primary head separately from the coherent read snapshot.
Old read R, fresh head R+1 matching latest checkpoint R+1 is **REVISION_STALE**, not
rollback. Fresh primary behind independently current R+1 is ROLLBACK_DETECTED.
Unknown primary/source, partial data or missing completeness proof denies.

Final DB execution requires the shared tenant/head lock protocol through commit,
fresh authority/session/revocation checks and atomic action/audit. If revocation
completed before gate ordering, stale work denies; a gate already ordered first may
finish before revocation is acknowledged. A single earlier revision check cannot
promise immediate revocation. Dispatching workers must recheck; database locks do
not control remote side effects. External execution remains disabled without a
separate fencing/cancellation design. UNKNOWN commit outcomes require reconciliation,
not blind retry or a claim that no effect occurred.

## 10. Tenant, deployment and environment isolation

All root/issuer/policy/recovery/checkpoint frames bind trust domain, customer,
deployment kind/UUID, environment kind/UUID, tenant, root policy/version/set and
purpose; issuance additionally binds subject/source/operation/scope/revision/epoch.
No wildcard root for all customers, issuer key shared across tenants, platform-to-
customer identity substitution or inference from key/API ownership is recommended.
Independent expected context is required before lookup and after signature validation.

Self-hosted clones, SaaS tenant changes, TEST-to-PRODUCTION, enterprise-to-SaaS and
disaster restore are not equivalent identities. Legitimate moves need a signed
explicit source-to-destination transition plus independent destination enrollment,
state/checkpoint transfer verification and old-source fencing. Copying root files,
changing a hostname or replaying valid signatures is insufficient. Root policy
controls whether retaining the trust domain is permitted; deployment/environment
and incarnation changes are explicit, never an automatic rekey/reset fallback.

SaaS administrators retain platform infrastructure identity only. Customer signatures
cannot be fabricated by that identity and policy grants no evidence/response rights
from it. **This is not cryptographic data confidentiality against a provider controlling
the running application/host or plaintext DB.** Restricted administration, independent
signers/witness, runtime integrity and any customer-controlled encryption boundary
need separate threat-model/deployment approval. Do not market root signatures as
preventing a malicious infrastructure operator from bypassing its own runtime.

## 11. Unresolved decisions and next milestone

A01: named custody/independence, algorithm/device fit, provider-purpose restriction,
bootstrap/rotation/quorum-loss ceremonies and acceptable host/witness/restore risk.
A04: exact signed sidecar/purpose schemas, canonical vectors, verifier library/API/
source authentication, error precedence, complete-state commitment/budgets, runtime
projection, production admission and final gate. A02: real human/session source;
A03: exact disposable target/roles and guarded harness; A05: restricted schema/FKs/
profile. No pending item is approved by this design.

No incompatible code change or missing source blocks this documentation milestone.
Unfinished wire schemas and independent-source choices **block cryptographic
implementation**, not permission to invent them. If frozen schemas later require
changing existing IAM semantics/bytes, stop for a new compatibility decision.

Recommend a separately authorized TRUST-04 specification freeze: approve the first
signature profile, independently supplied anchor/verifier interfaces, exact supported
purpose fields and published-vector plan. Only after its implementation gate is
satisfied may an explicitly authorized offline verifier use published test material;
real root keys, environment setup, recovery or operational wiring need separate gates.

## 12. Offline reference catalog and validation

Established primary references for future profile review (links not fetched in this
no-network milestone; no verbatim quotations or current validation-status claims):

- [RFC 8032 — EdDSA](https://www.rfc-editor.org/rfc/rfc8032): Ed25519 algorithms and vectors.
- [RFC 8017 — PKCS #1](https://www.rfc-editor.org/rfc/rfc8017): RSA-PSS parameters/encoding.
- [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979): deterministic ECDSA nonce generation.
- [RFC 8785 — JCS](https://www.rfc-editor.org/rfc/rfc8785): comparison only; TRUST02 is not JCS.
- NIST FIPS 186-5, FIPS 140-3 and SP 800-57 Part 1 Rev. 5: signature standards,
  module-validation boundary and key management; selected profile/module applicability
  must be checked during the separately authorized standards/dependency review.

Performed only local document/contract/reference/approval/link/whitespace and
preexisting-content/index preservation checks. All three local document link sets
and referenced existing symbols resolve; the plan maps 20 threats to 35 specified
cases and seven separate readiness gates. New-file whitespace checks supplement
git diff --check, which alone does not inspect untracked documents. The prior
98/2,034 test results are
historical; no pytest, compilation, cryptographic verification, key generation,
network, DB, Docker or identity/service access occurred here.

**IAM-03C-TRUST-03: COMPLETE — documentation only**  
**A01: PRODUCTION APPROVAL PENDING**  
**A04: PRODUCTION APPROVAL PENDING**  
**A02/A03/A05: PENDING**  
**CRYPTOGRAPHIC DESIGN: PROPOSED**  
**CRYPTOGRAPHIC IMPLEMENTATION: NO-GO**  
**DATABASE SCHEMA IMPLEMENTATION: NO-GO**  
**OPERATIONAL IAM: NO-GO**  
**PRODUCTION DEPLOYMENT: NO-GO**  
**NEXT STEP: Recommendation only**
