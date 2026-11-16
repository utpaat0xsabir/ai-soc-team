# TRUST-04 ROOT_POLICY test wire specification

2026-11-16. **PROPOSED FREEZE**, profile ROOT_POLICY-TEST-1. Documentation only;
not an approved production protocol or implementation authorization.

Companions: [anchor/verifier](iam03c-trust04-anchor-and-verifier-contract.md),
[errors/vectors](iam03c-trust04-vector-and-error-matrix.md),
[G1 review](iam03c-trust04-g1-readiness-review.md).
Baseline: [TRUST-03](iam03c-trust03-cryptographic-architecture.md) and
[TRUST-02](iam03c-trust02-structural-contracts.md).

## 1. Scope and normative conventions

Existing code remains unchanged. This candidate supports only ROOT_POLICY,
ED25519-PURE-1 and environment_kind=TEST, for both structural deployment kinds.
All three custodians must be CUSTOMER. No provider-recovery delegation, issuer
ceiling, state/checkpoint, transition, recovery, identity proof or production purpose
is represented. ROOT_TRANSITION, ISSUANCE and CHECKPOINT are unsupported, not empty
trusted components. Signatures cannot activate a manifest or policy.

Every object below is **closed**: exactly its listed fields, all required including
nullable fields; no extra keys, aliases or extension dictionaries. Default injection
is forbidden in wire input. Numbers are strict integers, never bool/float/string.
Array multiplicity/order and cross-field comparisons are normative. Field errors
are mapped by the fixed stages in the error document, not by exception text.
Well-typed canonical spelling aliases are distinguished from malformed values below.

Primitive types:

| Type | Exact wire representation |
| --- | --- |
| ID | ASCII string matching existing iam.Identifier: `[a-z][a-z0-9_.:-]{0,95}` |
| U | Lowercase hyphenated UUID string, nonnil; exactly 36 ASCII bytes |
| D | Lowercase hex string, exactly 64 ASCII bytes, representing SHA-256 |
| N | Integer 1..9,223,372,036,854,775,807; shortest decimal, no leading zero/sign/exponent |
| T | Valid Gregorian UTC datetime, year 0001..9999, exactly `YYYY-MM-DDTHH:MM:SS.ffffff+00:00`; no leap seconds, Z, implicit zone or offset alias |
| H32 / H64 | Exactly 64 / 128 lowercase hex characters, decoding to 32 / 64 bytes |

JSON encoding rules are in section 5. No raw key, signature or fixture material is
generated or supplied by this specification. Primitive type/required/unknown-field
violations are STRUCTURE_INVALID. For UUID/time/hex values, an otherwise valid parseable
spelling alias (uppercase UUID/hex, equivalent aware offset or Z timestamp) is
CANONICAL_MISMATCH at the canonical stage; invalid UUID/nil, invalid calendar/naive
time, nonhex/odd/wrong fixed length is STRUCTURE_INVALID. Lowercase/UTC spelling
above defines acceptance, not normalization into acceptance. Well-typed wrong constants/bindings/digests have
specific later codes shown below. Reference values name proposed TEST artifacts,
not approvals that have already been granted.

## 2. Signed body — exact 17 fields

| Field | Type / allowed value and presence | Binding / validation and failure |
| --- | --- | --- |
| protocol_version | Required string IAM-TRUST-SIGNED-1 | Different well-typed value -> DOMAIN_MISMATCH |
| canonicalization_id | Required string IAM-TRUST-ASCII-1 | Different well-typed value -> CANONICAL_MISMATCH |
| signature_profile_id | Required string ED25519-PURE-1 | Different well-typed value -> ALGORITHM_UNSUPPORTED |
| purpose | Required string ROOT_POLICY | Other purpose, including future known purposes -> DOMAIN_MISMATCH |
| binding | Required exact TrustBinding wire object below | Must equal independent expected context and inner policy/manifest/key-set binding -> BINDING_MISMATCH |
| environment_id | Required U | Match expected TEST environment and manifest -> BINDING_MISMATCH |
| environment_kind | Required string TEST | PRODUCTION/other value -> DOMAIN_MISMATCH; never attempt production anchor lookup |
| root_policy_id | Required ID | Equal inner/manifest value; disagreement -> BINDING_MISMATCH; different from independent approved TEST policy -> POLICY_STALE |
| root_policy_version | Required N | Same internal equality, then exact independent approved TEST version; older AND newer unapproved versions -> POLICY_STALE |
| root_set_digest | Required D | Equal manifest value -> BINDING_MISMATCH if inconsistent; derived projection mismatch -> CANONICAL_MISMATCH; consistent but unpinned set -> POLICY_STALE |
| operation_id | Required U | Exact independently expected test intent UUID -> BINDING_MISMATCH; no execution or durable idempotency semantics |
| issued_at | Required T | Strictly before expires_at; compare explicit evaluation time and manifest key intervals; invalid interval -> STRUCTURE_INVALID, outside evaluation window -> TIME_INVALID |
| expires_at | Required T | Exclusive endpoint; evaluation requires issued_at <= test_time < expires_at; no implicit clock or grace period |
| payload_type | Required string RootTrustPolicy/trust02.1 | Other well-typed value -> DOMAIN_MISMATCH; never dispatch to another model |
| payload_hex | Required even-length lowercase hex string; decoded bytes 1..24,576 | Exact unchanged TRUST02-JSON-1 RootTrustPolicy bytes, parse and byte-compare; malformed model -> STRUCTURE_INVALID; byte alias/digest disagreement -> CANONICAL_MISMATCH; size -> LIMIT_EXCEEDED |
| payload_sha256 | Required D | SHA-256 of decoded payload bytes only; disagreement -> CANONICAL_MISMATCH |
| purpose_context | Required exact object: profile_id and manifest | profile_id string ROOT_POLICY-TEST-1; different value -> DOMAIN_MISMATCH; manifest closed schema below |

Binding object is the **exact serialized existing TrustBinding**, with these eight
fields, all present:

| Field | Type / constraints |
| --- | --- |
| schema_version | String trust02.1 |
| executable | JSON false, never 0 |
| trust_domain_id, deployment_id, tenant_id, customer_authority_id | Four separate U fields |
| deployment_type | SELF_HOSTED_ENTERPRISE or MANAGED_SAAS |
| provider_identity_id | null for self-hosted; U distinct from customer_authority_id for SaaS |

The table groups four fields in one row: eight is the exact member count. Structural
invalidity uses STRUCTURE_INVALID; valid binding unlike expected context uses
BINDING_MISMATCH. No ID is inferred from a hostname, key, tenant membership or
provider identity. TEST SaaS still requires three customer custodians.

## 3. Inner policy and RootManifest test subset

### 3.1 Existing RootTrustPolicy bytes

Do not change `services/api/app/iam/trust/contracts.py:RootTrustPolicy`,
TrustBinding, RootCustodian or TrustAnchorReference, or their serializer.
All model fields, including existing executable=False and nested schema_version,
are present in canonical bytes. RootTrustPolicy has exactly schema_version,
executable, binding, root_policy_id, root_policy_version, required_quorum and
custodians. Required quorum is integer 2. Custodians is exactly three entries, sorted
ascending by custodian_id; duplicate IDs/anchor IDs/material digests reject.

Each RootCustodian has exactly schema_version=trust02.1, executable=false,
custodian_id:ID, kind=CUSTOMER, anchor:TrustAnchorReference and delegation_ref=null.
Each TrustAnchorReference has exactly schema_version=trust02.1, executable=false,
anchor_id:ID and public_material_digest:D. Existing broader structural support for
PROVIDER_RECOVERY is not admitted by this narrower purpose; valid such input returns
DOMAIN_MISMATCH. A structural reference is not a key or endorsement.

### 3.2 RootManifest object — exact fields

The purpose_context.manifest is a **new proposed sidecar**, not an existing Python
model or a replacement for RootTrustPolicy. All these fields are signed as part of
the body. No routine issuer/checkpoint/state fields or arbitrary metadata are allowed.

| Field | Type / value and relationships |
| --- | --- |
| manifest_version | String root-manifest-test.1 |
| binding | Exact binding object in section 2; equal body and payload |
| environment_id, environment_kind | U and TEST, equal body/expected context |
| root_policy_id, root_policy_version | ID and N, equal body/payload |
| root_generation | N, equal independently pinned TEST root generation |
| signature_profile_id | String ED25519-PURE-1 |
| allowed_root_purposes | Array of exactly one string ROOT_POLICY |
| required_quorum | Integer 2 |
| custodians | Exactly three ManifestCustodian entries below, sorted ascending by custodian_id |
| test_pin_ref | ID naming an independently registered TEST pin fixture; candidate cannot select/register its own source |
| root_set_digest | D; computed from exact RootKeySet projection below |
| manifest_digest | D; computed excluding only this field |

Grouped rows mean separate fields. The manifest has exactly **14** fields. Constants
must match; profile/purpose failures map as body constants; incompatible manifest
version -> STRUCTURE_INVALID. Independent pin/version mismatch -> POLICY_STALE.
Claimed root_generation unlike pinned generation is POLICY_STALE, not automatic
activation. Wrong test_pin_ref with a known snapshot is POLICY_STALE; unavailable
registered snapshot is ANCHOR_UNAVAILABLE. Shape errors are STRUCTURE_INVALID.

ManifestCustodian has exactly these **12** fields:

| Field | Type / constraint |
| --- | --- |
| custodian_id | ID; equal corresponding RootCustodian ID |
| kind | String CUSTOMER |
| key_id | ID; equal corresponding payload anchor.anchor_id |
| anchor_ref | Exact existing TrustAnchorReference object, equal payload anchor |
| public_key_encoding | String ED25519-RAW-32 |
| public_key_hex | H32; exact canonical compressed public-key bytes; equal independent TEST anchor bytes |
| signature_profile_id | String ED25519-PURE-1 |
| status | ACTIVE or REVOKED |
| valid_from, valid_until | Two T fields, valid_from < valid_until |
| revoked_at | T or null; status=REVOKED iff nonnull, valid_from <= revoked_at < valid_until |
| enrollment_ref | ID; match corresponding independently registered TEST enrollment reference |

public_material_digest equals SHA-256 of the decoded 32 public-key bytes. Each
custodian, key_id, anchor_ref.anchor_id, public_key_hex and public_material_digest
is unique across all three entries. Custodian/key/anchor correspondence is one-to-one;
no aliases. Wrong internal correspondence -> BINDING_MISMATCH; duplicate identities/
material -> SIGNER_DUPLICATE. Malformed public-key length/hex is STRUCTURE_INVALID;
well-shaped cryptographically invalid material fails the strict profile checks.
The manifest cannot alter independent pin/key/enrollment data by claiming ACTIVE.

Candidate key windows must contain the entire body interval:
valid_from <= issued_at < expires_at <= valid_until, for every supplied signer.
Window inconsistency is TIME_INVALID. Revoked supplied signer is KEY_REVOKED,
regardless of the signed time. Historical observation does not establish current
production status. All three manifest records remain present when a slot is revoked;
only eligible signers count. No statement of real-person independence is inferred.

### 3.3 RootKeySet projection and digest DAG

RootKeySet is an exact **derived** canonical object with the fields:
key_set_version=root-key-set-test.1; binding; environment_id; environment_kind;
root_policy_id; root_policy_version; root_generation; signature_profile_id;
allowed_root_purposes; required_quorum; custodians.
Copy the latter ten fields verbatim from the manifest. custodian entries are the
entire exact ManifestCustodian objects, in the same sorted order. There are eleven
fields, no digest or signature field at this level.

Use IAM-TRUST-ASCII-1 encoding defined below for these sidecar objects:

1. For each public key: public_material_digest = SHA-256(exact decoded key bytes).
2. root_set_digest = SHA-256(canonical RootKeySet bytes), lowercase hex D.
3. manifest_digest = SHA-256(canonical RootManifest with only manifest_digest removed).
   root_set_digest stays included; test_pin_ref and all enrollment/lifecycle fields
   stay included. No digest includes itself. No signatures are in the manifest.
4. payload_sha256 = SHA-256(exact decoded unchanged TRUST02 payload bytes).
5. frame_sha256 = SHA-256(exact framed signed bytes, including label/NUL/length).

No hash truncation, salt or additional digest framing is introduced here. Type and
profile context are signed and independently pinned; these distinct digest fields
are not interchangeable. The DAG is key -> key set -> manifest -> body -> frame.
The independent snapshot pins both the derived root-set and full manifest digest,
not merely the public-key fingerprints. Test pin refs refer outward; no artifact
hash may depend on an artifact that embeds that hash. Provenance reference IDs
are opaque fixture names, not self-hashing fixture bundles.

## 4. Proof transport and unsigned signature entries

Input proof is bytes containing a closed JSON object with exactly frame_hex and
signatures. frame_hex is even-length lowercase hex of one complete signed frame.
signatures is an array of 0..3 entries, each with exactly:

| Field | Type / exact rule |
| --- | --- |
| custodian_id | ID; must map to the independently enrolled custodian |
| key_id | ID; exact independently pinned key for that custodian |
| algorithm_id | String ED25519-PURE-1; no request algorithm negotiation |
| signature_hex | H64; 64 decoded bytes, no DER/base64/alternate length |

No key material, certificate, URL, critical flag, diagnostic, metadata, source flag
or extra header is accepted in transport. Signature bytes/entries are outside the
signed body to avoid self-reference; their mapping/profile is checked against the
independent snapshot and the body's signed root set/profile. Reordered signature
entries are accepted; verification/output order sorts by custodian_id after duplicate
checks. Object keys use canonical ordering, but signature array order is retained
when checking transport encoding; no sorted-set claim for this unsigned array.

Transport is compact sorted-key ASCII JSON, exact re-encoding required. Any compact
array permutation is valid; whitespace/object-key aliases are CANONICAL_MISMATCH.
Duplicate decoded keys at any level are STRUCTURE_INVALID, never last-key-wins.
Transport bytes themselves are not signed; changing signature order does not change
the frame digest. Every supplied signature must verify; transport cannot extend
what is signed or manufacture an accepted key.

## 5. Canonical bytes and exact signed frame

IAM-TRUST-ASCII-1 for NEW body/manifest/key-set/transport objects means:

- ASCII-only bytes and decoded keys/strings; therefore a strict UTF-8 subset, no
  BOM or invalid UTF-8. No Unicode normalization/case-folding or non-ASCII escape
  aliases. JSON keys sort ascending ASCII. No optional whitespace or trailing newline.
- Strings use standard JSON escaping: only quote and backslash where required;
  other printable ASCII characters (0x20..0x7e) appear literally. No control characters
  are permitted in any valid schema string. No escaped slash or \u aliases.
- Exact true/false/null tokens where allowed; only false in inherited executable
  fields. Strict integers use ordinary shortest base-10 decimal; no sign, leading
  zero, decimal point, exponent, -0, NaN or Infinity. N can exceed 2^53: parser and
  serializer must preserve exact integers. IEEE-754/ordinary JS Number parsing is
  insufficient. This profile is **not RFC 8785/JCS**.
- Arrays have schema-defined order: manifest/key-set/payload custodian IDs ascending;
  signature transport order preserved; allowed_root_purposes singleton. Duplicate
  semantic IDs/material reject, never normalize/deduplicate into success.
- All constants, nulls and inherited fields are explicit. Reject unknown fields,
  omitted fields, unsupported schemas and all byte aliases after shape validation.
- TRUST02-JSON-1 payload is decoded/checked using its existing exact behavior; never
  re-encode it under the new sidecar profile and call those the original bytes.

The exact domain label is the 24 ASCII bytes AI-SOC-IAM-ROOT-POLICY-1:
`41 49 2d 53 4f 43 2d 49 41 4d 2d 52 4f 4f 54 2d 50 4f 4c 49 43 59 2d 31`.
Append one 00 byte, then an unsigned eight-byte big-endian length L of canonical
body bytes only, then exactly L body bytes. Signature input is this entire frame,
not its SHA-256 digest. Header length is 33 bytes; maximum frame is 65,569 bytes.
No trailing bytes, second frame, alternate label, NUL or length interpretation.
Label/purpose/protocol disagreement is DOMAIN_MISMATCH. After hard size checks,
read the fixed header positions regardless of claimed label. A frame shorter than
33 bytes, L=0, or fewer than L body bytes returns DOMAIN_MISMATCH before attempting
a partial body parse; later stages are unobservable. A declared L above cap is
LIMIT_EXCEEDED first. If a complete L-byte body can be extracted, preserve a wrong
label/NUL or trailing-byte flag and reject it at the domain stage after earlier
readable-body checks. Never parse the trailing suffix as a second message. Thus
wrong tenant in a readable body precedes a trailing-byte fault; no trailing bytes
are ever accepted. This is a deterministic extraction exception to the staged table.

## 6. Resource accounting — candidate fixed limits

| Budget | What counts / enforcement |
| --- | --- |
| Inner signable payload 24,576 bytes | Decoded payload_hex bytes only; check hex length before allocation, before structural parse; cap+1 -> LIMIT_EXCEEDED |
| Body 65,536 bytes | Exact canonical body bytes including hex expansion and all manifest/context fields. payload_hex alone counts 2x decoded bytes plus JSON string syntax. Check declared L before body parse/allocation |
| Frame 65,569 bytes | 24 label + 1 NUL + 8 length + body; no separate uncounted suffix |
| Combined assessment 262,144 bytes | Raw transport bytes + decoded frame bytes + decoded payload bytes + canonical TestAnchorSnapshot bytes + canonical ExpectedTestContext bytes + decoded signature bytes (64 per supplied entry). No double count of key bytes already in snapshot. Check raw cap before parse, then each added decoded/input length before allocation/use |
| Anchor snapshot 16,384 bytes | Exact canonical independently supplied TEST snapshot; part of combined budget, no unbounded registry |
| Expected context 4,096 bytes | Exact canonical expected TEST context; part of combined budget |
| Nesting depth 16 | Independently for each parsed transport/body/payload/manifest-projection/context/snapshot JSON document: document root depth 0; each object member value/array element is parent depth + 1; maximum value depth 16, checked before descending beyond it |
| Signature entries 3 | Count before entry validation/crypto; four -> LIMIT_EXCEEDED. Zero/one are representable rejection inputs, not a relaxed quorum |

These are input/work budgets, not a proof of process peak memory. The future parser
must avoid duplicate unbounded copies, include a bounded token/parse implementation
and measure worst-case CPU/memory before G1 implementation acceptance. A declared
body over cap returns LIMIT_EXCEEDED even if truncated; a within-cap but inconsistent
length is DOMAIN_MISMATCH. Type/syntax failures that prevent locating a later field
do not authorize scanning arbitrary data to discover a higher-priority error.

The limits are jointly feasible: maximum valid signature metadata is bounded by
ID lengths and three entries; frame hex uses at most 131,138 characters. Even with
that transport, decoded frame/payload, max snapshot/context and three decoded
signatures, a shape-valid compact proof fits the combined bound. The body may impose
a tighter payload limit for a particular manifest; cap compliance is necessary,
not a promise every max-sized inner payload fits a max-sized body. Do not pad with
unknown metadata, truncate or weaken fields to reach a cap. See boundary-vector plan.
TRUST-02's existing structural 65,536-byte limit is unchanged.

## 7. Compatibility and status

The reviewed source exposes canonical_bytes/parse_canonical, strict frozen records
and STRUCTURAL_ONLY, not RootManifest, crypto, key pins or SignatureEvidence. No
reviewed signing assumption differs from that behavior. TRUST-03's generic contexts
are deliberately narrowed to this field-exact TEST subset; no production sidecar
semantics are silently frozen. Existing IAM hashes, policies, admission, providers,
API/audit behavior and is_current=False remain untouched.

This is a proposed review baseline requiring the A01/A04 subset decisions in the
G1 review, not final architecture approval or permission to implement.
