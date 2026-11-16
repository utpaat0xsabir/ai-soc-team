# TRUST-04B ED25519-PURE-1 compatibility matrix

2026-11-16. **ED25519 COMPATIBILITY: UNVERIFIED.**
[Dependency evidence](iam03c-trust04b-dependency-assessment.md),
[golden vectors](iam03c-trust04b-golden-vector-provenance.md),
[owner/G1 decisions](iam03c-trust04b-g1-evidence-and-owner-decisions.md).

No cryptographic API was imported or executed. API names describe candidate future
calls, not tested behavior. Risks below are consequences of omitting a required
control, not confirmed vulnerabilities in the local package. A local API declaration
or a known release name cannot establish strict compatibility.

## 1. Frozen profile and compatibility requirements

[TRUST-04 anchor section 4](iam03c-trust04-anchor-and-verifier-contract.md) requires
pure Ed25519, 32-byte canonical compressed A, 64-byte R||S, canonical S < L,
nonidentity prime-order A and prime-order R (identity R is not rejected solely for
identity if the standard equation holds). No ph/ctx, cofactor-only permissive/ZIP-215
substitution or arbitrary algorithm choice. Keep these requirements unchanged.

Evidence shorthand: S = frozen specification; H = TRUST-04A's historical static API
inspection; M = present distribution/OS metadata. None demonstrates mathematical
acceptance. Every behavioral result below remains UNVERIFIED. Current official API/
release claims needing acquisition are EXTERNAL_VERIFICATION_REQUIRED.

| Requirement | Required behavior | Candidate API / responsible layer | Existing evidence | Missing evidence / future method | Risk |
| --- | --- | --- | --- | --- | --- |
| Valid RFC 8032 signatures | Accept exact published pure-Ed25519 messages/key/signatures; do not treat RFC messages as project frames | Ed25519PublicKey.verify(signature, message) in algorithm suite | S/H/M; no vector run | Acquire pinned RFC artifacts, independently check known answers on exact selected package/backend | Critical: false mathematical result |
| Invalid 64-byte signatures | Reject changed signature/equation, including invalid third vote; no partial evidence | verify; InvalidSignature maps SIGNATURE_INVALID | S/H; no behavior proof | Frozen bit mutations plus independent adversarial references, every sorted position | Critical: forgery/quorum bypass |
| Incorrect signature lengths | Reject length/hex before source/crypto as STRUCTURE_INVALID; do not rely on backend permissiveness | Bounded wire parser, H64 field | S | Exact 0/63/65-byte and malformed-hex fixtures, zero crypto-call assertions | High: ambiguous parsing |
| Incorrect key lengths | Reject malformed 32-byte encoding/hex shape before use | Wire H32 parser; from_public_bytes only after approved source checks | S/H; metadata not length-test evidence | Published/local independent shape fixtures, exact API/backend behavior recorded | High: backend-dependent parsing |
| Unknown public key/signer | Reject SIGNER_UNKNOWN or earlier pin/policy failure, never search other keys | Independent TEST source and exact custodian/key map, not library lookup | S | Reviewed source fixtures, no fallback/source-count tests | Critical: self-selected trust |
| Wrong message frame | Signature must cover full exact frame, not a digest, raw body or another message | verify(signature, full_frame) | S/H | Independent framed-message signatures and wrong-message mutations | Critical: signature meaning mismatch |
| Wrong domain separation | Wrong label/protocol/purpose rejects per frozen DOMAIN_MISMATCH/extraction rules before math | Wire/domain layer | S | Exact label/NUL/length/trailing/purpose fixtures and stage counters | Critical: cross-protocol replay |
| Wrong algorithm/profile | Reject unsupported/mixed profile before anchor/maths; no negotiation | Closed schema/profile layer; fixed Ed25519 API | S | Declared ph/ctx/P-256/unknown profile negatives | Critical: algorithm confusion |
| ph/ctx bytes disguised as pure | Call pure API on exact frame only; differently computed signature must not be silently adapted | Fixed pure verify; no prehash/context helper | S; no test evidence | Independent variant test sources and exact pure/variant acceptance results; metadata tag alone is insufficient | Critical: silent substitution |
| Noncanonical scalar/R encoding | Reject noncanonical S, S >= L, noncanonical/invalid R under frozen strict profile | Approved vetted verify/validation APIs | S; H does not prove this | Published adversarial vectors and independent verdicts for exact backend; no custom arithmetic | Critical: malleability/acceptance divergence |
| Malformed public-key point | Canonical on-curve A, correct subgroup and nonidentity; length alone insufficient | Vetted public-key validation plus verify behavior | S/H/M; no point validation proof | Review established APIs, independently test malformed/invalid encodings and fixture registration behavior | Critical: weak/invalid anchor acceptance |
| Small/mixed-order cases | Enforce exact frozen A/R restrictions, not permissive corpus defaults | Approved established-library APIs, never homemade point math | S only | Exact Wycheproof/adversarial corpus, map each acceptable label, cross-implementation evidence; stop if unsupported | Critical: strict-profile failure |
| Library/backend rejection | Malformed input/provider errors never become success; fixed SIGNATURE_INVALID for selected crypto API failure | Small exception-sanitizing wrapper | S/H | Exact exception classes/API behavior; missing startup backend blocks environment rather than skipped tests; approved fault injection | High: hidden failure/fallback |
| Error sanitization | No raw payload/key/signature/provider text or foreign inventory in rejection | Pure staged boundary, no operational logger/audit mutation | S | Canary inputs, zero partial evidence, exact fixed result/counters across permutations | High: information disclosure |
| Python/platform/API support | Exact approved release/backend works on declared Python 3.10/OS/ABI and is reproducible | Dependency/harness preflight, outside pure verifier | M declares >=3.6 and system amd64 only | Current official support/artifacts/advisories EXTERNAL_VERIFICATION_REQUIRED; later authorized offline compatibility run | High: unreviewed/unusable dependency |

The matrix does not declare that PyCA lacks the needed behavior. It says there is
no permitted executed evidence establishing it. If the chosen APIs cannot enforce
the strict acceptance set, stop for dependency/spec owner review; do not weaken the
protocol, introduce alternate algorithms or implement arithmetic/point blacklists.

## 2. Wire and diagnostic compatibility review

[Wire](iam03c-trust04-root-policy-wire-spec.md) and
[error matrix](iam03c-trust04-vector-and-error-matrix.md) remain authoritative.

| Frozen item | Reviewed constraint / consequence |
| --- | --- |
| All 17 body fields | protocol_version, canonicalization_id, signature_profile_id, purpose, binding, environment_id, environment_kind, root_policy_id, root_policy_version, root_set_digest, operation_id, issued_at, expires_at, payload_type, payload_hex, payload_sha256, purpose_context; closed required schema |
| Canonical encoding | ASCII closed fields, explicit nulls/defaults, lossless bounded integers, UTC microseconds, exact bytes; no JCS claim, aliases/unknowns reject; TRUST02 serializer stays unchanged |
| Signed frame | 24-byte AI-SOC-IAM-ROOT-POLICY-1 label + one NUL + U64BE body length + exact body; 33-byte header; signature input is full frame, not frame_sha256 |
| Digests | SHA-256 public bytes; exact key-set projection; manifest excluding only own digest; exact inner payload; exact full frame. Acyclic, no signatures included in their own preimage |
| Key/custodian binding | Three CUSTOMER identities and distinct key/reference/material mapping; independent TEST context/pins, no self-signed bootstrap or provider vote |
| Quorum | Fixed 2-of-3; zero/one eligible vote denies before math; all supplied valid for success; invalid third fails entire result; duplicate/revoked/unknown behavior fixed |
| Fifteen diagnostics in order | LIMIT_EXCEEDED (observable repeated guards), SYNTHETIC_SOURCE, STRUCTURE_INVALID, BINDING_MISMATCH, SIGNER_DUPLICATE, CANONICAL_MISMATCH, DOMAIN_MISMATCH, ALGORITHM_UNSUPPORTED, ANCHOR_UNAVAILABLE, POLICY_STALE, SIGNER_UNKNOWN, KEY_REVOKED, TIME_INVALID, QUORUM_INSUFFICIENT, SIGNATURE_INVALID |
| Bounds | Inner 24,576; body 65,536; frame 65,569; combined assessment 262,144; snapshot 16,384; expected context 4,096; depth 16; signatures <=3, with raw/decoded accounting and extraction exceptions as frozen |
| Output | Immutable TEST_SIGNATURE_DIAGNOSTIC / SIGNATURES_VALID_TEST_ONLY, executable=false, exact digest/context/pin/signer bindings; no ALLOW, CURRENT authority, role grant or production consumer |

No security-critical wire contradiction was identified in this local review. The
required wrappers, parser limits, dependency behavior and golden values are **not
implemented or tested** by that finding. A different observed API acceptance set
would be a blocker, not permission to alter the frozen specification. Existing
TRUST-02/IAM modules, admission, providers and is_current remain unchanged.
