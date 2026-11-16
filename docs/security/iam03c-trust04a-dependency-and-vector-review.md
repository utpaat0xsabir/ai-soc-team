# TRUST-04A dependency and independent-vector review

2026-11-16. **Assessment only; no cryptographic package imported or executed.**
[Owner proposals](iam03c-trust04a-owner-decision-package.md),
[implementation boundary](iam03c-trust04a-trust05-implementation-boundary.md),
[authorization checklist](iam03c-trust04a-g1-authorization-checklist.md).

## 1. Verified local dependency facts

Inspection used ordinary file reads and a Python 3.10 standard-library-only helper
started with `python3 -S` (no site/.pth processing), not pip or crypto imports.

| Local evidence | Verified observation | What it does not establish |
| --- | --- | --- |
| `requirements.txt` | Declares existing API/test dependencies; no cryptography requirement | No direct approved verifier dependency or version constraint |
| `pyproject.toml` | Pytest settings only; no cryptography/project dependency declaration | No lock, artifact hash or dependency authorization |
| Bounded repository dependency-file inventory | requirements.txt and pyproject.toml found; no matching repository lock/constraints file found in that inventory | Not a full system/transitive dependency audit |
| `/usr/lib/python3/dist-packages/cryptography-3.4.8.egg-info/PKG-INFO` | Name cryptography; Version 3.4.8; Requires-Python >=3.6 | Not effective runtime import resolution, current maintenance, advisory clearance, backend version, validation or exact installed binary integrity |
| `/usr/lib/python3/dist-packages/cryptography/hazmat/primitives/asymmetric/ed25519.py` | Static source has 32/64-byte constants, from_public_bytes and verify(signature, data) -> None, delegating to a backend | No verification was run; API existence does not prove strict point/subgroup semantics |
| `/usr/lib/python3/dist-packages/cryptography/hazmat/backends/openssl/ed25519.py` | Static verify path invokes EVP_DigestVerify and raises InvalidSignature on failure | Actual OpenSSL runtime/provider/build and acceptance behavior remain UNVERIFIED |
| `.venv/pyvenv.cfg` | version 3.10.12; include-system-site-packages=false | System 3.4.8 is not thereby available/selected inside this venv |
| Inspected metadata roots | No cryptography distribution metadata found under project .venv/venv Python-3.10 site-packages or inspected user/local roots; system metadata above was found | Not a guarantee no other interpreter, path or incomplete package copy exists |
| Helper interpreter | Python 3.10.12, prefix /usr, cryptography absent from helper's sys.modules | No project/runtime backend or cryptographic API was loaded |

Thus an exact **local distribution metadata version** can be stated (3.4.8), but
an exact **executing verifier dependency/backend** is not established. Do not import
it to resolve that uncertainty under this milestone. Metadata can be stale or
incomplete and is not an integrity certificate. No package-manager/network query,
installation, upgrade or certificate check was performed.

## 2. Candidate support range, pinning and required behavior

**Approved version range: NONE. Candidate supported numeric range: UNVERIFIED.**
There is insufficient permitted evidence to claim a specific current release line
is maintained, secure and Python-3.10 compatible. Do not invent `>=3.4.8`, an open-ended
minimum or a guessed future range as an allowlist. Candidate eligibility is the
intersection of a later-reviewed maintained release line, explicit Python 3.10
support/artifacts, cleared relevant advisories, reproducible artifact/backend
provenance and demonstrated strict-profile conformance. Select an exact patch
version/artifact set, not that broad eligibility rule, for implementation approval.

Proposed final requirement form is `cryptography==<reviewed exact version>` plus
artifact hashes and an identified backend/build. This placeholder is not a proposed
installed version, requirement-file edit or executable installation instruction.
Numeric pin/range selection remains DEP-TEST pending. The local 3.4.8 metadata is
not approved for reuse and provides no evidence of current support; this review
does not assert a particular unverified CVE or declare that it cannot work.

Required future API behavior:

- Load exactly 32 raw public-key bytes with an approved Ed25519PublicKey API;
  reject malformed lengths and enforce the frozen point/key acceptance set.
- verify(signature, exact_full_frame) checks a 64-byte pure Ed25519 signature;
  success is a mathematical diagnostic only. InvalidSignature and provider errors
  map to frozen safe outcomes, never fallback, retry-as-other-key or raw error text.
- No Ed25519ph/ctx, implicit prehash, alternate key/profile negotiation or signing
  API in the verifier. Never add custom curve arithmetic or a homemade point blacklist.
- Constructor length checking is insufficient to establish canonical on-curve,
  prime-order nonidentity A or the required R/S rules. Prove those rules through
  vetted APIs and independent adversarial vectors for the exact backend. Unknown
  compatibility is a blocker, not permission to assume stricter behavior.

Python 3.10 compatibility has two distinct questions: the observed metadata's
Requires-Python >=3.6 includes 3.10 syntactically, but actual behavior/wheel/ABI/backend
compatibility is untested; a future chosen release must independently document and
demonstrate Python 3.10 support. New releases may change supported interpreters,
OpenSSL requirements, build tools or APIs. No current support claim is made offline.

Before approval, obtain exact release/license/support/advisory evidence, dependency
and backend inventory, source/wheel hashes and provenance, supported OS/architecture/
Python constraints and strict conformance results. Record whether a wheel embeds
OpenSSL or uses system libraries; package version alone cannot pin both. Require
reproducible offline artifact supply and lock/hash review. Installation/build/toolchain
or dependency-declaration changes require exact separate authorization; no automatic
build/download/system upgrade. No FIPS validation claim follows from API availability.
Unsupported/outdated/unreviewed software risks remain until that evidence exists.

## 3. Vector provenance and missing assets

[TRUST-04 section 3](iam03c-trust04-vector-and-error-matrix.md) defines a future
recipe, not approved literal vectors. Targeted repository filename/content review
found structural fixtures but no approved RFC 8032/Wycheproof artifact bundle,
independent project golden-byte/hash manifest, project-frame signatures or review
record. Their absence is an **IMPLEMENTATION_BLOCKER for TRUST-05 verification**.
A plan naming a corpus is not independent expected output.

Separate suites and provenance:

| Suite | Required future source and trust evidence | Generation/usage restriction |
| --- | --- | --- |
| ALG-RFC8032 | Exact RFC 8032 section 7.1 vectors with source/version/license/artifact digests and known published message/key/signature values | Verify the original published messages; no claim their signatures sign project frames |
| ADV-ED25519 | Exact reviewed Wycheproof Ed25519 release/commit/file/digest/license and validity flags; reconcile ambiguous acceptance against strict frozen profile | Never accept every acceptable/valid label without examining profile differences |
| FRAME-ROOT-POLICY-1 | Three named published TEST keys, exact independently registered context/pin fixtures, complete literal inner/key-set/manifest/body/frame bytes, expected SHA-256 values, valid two/three-signature entries and reviewed negative mutations | Separate reference derivation/signing activity, not the verifier generating its own expected bytes/hash/signature |

No corpus was fetched, signed fixture generated or key/seed material copied here.
Potential public reference locations are already listed in TRUST-04; exact source
artifacts and their current authenticity/license status remain UNVERIFIED. Distinct
published TEST key labels do not demonstrate independent real custodians.

## 4. All 26 V04 cases classified

Primary class labels: PUBLISHED = published algorithm vector; PROJECT = independently
derived project-specific vector; PARSING = adversarial parsing vector; QUORUM_BINDING
= quorum and binding fixture; NEGATIVE = negative security case. A case may also
use approved project assets; a label does not imply it already exists or is approved.
All rows are **SPECIFIED, ASSETS NOT APPROVED, NOT EXECUTED**.

| V04 | Primary class | Independent expected value / missing evidence |
| --- | --- | --- |
| 01 | PUBLISHED | Exact RFC original positive vectors, published outputs and reviewed artifact |
| 02 | PROJECT | Separate encoders' exact canonical/preimage/frame literals and independent SHA-256 constants; no same-UUT expected generation |
| 03 | QUORUM_BINDING | Approved two-key project-frame signatures and expected two sorted pairs/counters |
| 04 | QUORUM_BINDING | Three independently checked signatures and all six input permutations, identical logical evidence |
| 05 | QUORUM_BINDING | Frozen zero/one-vote rejection plus zero crypto-call expectation |
| 06 | NEGATIVE | Fixed mutated well-shaped signature with independently checked rejection, not arbitrary random mutation with unknown result |
| 07 | QUORUM_BINDING | Exact duplicate custodian/key/material and bad-source-map fixtures, earlier-stage expected codes |
| 08 | QUORUM_BINDING | Independent expected tenant versus altered claimed/nested tenant; no source lookup |
| 09 | QUORUM_BINDING | Domain/deployment/customer/kind mismatches; exact typed context comparison |
| 10 | QUORUM_BINDING | Environment UUID mismatch versus PRODUCTION-purpose exclusion, distinct expected diagnostics |
| 11 | NEGATIVE | Unsupported/mixed profiles, no fallback and no source/crypto calls |
| 12 | PARSING | Literal byte/numeric/time/UUID/duplicate-key aliases with frozen code order |
| 13 | PARSING | Unknown/extra signed or unsigned fields; closed-schema rejection |
| 14 | PROJECT | Inconsistent derived digests versus coherent but differently pinned set/manifest; independent preimage/hash review |
| 15 | NEGATIVE | Two valid signatures plus invalid third at each sorted position; no partial evidence |
| 16 | NEGATIVE | Unknown signer versus known signer using wrong key; independently selected keys/expected stage |
| 17 | NEGATIVE | TEST root/key revocation and explicit time/lifecycle states, no implicit clock |
| 18 | NEGATIVE | Missing/self-selected/corrupt/non-TEST source, fixed unavailable result |
| 19 | NEGATIVE | Old/new unapproved pin/policy/generation; no self-activation |
| 20 | NEGATIVE | Protected synthetic/production input classification, not operational synthetic import |
| 21 | PUBLISHED | Reviewed adversarial corpus plus strict point/scalar profile verdicts and independently checked registration failures |
| 22 | PARSING | Exact label/NUL/length/trailing/future-purpose mutations and observable-limit exceptions |
| 23 | PARSING | Cap/cap+1 byte/count/depth fixtures, independent length accounting and precedence; no new padding field |
| 24 | NEGATIVE | Frozen multi-fault recipes and semantic permutations with exact counters |
| 25 | QUORUM_BINDING | Explicit provider-recovery/domain exclusion and unknown platform signer; no implicit provider authority |
| 26 | NEGATIVE | Source/backend faults, immutable result and zero operational integration; no forged success accepted |

## 5. Independent derivation and acceptance gates

Freeze symbolic fixture inputs and wire-document revision first. A separate reference
encoder derives literal inner/key-set/manifest/body/frame bytes. A second reviewed
implementation/person reconstructs them independently; a separate standard hash
tool computes expected SHA-256 values from the literal preimages. An independently
reviewed signing/verification implementation creates/checks project-frame signatures
only after explicit VEC-TEST authorization using published non-production material.
No newly generated production keys, live root enrollment or signing service is needed.

Retain exact provenance, tool/version/review references and content digests; compare
complete bytes, not just a success flag. Approve and pin literal assets before
verifier tests consume them. No fixture may call the verifier's serializer/hash/
verify routine to produce its own expected results at runtime. Mutation recipes
must pin expected errors/counters and distinguish a malformed input from a validly
signed differently pinned policy. Golden changes require review, not regeneration
to make the implementation pass. Do not include private inputs in reports.

The pure verifier must contain no signer/key generator. If project signatures are
not separately authorized or independently supplied, positive project-quorum tests
remain blocked. Missing sources, expected constants, license/provenance, strict
library behavior or independent review cannot be replaced with arbitrary synthetic
success. Production is unaffected: every accepted fixture/result remains TEST-only.

**Dependency selection: UNVERIFIED / NOT APPROVED**  
**Independent golden assets: MISSING / NOT APPROVED**  
**Cryptographic compatibility: UNVERIFIED**  
**G1 TECHNICAL READINESS: NOT_READY**
