# TRUST-04C authoritative dependency evidence

Retrieved/reviewed **2026-11-16**. Documentation and HTTPS research only; no package
installed/imported, downloaded wheel executed, hash computed or signature verified.
[Public catalog](iam03c-trust04c-ed25519-public-vector-catalog.md),
[golden plan](iam03c-trust04c-independent-golden-vector-plan.md),
[G1 review](iam03c-trust04c-g1-evidence-review.md).

## 1. Recommendation and evidence boundary

Recommend **cryptography==50.0.2 as a candidate for separately authorized offline
compatibility review**, not an approved verifier dependency. Selection is supported
by documented target compatibility, released/security-supported status, Ed25519 API
and an available matching wheel; it is not simply choosing an unexamined newest
version. Strict ED25519-PURE-1 behavior remains UNVERIFIED until local tests.

The official security policy limits upstream security maintenance to development
and the latest release; release information identifies 50.0.2 dated 2026-09-30,
while latest documentation also describes unreleased 51 development. Recheck this
moving support boundary immediately before any later adoption. Do not pin a dev
release or silently carry this recommendation forward after support changes.
Sources [S1](https://cryptography.io/en/latest/security/),
[S2](https://cryptography.io/en/50.0.2/changelog/) and
[S3](https://cryptography.io/en/latest/changelog/) were consulted on the date above.

Local prior facts remain limited: requirements.txt/pyproject.toml declare no
cryptography dependency; inspected .venv disables system packages and had none.
System metadata 3.4.8 and Ubuntu package revision 3.4.8-1ubuntu2.4 do not identify
this candidate, its backend or its security state. No system/venv change is made.
Upstream support policy does not assess Ubuntu downstream patch maintenance;
no safe/unsafe verdict for that installed package is inferred from its version.

## 2. Target/API/platform evidence

| ID / authoritative source, retrieved 2026-11-16 | Version and relevant evidence | Limit |
| --- | --- | --- |
| S4 [installation](https://cryptography.io/en/50.0.2/installation/) | 50.0.2 documents Python 3.9+ and x86-64 Ubuntu 22.04 among tested targets; describes prebuilt Linux wheels and separate Rust/compiler/OpenSSL/libffi source-build needs | Target support documentation, not a local install/ABI test; no source-build fallback authorized |
| S5 [Ed25519 API](https://cryptography.io/en/50.0.2/hazmat/primitives/asymmetric/ed25519/) | 50.0.2 public-key loader expects 32 bytes; verify(signature, data) returns None or raises InvalidSignature; unsupported backend and malformed-key errors documented | DOCUMENTED API SUPPORT; not a promise of the frozen prime-subgroup/canonical acceptance set |
| S6 [PyPI release metadata](https://pypi.org/pypi/cryptography/50.0.2/json) | Release version 50.0.2, Requires-Python !=3.9.0,!=3.9.1,>=3.9; matching cp39-abi3 manylinux_2_28_x86_64 wheel not yanked | Read-only metadata retrieval, not artifact verification or transitive lock |
| S7 [PyPA tags](https://packaging.python.org/en/latest/specifications/platform-compatibility-tags/) | Stable-ABI and manylinux tags describe Python ABI/platform eligibility | Applying the tags supports candidate CPython 3.10/glibc target suitability; actual environment still needs recorded checks |
| S8 [Python lifecycle](https://devguide.python.org/versions/) | Retrieved table marks upstream Python 3.10 end-of-life on 2026-10-01 | Compatibility is not runtime security support; downstream support and organizational exception/upgrade decision remain unresolved |
| S9 [maintainer implementation](https://raw.githubusercontent.com/pyca/cryptography/50.0.2/src/rust/src/backend/ed25519.rs) | 50.0.2 tag: public key uses raw OpenSSL ED25519; verify delegates to a no-digest one-shot backend and maps false/error to InvalidSignature | Read as source only, never saved/executed; backend behavior still requires tests |

The candidate's documented Python support includes 3.10, but Python's own upstream
EOL is a separate risk. The project requires Python 3.10; do not silently change it.
Owner must review an isolated TEST exception/downstream support evidence or separately
authorize target modernization. No production approval follows from ABI compatibility.

## 3. Exact candidate artifact provenance

From S6, retrieved 2026-11-16:

- Filename: cryptography-50.0.2-cp39-abi3-manylinux_2_28_x86_64.whl.
- Upload timestamp: 2026-09-30T15:29:32.605292Z; yanked=false.
- Publisher SHA-256: `f21e8a22c8605750c7af886bab299a363721264061b4ac0a30efb73cfd58efc5`.
- [Publisher artifact URL](https://files.pythonhosted.org/packages/4f/87/ef344a9e616871f2519c22d6afcda79ddd5d35e9592d95eb6e677608d055/cryptography-50.0.2-cp39-abi3-manylinux_2_28_x86_64.whl).

The checksum is copied publisher metadata, **not locally computed or matched**.
No wheel/archive was downloaded. This is a single candidate artifact reference,
not a complete dependency lock, installation authorization or publisher attestation.
Transitive artifacts, Python/pip/tool versions, OS/glibc/architecture, hashes and
licenses must be reviewed/pinned together before an offline installation. Do not
use a mutable latest requirement, resolver/network fallback or source build.

S2 states release wheels use OpenSSL 4.0.3. A source build/system package can use a
different backend; candidate version alone cannot prove the backend loaded later.
Future environment recording must confirm exact artifact and backend without
changing the pure verifier's no-discovery boundary. No FIPS claim is made.

## 4. Security evidence reviewed, not a vulnerability-free certification

The official [advisory index](https://github.com/pyca/cryptography/security/advisories)
and these maintainer advisories were consulted on 2026-11-16:

| ID / exact source | Published patch information | Relevance / remaining scope |
| --- | --- | --- |
| [GHSA-g6cj-pr64-35w5](https://github.com/pyca/cryptography/security/advisories/GHSA-g6cj-pr64-35w5), 2026-07-31 | PKCS#7 decryption oracle; patched version 50.0.0 | Different API than this pure verifier; supports rejecting arbitrary older-version assumptions, not proof of Ed25519 strictness |
| [GHSA-537c-gmf6-5ccf](https://github.com/pyca/cryptography/security/advisories/GHSA-537c-gmf6-5ccf), 2026-06-09 | Bundled OpenSSL issue; patch 48.0.1; source-build users must assess their own OpenSSL | Shows why backend/artifact provenance matters; candidate is later, but no installed-backend assessment occurred |
| [GHSA-p423-j2cm-9vmq](https://github.com/pyca/cryptography/security/advisories/GHSA-p423-j2cm-9vmq), 2026-04-08 | Non-contiguous-buffer overflow; patched >=46.0.7 | Candidate is later than named fix; frozen byte inputs still require shape checks and full environment review |

This bounded manual review is not an exhaustive all-package/backend/transitive
advisory audit. It neither proves absence of other issues nor establishes a
vulnerability in the Ubuntu-patched 3.4.8 package. Repeat official advisory and
artifact review before use. No security scanner, package manager or crypto API ran.

## 5. Update/rollback and remaining decisions

Keep an exact approved artifact set, dependency/backend provenance and independent
compatibility results per version. Updates require support/advisory review and
rerunning approved vectors; no automatic newest-version adoption. A code/dependency
rollback may use only a still-reviewed acceptable artifact set, not a blind return
to system 3.4.8 or a version reintroducing an advisory. Root/pin state is never
rolled back as part of dependency rollback. All installation/build changes require
separate approval and are outside this task.

Primary-source evidence is **SUFFICIENT_FOR_REVIEW** of this candidate recommendation.
Acceptance still needs owner dependency/runtime decisions, complete reproducible
artifacts, strict local compatibility evidence and independent project goldens.
No statement in this document grants A01-TEST/A04-TEST or production authority.
