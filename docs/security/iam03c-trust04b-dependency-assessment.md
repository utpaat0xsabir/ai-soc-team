# TRUST-04B cryptographic dependency assessment

2026-11-16. **DEPENDENCY_CANDIDATE: PyCA cryptography.**
**Assessment: MORE_EVIDENCE_REQUIRED; not approved, installed or executed by this task.**
[Compatibility matrix](iam03c-trust04b-ed25519-compatibility-matrix.md),
[vector provenance](iam03c-trust04b-golden-vector-provenance.md),
[G1 and owner decisions](iam03c-trust04b-g1-evidence-and-owner-decisions.md).

## 1. Evidence labels and method

- VERIFIED_LOCAL_METADATA: a declaration/configuration/installed metadata file was
  read directly. It does not establish executed code, authenticity or security.
- SOURCE_SUPPORTED: an existing repository specification/inspection record states
  a requirement or static API observation, not a successful cryptographic test.
- UNVERIFIED: behavior or provenance not demonstrated by the permitted inspection.
- EXTERNAL_VERIFICATION_REQUIRED: current authoritative information unavailable
  locally and requiring separately authorized acquisition. No URLs below were fetched.
- PROPOSED — NOT APPROVED: recommendation requiring an explicit owner decision.

Inspection used `PYTHONDONTWRITEBYTECODE=1 python3 -S` with standard-library file/
metadata parsing only: no site/.pth startup, pip, project import or cryptography
import. The Git index and tracked/untracked content were inventoried for preservation.
No environment secret values, private material or connection configuration was read
or printed. No cryptographic message, hash vector, key or signature was generated.

## 2. Dependency inventory

| Question / source | VERIFIED_LOCAL_METADATA | Limit / conclusion |
| --- | --- | --- |
| Direct project declaration: requirements.txt | No cryptography requirement; existing API/test dependencies remain unchanged | No direct verifier dependency or approved version |
| pyproject.toml | Pytest configuration only | No dependency, pin or cryptographic build configuration |
| Repository lock/constraints inventory | Only requirements.txt and pyproject.toml matched bounded dependency searches; no matching lock/constraints file found | No reproducible cryptography lock/artifact hashes; not an exhaustive machine audit |
| System distribution metadata | `/usr/lib/python3/dist-packages/cryptography-3.4.8.egg-info/PKG-INFO`: Name cryptography, Version 3.4.8, Requires-Python >=3.6 | Exact metadata label, not effective runtime import selection or strict verification evidence |
| OS package database | `/var/lib/dpkg/status`: python3-cryptography, install ok installed, amd64, version 3.4.8-1ubuntu2.4 | Distro revision differs from upstream label; backports/support must be assessed separately. No safe/unsafe conclusion follows |
| Declared system dependencies | That package record declares Python, CFFI backend ABI ranges, libc and libssl3 >=3.0.0~~alpha1 | These are constraints, not actual loaded OpenSSL/CFFI/provider versions or build integrity |
| Project virtual environment | `.venv/pyvenv.cfg`: Python 3.10.12, include-system-site-packages=false | System metadata is not automatically the project's dependency |
| Inspected venv metadata | `.venv/lib/python3.10/site-packages`: no cryptography metadata or cryptography directory found | No project-venv cryptography selected by this observation; do not execute its interpreter to test imports |
| Other bounded roots | Inspected user Python-3.10 site-packages and /usr/local/lib/python3.10/dist-packages: no cryptography metadata/directory found | One version observed; other interpreters/paths/copies are not globally excluded |
| Transitive dependency status | No cryptography Requires-Dist consumer found among inspected dist-info/egg-info metadata; system cryptography record had no Requires-Dist headers | Debian/optional/transitive metadata may be incomplete. Project transitive inclusion is UNVERIFIED without a resolved dependency graph; do not infer no dependencies |
| Reproduction records | System egg-info lacked WHEEL, RECORD and INSTALLER files; no project cryptography lock/hash records found | OS package tracking is not a reproducible PyPI wheel manifest; binary provenance remains UNVERIFIED |
| Local documentation | /usr/share/doc/python3-cryptography contains copyright and changelog.Debian.gz | Filenames observed, not a current support/advisory clearance or license audit |
| Helper interpreter | Python 3.10.12, prefix /usr, no cryptography in sys.modules | No crypto library/backend was loaded |

The distro package revision is new evidence beyond TRUST-04A's upstream label.
It neither proves security fixes are absent nor that all relevant fixes are present.
The exact runtime/backend remains UNVERIFIED. No package version is approved merely
because metadata or a package record says installed.

## 3. Candidate version/support and installation recommendation

**Approved version: NONE. Candidate supported numeric range: UNVERIFIED.**
Do not guess a current release, infer maintenance from installation or recommend an
open-ended >=3.4.8 minimum. Candidate eligibility is a release demonstrably maintained
for the intended deployment, with Python 3.10/platform artifacts, acceptable advisory/
license/provenance evidence and frozen strict-profile conformance. The intersection
may be empty; if so stop for dependency/target review without weakening signatures
or changing the project's Python requirement under this scope.

Requires-Python >=3.6 syntactically includes 3.10, but does not prove operation on
3.10.12, suitable wheels/ABI or current Python/library support. Current Python 3.10
lifecycle and supported library release lines are EXTERNAL_VERIFICATION_REQUIRED.
No claim that 3.4.8 is supported, safe, unsafe or incapable is made here.

Propose an exact approved package patch version and artifact hashes, with exact
Python/OS/architecture and backend/build provenance. Record whether OpenSSL is
bundled or system-linked, CFFI/Rust/build requirements if applicable, transitive
pins and installation provenance. Those details depend on the selected artifact;
no current wheel/build policy is inferred. Use a reviewed lock/constraint/artifact
manifest and reproducible offline supply, not whatever system copy imports first.

Installation, upgrade, requirement/lock edits, new build tooling or artifact/network
acquisition need separate explicit owner scope. The current task authorizes none.
An already available package also needs review; availability does not bypass DEP-TEST.
Do not silently use the system 3.4.8 or alter .venv. No FIPS validation is claimed.

## 4. Required API and compatibility evidence

The frozen candidate uses Ed25519PublicKey.from_public_bytes and
verify(signature, exact_full_frame), not a hash of that frame. TRUST-04A recorded
those APIs and a backend InvalidSignature path by static source inspection. That
is SOURCE_SUPPORTED historical local evidence only; current metadata cannot prove
API behavior for a future selected release/backend. Official documentation and
independent tests must substantiate it.

Required: exact 32-byte canonical keys, exact 64-byte pure signatures, strict A/R/S
acceptance, deterministic failure mapping, no ph/ctx/algorithm/key fallback and no
signature-to-IAM permission. Constructor length checks are insufficient for subgroup
rules. See the compatibility matrix for each missing behavior. If no established
vetted API meets the profile, stop; no custom arithmetic/blacklist or permissive
profile revision under this authorization.

## 5. Exact authoritative evidence to obtain later

Every row is **EXTERNAL_VERIFICATION_REQUIRED**. These are source locations and
questions, not current facts or verified link responses. Later review must pin the
selected version's documents/artifacts rather than rely solely on a mutable latest page.

| Source location | Evidence required |
| --- | --- |
| [PyCA Ed25519 API](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/) | Exact API, pure-message semantics, exception/unsupported-backend behavior; strictness still needs tests |
| [PyCA installation](https://cryptography.io/en/latest/installation/) | Supported Python/OS/architecture, wheels, backend and source-build requirements for selected release |
| [PyCA changelog](https://cryptography.io/en/latest/changelog/) | Exact releases, deprecations, Python/backend compatibility changes and relevant fixes |
| [PyCA security](https://cryptography.io/en/latest/security/) and [official advisories](https://github.com/pyca/cryptography/security/advisories) | Reporting/support guidance, applicable advisories, affected/fixed versions and backend implications |
| [PyPI cryptography metadata](https://pypi.org/pypi/cryptography/json) | Versioned Requires-Python, distributions/tags/hashes/yank status/license metadata; authenticity checked independently |
| [Python version lifecycle](https://devguide.python.org/versions/) | Actual Python 3.10 lifecycle and organizational support risk; no silent interpreter change |
| [OpenSSL advisories](https://openssl-library.org/news/vulnerabilities/) | Applicability to exact bundled/system backend and provider build |
| [Ubuntu package information](https://launchpad.net/ubuntu/+source/python-cryptography) | Distro revision/source patches/support and security updates if system package is considered |

Metadata does not substitute for current advisories or adversarial acceptance tests.
No external lookup is needed to finish this assessment: missing evidence is reported,
not fabricated. Any acquisition/testing needs a separately authorized next activity.

## 6. Decision

**DEPENDENCY ASSESSMENT: MORE_EVIDENCE_REQUIRED.** PyCA remains a candidate for
future test review, not an accepted dependency. Exact version/backend/artifact and
security/support review, strict-profile compatibility and independent vectors must
be accepted before TRUST-05. Unknown evidence cannot become a supported-version claim.
