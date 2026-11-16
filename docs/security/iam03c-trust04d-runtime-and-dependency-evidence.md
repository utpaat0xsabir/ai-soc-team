# TRUST-04D runtime and dependency evidence

2026-11-16. **BLOCKED before package acquisition/installation.**
[Compatibility results](iam03c-trust04d-ed25519-compatibility-results.md),
[golden review](iam03c-trust04d-independent-golden-review.md),
[G1 assessment](iam03c-trust04d-g1-readiness-assessment.md).

## Authorization actually supplied

The owner explicitly authorized TRUST-04D TEST-only execution, Python 3.10 under a
TEST-only exception, disposable /tmp/ai-soc-trust04d-* isolation, focused public-vector
tests and independent TEST signing/hashing. A subsequent OWNER AUTHORIZATION —
IAM-03C-TRUST-04D-DEPENDENCY authorized official PyPI metadata/binary wheels,
complete pins, independent publisher-hash checks and offline installation in that
disposable environment. It expressly required stopping on an unexpected dependency.
Neither decision authorizes TRUST-05, operational IAM, system/project environment
changes or production custody. General A01-TEST/A04-TEST remain proposed outside
this specific activity; G1 implementation authorization remains pending.

## Verified runtime and isolation preflight

- Approved interpreter: /usr/bin/python3.10, version 3.10.12; GCC 11.4.0 build.
- Reported platform: Linux 6.8.0-149-generic x86_64, glibc 2.35.
- Fresh disposable directory: /tmp/ai-soc-trust04d-e_auys_0, created with private
  temporary-directory permissions. No production credentials or root keys copied.
- Empty venv created using `/usr/bin/python3.10 -I -B -m venv --without-pip /tmp/ai-soc-trust04d-e_auys_0/env`.
  Existing project .venv/system Python remain unchanged.
- Planned installer bootstrap: existing OS-provided pip-22.0.2 wheel, not installed
  into the environment and not used to perform an installation. Its vendored
  packaging utilities were used only for metadata/marker/tag parsing.
- `unshare --user --map-root-user --net -- /usr/bin/true` succeeded.
- Initial sandboxed bubblewrap preflight failed on a NETLINK_ROUTE restriction;
  sandbox escalation for the same approved local isolation check succeeded.

Successful isolation preflight command (no cryptographic library import):

```bash
bwrap --unshare-all --die-with-parent --new-session --ro-bind /usr /usr --ro-bind /lib /lib --ro-bind /lib64 /lib64 --proc /proc --dev /dev --dir /tmp --clearenv --setenv PATH /usr/bin:/bin -- /usr/bin/python3.10 -I -S -B -c 'import os,socket;print("isolated namespace ready");print(os.path.exists("/home"),os.path.exists("/run/postgresql"));print(open("/proc/net/route").read())'
```

Output confirmed /home and /run/postgresql absent and no routing-table entries.
System libraries were read-only; no project/home/credential/database directories
were exposed. This is **preflight evidence**, not a claim cryptographic tests ran
inside that environment. No cryptography test backend was imported or its OpenSSL version measured.
HTTPS metadata retrieval used Python TLS, not a signature compatibility routine.
Python 3.10 approval is a TEST exception, not a reversal of its recorded lifecycle
risk or a production-runtime approval.

## Dependency attempt and exact blocker

The acquisition helper was saved only under the disposable directory. It used
Python -I -S -B, a no-proxy HTTPS opener restricted to pypi.org and
files.pythonhosted.org, with redirect/size checks. No application module was imported.

The initial candidate list was cryptography==50.0.2, cffi==2.0.0 and pycparser==2.22.
These were tentative pins to validate, **not** a complete approved lock. Official
metadata retrieval began at https://pypi.org/pypi/cryptography/50.0.2/json.
The release and Requires-Python metadata passed the helper's Python compatibility
check. Active dependency parsing then encountered **typing-extensions**, not present
in that initial candidate list.

The helper stopped with:

```text
AssertionError: unexpected dependency: typing-extensions
```

This is an acquisition-plan completeness failure, not an installation failure,
cryptographic failure or finding that typing-extensions is unsafe. Its exact required
constraint/version was not retained before the stop and is **NOT RESOLVED** here.
No speculative version, artifact URL or checksum is provided for it.

Per the owner's mandatory stop condition, no additional dependency was silently
added and no subsequent acquisition/install/test step was run. Zero wheels were
downloaded; zero package artifact hashes were verified in this attempt; no complete
requirements.lock/dependency-lock.json was produced. The empty venv contains no
installed cryptography 50.0.2, CFFI, pycparser or typing-extensions from this task.
The system cryptography 3.4.8 was neither selected nor imported as a substitute.

The helper contains a planned exact-wheel tag selection, second metadata retrieval,
SHA-256 comparison, binary-only allowlist and pinned lock writer, but execution did
not reach those steps. Their presence is not evidence of successful installation.

## Decision required

Request explicit permission to expand the candidate resolution to include the
PyPI-declared typing-extensions requirement, under the same exact-version,
compatible-wheel, independent official hash and offline-install restrictions.
Only after its constraint and full transitive closure are resolved can a complete
pin/hash plan be validated. Stop again if another unexpected requirement, unavailable
wheel, mismatch, source build or out-of-scope action appears. No root/application
or TRUST-05 authority follows from that permission.

**Runtime exception: APPROVED FOR TRUST-04D ONLY**  
**Dependency resolution: BLOCKED / INCOMPLETE**  
**Installation: NOT_RUN**  
**Cryptography/OpenSSL test runtime: NOT_LOADED**

## Authorized continuation and final assessment — 2026-11-16

This section supersedes the earlier dependency-stop status without erasing it.
The owner separately authorized TRUST-04D TEST execution, official PyPI binary-wheel
acquisition/offline installation, and required typing-extensions. No broader A01/A04
or TRUST-05 approval follows.

Python 3.10.12 TEST exception was used in /tmp/ai-soc-trust04d-e_auys_0/env.
Verified official PyPI wheel set: cryptography 50.0.2, cffi 2.0.0, pycparser 2.22,
typing-extensions 4.15.0. The latter is required by cryptography's Python <3.11 marker.
All active dependencies were reviewed and pinned; no additional package was installed.
The artifact filenames, tags, URLs, exact hashes and runtime checks are retained in
[dependency-lock.json](../../tests/iam/fixtures/trust04d_offline_validation/dependency-lock.json).
Each wheel SHA-256 matched separately retrieved official PyPI metadata. This proves
artifact identity relative to HTTPS metadata, not publisher-key authentication.
PyPI and wheel Requires-Dist strings differed in formatting; parsed requirement
normalization established equality before installation. No constraint was waived.

Installation used the OS pip wheel as a zip-imported tool, not an installed dependency,
with --isolated --no-index --require-hashes --only-binary=:all: --no-deps and the
pinned local wheelhouse. See retained install_offline.py and requirements.lock.
The first harness attempt used the wrong RFC container field and stopped before
verification; corrected to original records without changing public inputs.

Installation and tests ran in bubblewrap's separate network/PID namespaces, cleared
environment, read-only /usr and libraries, no home/application tree or database socket,
and only the disposable /tmp work directory writable. No network routes were present.
Project .venv, system Python and dependency declarations were unchanged.
Runtime backend reported OpenSSL 4.0.3 29 Sep 2026. This is observed metadata,
not a FIPS or security certification. No package index was accessible during installation.

Exact focused test command (installation used the same isolation with install_offline.py):

```sh
bwrap --unshare-all --die-with-parent --new-session --ro-bind /usr /usr --ro-bind /lib /lib --ro-bind /lib64 /lib64 --proc /proc --dev /dev --dir /tmp --bind /tmp/ai-soc-trust04d-e_auys_0 /tmp/ai-soc-trust04d-e_auys_0 --chdir /tmp/ai-soc-trust04d-e_auys_0 --clearenv --setenv PATH /usr/bin:/bin --setenv LANG C.UTF-8 -- /tmp/ai-soc-trust04d-e_auys_0/env/bin/python -I -B /tmp/ai-soc-trust04d-e_auys_0/compatibility.py
```
