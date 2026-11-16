# SEC-02 — Git secret prevention

Verified 2026-11-14 on branch `master`, HEAD `8bffe403ab287fedd391586ef26ab28db5472e12`.
SEC-01 classifications in `~/ai-soc-security-reports/sec01-prepush-review.md`
are the authority for these exceptions; no new finding was automatically accepted.

## Scope and files

Changes are limited to `.gitignore`, `.gitleaks.toml` and this document.
Application code, security policy identifiers, test fixtures, regression hashes,
IAM policies, migrations, credentials, Git history and the index are unchanged.
No commit, push, external service call, database access or credential rotation occurred.
Existing untracked IAM readiness documentation and both terminal artifacts remain
untouched. Recovery is to revert only these SEC-02 edits, preserving existing work.

## Ignore rules

| Category | Added patterns | Boundary |
| --- | --- | --- |
| Environment variants | `.env.*`, `!.env.example` | Existing `.env` rule remains; root and nested reviewed templates remain visible |
| Keys/certificates/stores | `*.key`, `*.pem`, `*.crt`, `*.cer`, `*.der`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore` | Explicit file extensions, not source/deployment directories |
| SSH private identities | `id_rsa`, `id_ecdsa`, `id_ed25519` | Exact basenames; public `.pub` siblings remain visible |
| Local credentials | `credentials.local.*`, `secrets.local.*` | Explicit local naming convention; unrelated credential-handling source remains visible |
| Runtime secret overrides | `*.secrets.json`, `*.secrets.yaml`, `*.secrets.yml` | Explicit secret-bearing filename convention; ordinary deployment templates remain visible |
| Private scan reports | `ai-soc-security-reports/`, `gitleaks-report.*` | Named private report destinations; security documentation remains visible |

Public certificates/test certificates may eventually need a deliberate, reviewed
exception to an extension rule. None is currently tracked. These patterns do not
cover every possible secret filename, prevent `git add -f`, or protect files
already tracked. No entire source, documentation or deployment directory is ignored.

Ignore validation used `git check-ignore --no-index -q -- <candidate>` for 37
positive/negative cases, including nested environment variants, every added pattern
category, `.env.example`, source, documentation, Compose, gateway configuration,
Gitleaks configuration and SSH public-key siblings. Ten of the initial ten required
sensitive-path checks failed before the change; all final assertions passed.

`git ls-files -ci --exclude-standard -z` returned zero paths: no existing tracked
file is hidden by the new ignore rules. `git ls-files -- .env` returned nothing;
`.env` remains ignored and untracked. Its existing mode is 0600. It was neither
staged, modified nor excluded from Gitleaks detection.

## Gitleaks exceptions

Installed Gitleaks build metadata identifies **v8.30.1** (Go **go1.26.5**).
`gitleaks version` itself reports that the version is set by the build process.
The tested binary SHA-256 is
`4785bbc0e998a7a597736347ec6b4a0bf87a24d288ff0fcf40819661c76be5b1`.
No existing repository Gitleaks configuration was present at entry.

A repository-level configuration is justified because the reviewed false positives
occur in reachable history as well as current files; changing comments/fixtures
would leave historical findings and risk altering security regression contracts.
`.gitleaks.toml` extends **all default rules** with four targeted allowlists:

| Exact file | SEC-01 finding IDs | Exact source lines reviewed | Rationale |
| --- | --- | --- | --- |
| `services/api/app/analysts/inference.py` | H01 / W02 | 220 | Versioned token-accounting comparison, not a credential |
| `tests/analysts/test_analyst_inference.py` | H02 / W03 | 25 | Synthetic token-accounting policy identifier |
| `tests/analysts/test_ollama_inference.py` | H03 / W04 | 24 | Ollama token-accounting policy identifier |
| `tests/api/test_api_routes_offline.py` | H04–H19 / W05–W20 | 59, 69, 70, 71, 72, 74, 75, 82, 83, 84, 85, 88, 89, 92, 93, 110 | Fifteen expected HTTP response SHA-256 entries and the OpenAPI SHA-256 expectation |

The 19 full source-line regexes retain exact noncredential values and context.
Each allowlist targets only `generic-api-key`, requires **AND** between an anchored
exact repository-relative path and an anchored exact line, and uses
`regexTarget = "line"`. No blanket hash pattern, whole-file exclusion, commit
exclusion, broad test-directory exclusion, disabled rule or baseline is used.
Line-number comments record SEC-01 evidence; line numbers themselves are not the
match condition. An unchanged reviewed line can move within its exact file; a
changed identifier, hash or surrounding line must be reviewed again.

Gitleaks retains a leading newline in some line contexts. Patterns allow that
single optional newline, without broadening the source-line content. Initial
exact-line patterns without it left all 19 findings visible; the corrected
configuration was rescanned. The SEC-01 report describes the digest family as
HTTP/route snapshots; direct source inspection confirms the final listed line 110
is specifically `OPENAPI_SHA256`. That value and all source files are unchanged.

Run scans **from the repository root with source `.`**. Absolute source arguments
can produce absolute finding paths that intentionally do not match the exact
relative-path exceptions; this fails visibly rather than broadening exceptions.

## Raw and configuration-filtered results

All scans were local. Reports were written only under private
`/tmp/sec02-review` (directory 0700); findings were redacted at 100% and reduced
to rule/path/line/commit/fingerprint metadata before inspection. Values and matching
source lines are not retained in those reports or included here. Scanner output
was captured rather than echoed. No network was used.

“Raw” means default installed rules with **no SEC-02 exceptions**, not unredacted
output. `/tmp/sec02-review/raw.toml` contains only:

```toml
[extend]
useDefault = true
```

| Scope | Raw findings / exit | Filtered findings / exit | Interpretation |
| --- | --- | --- | --- |
| Reachable local history, `--all` | 19 / 1 | 0 / 0 | All 19 reviewed false positives handled; six commits in scope |
| Working directory | 20 / 1 | 1 / 1 | Only `.env:5` remains; ignored local PostgreSQL credential is deliberately not suppressed |
| Staged diff | 0 / 0 | 0 / 0 | Index delta is empty; this does not certify a future staged patch |

SEC-01 also identified a separate configured Wazuh credential in ignored `.env`
that the default scanner did not flag. Neither configured credential was copied
into this configuration/document, rotated or used for authentication. An ignored
local secret is not a Git leak, and a nonzero directory scan is expected here.
Do not suppress `.env` merely to produce a zero directory count.

The initial configuration validation returned unchanged filtered counts of 19/20;
this exposed the newline-context issue above. After correction, the six final
repository scans produced the table above. No new finding classification or test
assertion was weakened to obtain it.

Exact command families (replace MODE with `raw` or `filtered`, and CONFIG with
`/tmp/sec02-review/raw.toml` or `.gitleaks.toml`, respectively):

```sh
gitleaks git --log-opts=--all . --config=CONFIG --redact=100 --no-banner --no-color --ignore-gitleaks-allow --gitleaks-ignore-path=/dev/null --report-format=json --report-path=/tmp/sec02-review/history-MODE.json
gitleaks dir . --config=CONFIG --redact=100 --no-banner --no-color --ignore-gitleaks-allow --gitleaks-ignore-path=/dev/null --report-format=json --report-path=/tmp/sec02-review/working-tree-MODE.json
gitleaks git --pre-commit --staged . --config=CONFIG --redact=100 --no-banner --no-color --ignore-gitleaks-allow --gitleaks-ignore-path=/dev/null --report-format=json --report-path=/tmp/sec02-review/staged-MODE.json
```

The execution wrapper `/tmp/sec02-review/scan.py` used absolute CONFIG paths,
removed GITLEAKS_CONFIG environment overrides, recorded exact argument arrays and
exit codes, and sanitized report fields. Exit 1 denotes detected findings, not an
execution failure. Final scans include this documentation and final ignore rules.

## Exception boundary checks and regression safety

Temporary synthetic files outside the repository tested the configuration through
the installed scanner, not a second regex implementation:

- All 19 reviewed lines under their exact relative paths: **19 raw, 0 filtered**.
- New synthetic credential-shaped values in each of the four approved files:
  detected; the file paths alone do not suppress them.
- An altered digest in the otherwise approved response-digest context: detected.
- An unchanged reviewed line at an unapproved path: detected.
- An unrelated default `github-pat` rule canary: detected.
- Total negative cases: **7 detected**, including both new API-file cases.

These canaries are locally generated synthetic strings, never valid provisioned
credentials or externally tested values. The first temporary positive test used
an absolute scan path and reflagged all reviewed lines; its harness was corrected
to scan `.` from the synthetic root. Adjacent canaries initially produced one
combined scanner match; separating them with blank lines yielded seven distinct
findings. No repository code, assertions or allowlist scope changed for those
harness corrections.

The established safe selection ran unchanged:

```sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python /tmp/iam03c_review_offline.py > /tmp/sec02-review/offline.log 2>&1
```

**1,892 collected, 1,892 passed in 78.51 seconds**, matching baseline. The runner
uses `tests/offline-selection.json`, synthetic settings, an unusable database
module, blocked engine/session construction/connections and real HTTP/socket
transport guards. Pytest cache/bytecode writes are disabled; temporary fixtures
stay under `/tmp`. Subprocess import/route checks apply their own guards.
The 214 excluded cases and unrestricted pytest were not executed. No PostgreSQL,
Wazuh, Ollama or scheduler was started or contacted.

Final checks passed: in-memory compilation of **164 Python files** under
`services/api`, `tests` and `scripts`; `git diff --check`; and explicit whitespace
and final-newline checks of all three changed/new files. Bytecode-writing compileall
and unrestricted pytest were excluded in favor of the guarded checks. Content
hashes of all pre-existing tracked/untracked inputs and index bytes were compared
with the entry manifest: only `.gitignore` differs; the index is unchanged.
No tracked files match the ignore rules, and the staged file list remains empty.
An exact-value check also confirms neither configured local password appears in
any SEC-02 changed file. The installed scanner binary hash is unchanged.

## Limitations, remaining risks and push verification

Ignore rules are staging assistance, not secret detection or access control. They
do not remove historical/tracked content, block forced adds, protect arbitrary
filenames or stop future plaintext output from provisioning tools. The scanner
must actually be run: this phase does not install hooks, CI or automatic enforcement.
Default detector blind spots, encodings/archives and unreachable history remain
outside any promise of completeness. Keep private reports outside the repository.

Exact exceptions can reflag benign formatting/path changes, which is deliberate.
They also suppress the same unchanged reviewed line at the same path in future
history; they are not cryptographic proof of a value's meaning in every future use.
Any new context, value or finding requires independent review. Neither the raw
scanner nor these exceptions establish operational IAM authority.

SEC-01 found neither configured password in inspected reachable blobs. This phase
has no evidence requiring rotation or history rewriting. Any owner-known earlier
external disclosure still requires separate credential remediation authorization.
Local remote-tracking refs do not prove current GitHub visibility; no fetch or
remote inquiry was performed.

**GitHub push remains NO-GO for this unfinished release preparation:** these
SEC-02 changes are not staged or committed, the two accidental untracked terminal
artifacts remain, and no exact future staged/committed release tree has been
approved. The filtered current history is clean; the remaining directory finding
is an expected ignored local credential, not a reason to hide it.

Recommended next milestone: **SEC-03 — final intended-change and pre-push review**,
with separate authorization for any staging/commit/push actions. Review the
untracked IAM document and exclude accidental artifacts. After the exact intended
index is prepared, repeat raw and filtered history/directory/staged scans, inspect
all staged filenames and any newly tracked ignored files, verify `.env`/keys/reports
are absent, and require a clean filtered history/staged result. Treat any directory
finding by scope and provenance rather than forcing a zero. Recheck configuration
selection and tool version. Only then request/obtain explicit push authorization;
no push or commit occurs under SEC-02.

SEC-02 STATUS: COMPLETE  
GITHUB PUSH: NO-GO  
NEXT STEP: Recommendation only — SEC-03 final intended-change and pre-push review.
