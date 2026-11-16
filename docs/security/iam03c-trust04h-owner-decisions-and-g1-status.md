# TRUST-04H owner decisions and G1 status

2026-11-16. TRUST-04H documentation-only proposal. No code, crypto execution, new dependency, trust enrollment, reviewer appointment or approval. All owner decisions remain PROPOSED — NOT APPROVED.

## Decision package

H-COMP-1 is an exact **PROPOSED design composition**, not an approved deployable
build: curve25519-dalek4.1.3 canonical/point/subgroup/scalar predicates with A-only
identity exclusion, ed25519-dalek2.2.0 ordinary pure verifier under full preconditions,
and unchanged independent TEST anchor/quorum/result policy. No source patches,
custom curve arithmetic or operational IAM integration. Composition safety is
REVIEW_REQUIRED; R-identity handling has source support but no composed test evidence.
No source-level security contradiction in this proposal was found. Excluded strict
entry points remain unsuitable alternatives, not permission to change the profile.

## Six decisions — owner must decide separately

| Decision | Recommended decision / evidence | Remaining uncertainty / reviewer input | Required owner action / consequence of rejection | Status |
| --- | --- | --- | --- | --- |
| D04F-01 | Reaffirm canonical/on-curve/H/nonidentity A and exact independent enrollment; frozen4 and C1/C2 | Review helper/canonical/subgroup semantics, immutable bytes and tcId152 negative | Accept invariant; rejection holds work for explicit architecture reconsideration, never default permissive A | PROPOSED — NOT APPROVED |
| D04F-02 | Reaffirm canonical on-curve H R with identity permitted, exact LE S in[0,L); C1/C3/C5 | Review identity-R positive, S boundaries, no compatibility flags | Accept exact asymmetry; rejection requires formal profile review, no silent R!=O or S!=0 addition | PROPOSED — NOT APPROVED |
| D04F-03 | E1 reference through C4; E8 only under documented equivalence/full predicates | Reviewer confirms algebra, exact mode/transcript and source path; OpenSSL internals not assumed | Approve reference choice or retain unresolved equation; no implementation while unreviewed | PROPOSED — NOT APPROVED |
| D04F-04 | Submit H-COMP-1 for independent review; prefer single-family standalone TEST reference before any FFI | Full artifacts/commit lock/support/features/transitives/runtime/binding unresolved | Approve research candidate only; if rejected, keep NO-GO and seek another vetted composition, no ad hoc curve math | PROPOSED — NOT APPROVED |
| D04F-05 | Appoint qualified independent named reviewer plus independent golden review | No reviewer contracted, no authentic report; owner must verify expertise/conflicts | Appoint/contract separately with rejection freedom; otherwise sign-off remains pending | PROPOSED — NOT APPROVED |
| D04F-06 | Later narrow prototype authorization only after review and exact build/file grant | No runtime/dependency acquisition/code/testing is authorized here | Accept separate future scope or keep all corrective TEST execution forbidden; no inference from prior04D grant | PROPOSED — NOT APPROVED |

No approval register changed. A01-TEST/A04-TEST remain unapproved beyond historical
specific04D activity; production A01/A04 and A02/A03/A05 pending. Owner appointment,
reviewer's technical verdict and owner's implementation grant are distinct events.

## Proposed future corrective TEST authorization request — not executable

Owner should approve only after independently reviewed H-COMP-1 revision and exact
record below are completed; this is not a request to execute now. Unresolved fields
are blockers, not defaults or permissions to resolve packages at install time.

| Authorization field | Proposed scope / currently missing item |
| --- | --- |
| Exact composition | H-COMP-1 plus accepted reviewer conditions, exact approved report/source revisions |
| Dependencies | Research candidates curve4.1.3/ed25519 2.2.0 only at design level; no packages currently approved; full transitive/features/artifact/commit lock, current security/support/license review must precede grant |
| Runtime | Exact compiler/toolchain/target and optional Python interpreter/binding to be selected independently; previous Python3.10.12 exception is not Rust/build approval |
| TEST implementation paths | Proposed new isolated tests/iam/fixtures/trust04h_corrective_prototype/ only if separately approved and absent; no path or harness created now; report outputs must be named in later grant |
| Disposable environment | Proposed /tmp/ai-soc-trust04h-* only after explicit grant; no project venv/system changes, application imports, credentials, production/network services or persistent trust |
| Permitted operations | Explicit offline public signature verification and TEST hashing/signing only if separately granted; no production key/enrollment/recovery; signing/goldens conditional on independent oracle scope |
| Reviewer gate | Genuine APPROVED_FOR_TEST_PROTOTYPE or verified closure of APPROVED_WITH_CONDITIONS plus later actual-code review; no fake reviewer record |
| Vector scope | Exact152 reproduction, all3 original RFC and all210 Wycheproof native verdicts preserved, full A/R/S/equation negatives and allowed positives; all26 project cases with independent assets |
| Execution isolation | No network during tests; any dependency acquisition/build/install needs separate exact permission; no DB/Docker/Wazuh/Shuffle/Ollama or IAM consumers |
| Reproducibility | Exact commands/artifacts/features/backend/CPU versions, isolation, input provenance, native/backend/strict results and sanitized failures; no verifier-derived oracle |
| STOP conditions | Forbidden accept or allowed-profile over-reject; failed provenance/hash/build pin; unexpected dependency; unresolved reviewer condition; missing independent expected asset; source/profile conflict; unknown backend; user-work overwrite; operational reach |
| Full-corpus collection | Explicitly decide whether a bounded discrepancy-collection run can continue safely after mismatch; acceptance remains blocked on every incompatibility, prior stop rules otherwise apply |
| Result boundary | Immutable non-authorizing TEST evidence only; no ALLOW/current authority/provider privilege; no TRUST-05 or operational integration |

No dependency install, reference build, TEST fixture signing or rerun occurs under
this request. If independently derived goldens cannot be established, report NOT_READY;
do not generate expected outputs solely with the component under test.

## G1 technical versus authorization status

| Gate | Assessment |
| --- | --- |
| Normative profile | Documented unchanged A/R/S; permitted identity-R explicit |
| Component selection | Exact research design PROPOSED; reproducible supported artifacts not selected |
| Source evidence/equation | Candidate path supported; independent helper/composition correctness and binary behavior unverified |
| Backend safety | REVIEW_REQUIRED; single-family does not establish audit or host integrity |
| R identity | SOURCE_SUPPORTED design route; independently sourced positive/composed tests absent |
| Independent review packet | Prepared; NOT_APPOINTED, no verdict/sign-off |
| Corrective TEST | NOT_AUTHORIZED; no harness/environment/code/dependency changes |
| Vectors/goldens |58 NOT_RUN, all26 complete project goldens NOT_READY |
| G1 technical | BLOCKED |
| G1 implementation authorization | PENDING |

Recommended next action is owner appointment/contract of the independent reviewer and
submission of these exact materials. No further code or documentation milestone is
a substitute for authentic independent review. Resolve findings, exact artifact/runtime
choices and explicit owner scope before proposing corrective execution; do not
begin TRUST-05 or resume04D tests automatically.

## Validation and preservation

Preflight read instructions/historical handoff, inspected tracked/staged/untracked
Git state, git diff --check and cached check. Current explicit four-document scope
supersedes the handoff's older task-specific scope without editing it. All required
local documents/evidence were present; they were inspected read-only. Source research
was primary HTTPS documentation/text only, no package/executable acquisition.

Check all20 threat IDs,26 project IDs,15 ordered diagnostics, source210/recorded152/
remaining58 and3 RFC inventory; local links, whitespace and both diff checks; raw
existing-file bytes and Git index identical to preflight, only four authorized new
reports added. No hashing was used for preservation. No cryptographic imports,
verification/signing/hashing, pytest, package installation, DB/services/Docker,
source/test/fixture/dependency/approval edits, commits or pushes performed.

Companions: [composition](iam03c-trust04h-exact-verification-composition.md),
[R/backend risks](iam03c-trust04h-r-identity-and-backend-risk-review.md),
[appointment packet](iam03c-trust04h-independent-reviewer-appointment-package.md).
