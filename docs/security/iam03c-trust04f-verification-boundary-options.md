# TRUST-04F verification-boundary options and supplemental threats

2026-11-16. TRUST-04F documentation-only review. Existing frozen proposals are unchanged; no implementation or independent cryptographic sign-off is claimed. All D04F decisions are PROPOSED — NOT APPROVED.

## Comparison and recommendation

Use the predicates F-A01–F-E03 in the [profile review](iam03c-trust04f-strict-ed25519-normative-profile.md).
Every option must enforce the entire conjunction, including R identity allowance;
none is selected, installed, tested or production-approved by this review.

| Approach | Classification | Security properties and shortcomings | Required evidence |
| --- | --- | --- | --- |
| A: tested PyCA/OpenSSL only | INSUFFICIENT | Saved tcId 152 violates F-A03. No conclusion about all library versions or uses. Key constructor length check is not point validation | Cannot adopt unchanged; exact internal path unresolved |
| B: vetted validation plus documented equation backend | SUITABLE_FOR_FURTHER_REVIEW | Complete A, R and S prechecks isolate acceptance; can preserve existing backend. More native dependencies, FFI and version coupling; public-key-only or blacklist-only boundary is REJECTED | Each predicate's established API/source, exact A/R asymmetry, canonical round trip, backend E1/E8/mode proof and differential corpus |
| C: independently maintained strict verifier | REQUIRES_MORE_EVIDENCE | Potential coherent implementation; strict labels do not guarantee H or permitted R=O. Dalek verify_strict source rejects small-order R, so unchanged use cannot implement frozen set | Exact pinned library/features, canonical and torsion-free API coverage, reviewed acceptance composition; supported Python binding/binary artifacts not established |
| D: independently reviewed dedicated TEST boundary composed from established APIs | SUITABLE_FOR_FURTHER_REVIEW | Makes all predicate/mode/error/counter contracts explicit; useful comparison reference. Self-written curve arithmetic or ad hoc crypto is REJECTED | Independent source/design review before code/tests; independent oracle, exact API contract and owner TEST scope; no production claim |

Recommend B inside the small dedicated TEST boundary D for further review, with a
separately reviewed C-based reference for comparison if it can express the full set.
Do not implement until that mapping exists. No alternative currently has sufficient
support/runtime/binary/security evidence for selection. A failed mapping is a stop,
not an invitation to relax R or A rules.

Concrete research leads: libsodium's public point predicate can be evaluated for A;
it rejects identity and cannot be applied blindly to R. Curve25519-dalek exposes
separate torsion-free and small-order concepts; a reviewed composition may express
our predicates, but must also establish canonical decoding and exact R behavior.
This is an API/source-review direction, not a cryptographic implementation recipe or
claim of an approved Python package. A single complete reviewed implementation is
preferable to two stacks if it meets every frozen rule.

Review each candidate's support policy, advisory history, audit scope, release/artifact
provenance, licenses, Python 3.10 TEST exception, wheel/ABI/platform support and pinned
transitives. Existing project runtime and 04D packages cannot silently change. Rust
FFI or new native binaries expand supply-chain/build review; performance is secondary
to correctness and bounded input. No new package version is recommended or cleared.
No benchmark or alternate-library execution occurred.

## tcId 152 and similar gaps

Existing source and result exact-byte reconstruction is in
[TRUST-04E](iam03c-trust04e-case152-evidence-reconstruction.md). Key is canonical O;
raw message was `message`; R=B and S=1. Backend returned normally. No full project
frame, anchor enrollment, key predicate or quorum was tested. On this observation,
backend-only verification lacked effective nonidentity-A enforcement. Both equations
can admit this tuple, so it does not distinguish their internal use. OpenSSL source
path/build internals remain unverified; no reverse engineering or new run occurred.

The native acceptable verdict is a different policy, not a permission to admit O.
Other pure torsion A, mixed-order A/R, noncanonical y/sign aliases, undecodable points,
S>=L and truncation/extension require independent coverage. An identity blacklist
cannot establish on-curve, canonical or subgroup membership and is insufficient.
Do not write application field arithmetic or custom blacklists to bridge API gaps.

If malformed keys enter independently authenticated pins, forged endorsement could
undermine a vote without a secret, potentially reducing quorum security. This is a
conditional threat, not an observed root enrollment or operational exploit. Strict
pinning alone binds the wrong key if enrollment fails admissibility. Distinct bytes
and custodian IDs are not proof of real-person independence. Customer control,
revocation and two independent valid votes remain required even after crypto passes.

## Conceptual chain versus frozen observable order

Conceptually: envelope parsing -> canonical/budget/domain checks -> independent pins
-> A and signature admissibility -> equation -> uniqueness/revocation/quorum -> TEST
evidence -> separate operational IAM gate. This describes dependencies, not a new
execution/error order. Literal post-crypto uniqueness/revocation/quorum conflicts with
frozen early metadata checks. Owner review D04F-06 must explicitly preserve existing
order; no change is authorized or recommended.

Actual frozen order remains LIMIT_EXCEEDED (at observable boundaries), SYNTHETIC_SOURCE,
STRUCTURE_INVALID, BINDING_MISMATCH, SIGNER_DUPLICATE, CANONICAL_MISMATCH,
DOMAIN_MISMATCH, ALGORITHM_UNSUPPORTED, ANCHOR_UNAVAILABLE, POLICY_STALE,
SIGNER_UNKNOWN, KEY_REVOKED, TIME_INVALID, QUORUM_INSUFFICIENT, SIGNATURE_INVALID.
Admissibility/equation work is inside the final math stage after metadata/eligibility
and threshold precheck, with no evidence for earlier failures. Invalid independent
anchor source maps to its existing source stage; enrollment validation is separate.
Do not move subgroup work ahead of prior failures and thereby change diagnostics.
For sufficient eligible entries, sorted custodian verification stops on failure and
returns no partial evidence; two valid plus invalid third rejects. Independent anchor
registration must reject unusable material, with no self-signed bootstrap.

Successful output remains immutable non-authorizing TEST SignatureEvidence, bound
to exact frame/context/pin/signers. No ALLOW, current authority, provider privilege,
role assignment or production evidence. Existing admission, policy, provider,
is_current(), APIs, audit logic and execution gates remain unchanged and unconnected.

## Supplemental threat traceability — original T03 model unchanged

C=confirmed observation; H=hypothetical path; O=outside offline verification.
Every mitigation below is a review/test requirement, not implemented protection.

| Threat | Discrepancy relevance / evidence | Required control and future case | Residual risk |
| --- | --- | --- | --- |
| T03-01 forged signatures | C identity-A acceptance; H forged vote after bad enrollment | Full A/R/S/equation; P-A/R/S/E, V04-21 | Verifier/backend compromise |
| T03-02 stolen custodian key | H another weak vote could reduce threshold protection | Valid independent pins, admissibility, two votes; V04-03/17 | Custody/revocation availability |
| T03-03 two colluding custodians | O not solved by point validation | Independent custody/ceremony | Valid malicious quorum |
| T03-04 duplicate counting | H aliases could misrepresent distinct keys | Canonical A plus duplicate custodian/key/material rules; V04-07 | False enrollment/people independence |
| T03-05 stale policy | O no fresh-state guarantee from strict math | Exact independent policy/pin comparison; V04-19 | Rollback of trusted source |
| T03-06 revoked anchor | O mathematical key validity not eligibility | Reject every supplied revoked entry; V04-17 | Stale revocation observation |
| T03-07 cross-tenant replay | H weak-key equations do not replace tenant checks | Expected tenant binding; V04-08 | Compromised context supplier |
| T03-08 cross-deployment replay | H domain/frame checks still required | Deployment/environment expected context; V04-09/10/22 | Legitimate migration fencing outside scope |
| T03-09 algorithm confusion | H selecting permissive mode/backend | Fixed pure profile, vetted backend, no fallback; V04-11/21 | Undocumented build changes |
| T03-10 canonical mismatch | H point aliases plus JSON ambiguity | Canonical A/R and unchanged wire bytes; V04-02/12/21 | Unreviewed upgrades/display |
| T03-11 unknown signed fields | O math does not enforce closed schema | Reject extensions before math; V04-13 | Future schema drift |
| T03-12 DB rollback | O no change | Independent checkpoint/freshness gates later | Valid old state remains replayable without external state |
| T03-13 checkpoint rollback | O unsupported ROOT_POLICY state claim | Independent high-water/fork controls later | Store compromise |
| T03-14 recovery tampering | O no recovery purpose | Unsupported purpose rejects; V04-22 | Separate ceremony required |
| T03-15 lost keys | O strong validation cannot restore custody | No quorum downgrade; V04-05 | Availability loss |
| T03-16 malicious recovery | H weak keys cannot authorize unsupported recovery | ROOT_POLICY-only subset; V04-22 | Compromised display/owner process |
| T03-17 SaaS escalation | H provider-controlled bad enrollment | Customer-only independent anchors, no provider inheritance; V04-25 | Infrastructure administrator access |
| T03-18 verifier compromise | O local result may be fabricated | Independent review, artifact pins, no IAM consumer; V04-26 | Host compromise cannot be fixed by equations |
| T03-19 time manipulation | O valid signature not current | Explicit TEST time/window checks; V04-17 | Authentic operational time unavailable |
| T03-20 revocation propagation | O strict math not immediate revocation | Independent state/final execution gate later | TOCTOU/process boundaries |
