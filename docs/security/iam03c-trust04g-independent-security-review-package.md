# TRUST-04G independent security-review package

2026-11-16. TRUST-04G read-only research and documentation. No cryptographic execution, dependency changes, new trust, owner approval or independent cryptographic sign-off. Existing frozen proposals remain unchanged.

## Review packet and trust boundary

The authoritative candidate is the unchanged [TRUST-04 wire](iam03c-trust04-root-policy-wire-spec.md),
[anchor contract](iam03c-trust04-anchor-and-verifier-contract.md) and
[error/vector matrix](iam03c-trust04-vector-and-error-matrix.md).
[TRUST-04F predicates](iam03c-trust04f-strict-ed25519-normative-profile.md) and
[04G source ledger](iam03c-trust04g-source-level-verification-evidence.md) distinguish
frozen requirements, proposed equation clarification and source findings. No owner
approval is supplied by inclusion in this packet.

Text diagram: bounded untrusted TEST proof -> structural/canonical/domain/context
validation -> independently authenticated immutable expected pins -> eligible exact
custodian mapping -> complete A/R/S predicates and pure equation -> non-authorizing
TEST signature evidence. Separate IAM policy/current-authority/final execution gate
would remain necessary later; this component cannot supply them. No database,
network/key discovery, TOFU, caller trusted flag or self-signed manifest creates pins.
The conceptual diagram does not reorder fifteen observable diagnostic stages below.

A=canonical on-curve point in H excluding O; R=canonical on-curve point in H including
O if equation valid; S=exact32 unsigned LE in[0,L). Pure M is exact frozen domain/NUL/
U64BE/body frame, never frame digest, ph/ctx or fallback. E1 reference and conditional
E8 equivalence require independent review under D04F-03. All17 body fields, digest
preimages, TEST-only customer3/quorum2 and lifecycle conditions remain unchanged.

## Independent reviewer scope and sign-off

Owner must name a qualified Ed25519 cryptographer/implementation reviewer independent
of prototype author and sole oracle author, with conflicts disclosed. Separate golden
review must establish independent derivation. No identity or credential is fabricated
here; Codex self-review and source summaries are not independent security sign-off.
Require a dated verdict tied to exact documents, source commits, feature/build graph,
mathematical assumptions, API composition and later prototype code/artifacts.

Review packet checklist: F-A01–F-E03->API map; canonical/decompression/subgroup proof;
A/R identity asymmetry; scalar constructors/features; equation and mode/transcript;
source/binary assumptions; invalid anchor registration; full adversarial classes;
error priority/counters; supply chain/licenses/advisories; independent golden oracles;
known tcId152; residual threats and owner decisions. Findings need severity, required
correction, evidence and closure review. No unresolved high/critical acceptance or
trust-boundary finding may be waved through by successful positive vectors.

Accept for a later TEST prototype only if each required predicate has a reviewed
established enforcing API, no hidden semantic restriction excludes allowed inputs,
mode/transcript/equation are documented, dependencies/runtime are selectable and
reproducible, and tests/oracles are approved independently. Reject blacklist-only,
custom unreviewed curve math, source-to-binary assumptions, ph/ctx/fallback, R-identity
blanket exclusion, weakened A policy, synthetic/production promotion or self-approved
pins. REVIEW_REQUIRED keeps G1 blocked for source/audit/oracle uncertainty.

## Future corrective TEST authorization proposal

Candidate selection is unresolved: D composition is recommended for review, not
locked. Propose no new dependency list until reviewer picks exact APIs/artifacts;
possible dalek2.2.0/curve4.1.3 sources are research versions, not approval to install,
compile Rust or add a Python binding. Owner grant must enumerate exact selected
versions/features/transitives/artifact hashes, runtime and acquisition/build rules.
Existing 04D Python3.10.12 exception and wheel approval do not authorize new packages
or builds. No automatic environment fallback. No new harness/file path is created
or authorized by this document; future grant must name its exact isolated fixture
path and disposable environment, preserving all original public assets.

Future tests must be offline in disposable credential-free environment, no project
venv/system change, application imports, operational state, database/services or
persistent trusted root. Any required acquisition/installation/build is separately
explicit; no network during tests. Only public or disposable TEST material, no
production keys/enrollment/recovery, no IAM integration and no TRUST-05 implementation.

Sequence proposed: independent design/source review -> owner scoped prototype grant
-> reviewed code -> exact case152 reproduction and corrected full-boundary rejection
-> RFC3 preservation and A/R/S/equation negatives -> authorized complete210 corpus
comparison -> separately permitted independent project goldens/all26 -> reviewer
result acceptance -> owner G1 review. A collected library-only discrepancy may be
retained without classifying it as a strict-boundary success. Permission to collect
all discrepancies must explicitly supersede stop-on-first-failure for that collection;
otherwise stop rules remain. Any confirmed strict-boundary mismatch blocks acceptance.

For each run record exact interpreter/compiler/dependencies/features/CPU/backend,
source/artifacts/provenance, command/isolation, original verdict, raw backend result,
strict result/reason, applicability, exceptions and review. Preserve acceptable as
native semantics. PASS requires full approved acceptance including allowed edge
positives; FAIL includes forbidden accept or allowed-profile over-reject; unresolved
policy/source/oracle differences are REVIEW_REQUIRED, never majority-vote success.

Independent golden preparation cannot call the verifier under test as its oracle.
Require literal canonical bytes/preimages/frame/digests, separate independently
reviewed derivation and signature implementation or manual byte-level framing review,
exact revisions and TEST-only review records. Wrappers over the same backend are
not independent crypto engines. No expected literal or signatures are produced here.

## Vector inventory and coverage preservation

[Original manifest](../../tests/iam/fixtures/trust04c_public_vectors/manifest.json)
retains provenance/licenses; [04D results](../../tests/iam/fixtures/trust04d_offline_validation/results.json)
retain actual execution. All210 source IDs are accounted for: tcId1–152 recorded,
153–210 absent/NOT_RUN. Native totals117 valid/64 invalid/29 acceptable; executed
88 valid accepted/63 invalid rejected/1 acceptable accepted. Remaining153–159:
7 acceptable SmallOrderPublicKey;160–180:21 acceptable MixedOrderPublicKey;
181–209:29 valid;210:1 invalid mixed-order. No test result is inferred for58 cases.
RFC8032 section7.1 TEST1/2/3 retain three original PASS records, not project frames.
Future tests need exact152, every torsion/mixed-order/noncanonical/invalid encoding
class, S=0/L-1/L/L+1/high bits/aliases, valid in-range edges with independent equations,
R=O positive under admissible A, wrong messages/keys/modes/frame and all210 native
verdict dispositions. Reject forbidden key classes even when acceptable upstream.

All26 project cases below remain NOT_READY as complete independently reviewed golden
validation. Existing RFC/partial-corpus evidence is component-only. Expected outcomes
and fifteen diagnostic priorities are not changed.

| Case | Objective | Existing coverage / future evidence | Readiness |
| --- | --- | --- | --- |
| V04-01 | RFC 8032 positive message/key/signatures | RFC3 pass; project-specific frame not validated | NOT_READY |
| V04-02 | Frozen canonical body, key-set, manifest and full frame | Specified only; exact independently reviewed assets/results pending | NOT_READY |
| V04-03 | Two distinct eligible TEST customer signatures | Specified only; exact independently reviewed assets/results pending | NOT_READY |
| V04-04 | Three valid entries, all six input permutations | Specified only; exact independently reviewed assets/results pending | NOT_READY |
| V04-05 | Zero/one otherwise eligible signature | Specified only; exact independently reviewed assets/results pending | NOT_READY |
| V04-06 | Flip one bit of otherwise well-shaped signature | Specified only; exact independently reviewed assets/results pending | NOT_READY |
| V04-07 | Duplicate custodian/key entries; manifest duplicate key/material; source duplicate map | Specified only; exact independently reviewed assets/results pending | NOT_READY |
| V04-08 | Well-typed wrong tenant in expected versus proof; nested payload/manifest mismatch | Specified only; exact independently reviewed assets/results pending | NOT_READY |
| V04-09 | Wrong deployment UUID/kind/customer/domain with otherwise valid bytes | Specified only; exact independently reviewed assets/results pending | NOT_READY |
| V04-10 | Wrong environment UUID; environment_kind=PRODUCTION | Specified only; exact independently reviewed assets/results pending | NOT_READY |
| V04-11 | Ed25519ph/ctx/P-256 or mixed signature profiles | Specified only; exact independently reviewed assets/results pending | NOT_READY |
| V04-12 | Whitespace, escaped alias, unsorted object/set, time/UUID spelling alias; bool/float/exponent counter | Specified only; exact independently reviewed assets/results pending | NOT_READY |
| V04-13 | Unknown field in body/manifest/context/signature, including trusted flag or key URL | Specified only; exact independently reviewed assets/results pending | NOT_READY |
| V04-14 | Wrong computed root-set/manifest/payload digest, internally consistent outer claims | Specified only; exact independently reviewed assets/results pending | NOT_READY |
| V04-15 | Two valid plus invalid third signature | Specified only; exact independently reviewed assets/results pending | NOT_READY |
| V04-16 | Unknown custodian/key pair, wrong key signature under known pair | Specified only; exact independently reviewed assets/results pending | NOT_READY |
| V04-17 | Revoked root/key, expired source/body/key, or future test_time | Specified only; exact independently reviewed assets/results pending | NOT_READY |
| V04-18 | Missing, self-selected, corrupt or non-TEST anchor source/pin | Specified only; exact independently reviewed assets/results pending | NOT_READY |
| V04-19 | Older/newer policy/version/generation, wrong independent pin reference | Specified only; exact independently reviewed assets/results pending | NOT_READY |
| V04-20 | Synthetic IAM provenance or production request classification | Specified only; exact independently reviewed assets/results pending | NOT_READY |
| V04-21 | Malformed/noncanonical point/scalar, torsion/mixed-order keys, scalar >= L, corpus edge vectors | Partial152 corpus; strict mismatch;58 not run | NOT_READY |
| V04-22 | Wrong label/NUL/length/purpose/trailing bytes; future purpose | Specified only; exact independently reviewed assets/results pending | NOT_READY |
| V04-23 | Body/payload/frame/combined/depth/entry limit cap and cap+1 | Specified only; exact independently reviewed assets/results pending | NOT_READY |
| V04-24 | Multi-fault fixtures from section 2 and permutations | Specified only; exact independently reviewed assets/results pending | NOT_READY |
| V04-25 | SaaS provider-recovery custodian/delegation or platform key as signer | Specified only; exact independently reviewed assets/results pending | NOT_READY |
| V04-26 | Erroring backend/source or mutated result object/caller success flag | Specified only; exact independently reviewed assets/results pending | NOT_READY |

## Fifteen diagnostics — unchanged observable order

| Order | Diagnostic | Required review/test boundary |
| --- | --- | --- |
| 00 | LIMIT_EXCEEDED | Preserve frozen trigger, earliest-failure priority and source/crypto call counters; no later-stage override |
| 01 | SYNTHETIC_SOURCE | Preserve frozen trigger, earliest-failure priority and source/crypto call counters; no later-stage override |
| 02 | STRUCTURE_INVALID | Preserve frozen trigger, earliest-failure priority and source/crypto call counters; no later-stage override |
| 03 | BINDING_MISMATCH | Preserve frozen trigger, earliest-failure priority and source/crypto call counters; no later-stage override |
| 04 | SIGNER_DUPLICATE | Preserve frozen trigger, earliest-failure priority and source/crypto call counters; no later-stage override |
| 05 | CANONICAL_MISMATCH | Preserve frozen trigger, earliest-failure priority and source/crypto call counters; no later-stage override |
| 06 | DOMAIN_MISMATCH | Preserve frozen trigger, earliest-failure priority and source/crypto call counters; no later-stage override |
| 07 | ALGORITHM_UNSUPPORTED | Preserve frozen trigger, earliest-failure priority and source/crypto call counters; no later-stage override |
| 08 | ANCHOR_UNAVAILABLE | Preserve frozen trigger, earliest-failure priority and source/crypto call counters; no later-stage override |
| 09 | POLICY_STALE | Preserve frozen trigger, earliest-failure priority and source/crypto call counters; no later-stage override |
| 10 | SIGNER_UNKNOWN | Preserve frozen trigger, earliest-failure priority and source/crypto call counters; no later-stage override |
| 11 | KEY_REVOKED | Preserve frozen trigger, earliest-failure priority and source/crypto call counters; no later-stage override |
| 12 | TIME_INVALID | Preserve frozen trigger, earliest-failure priority and source/crypto call counters; no later-stage override |
| 13 | QUORUM_INSUFFICIENT | Preserve frozen trigger, earliest-failure priority and source/crypto call counters; no later-stage override |
| 14 | SIGNATURE_INVALID | Complete reviewed A/R/S/equation after all eligible metadata/threshold; no partial evidence |

Budget guards repeat as extents become observable. Well-shaped mathematical failure
remains SIGNATURE_INVALID, malformed size/hex/shape STRUCTURE_INVALID; unusable
independent source is ANCHOR_UNAVAILABLE under frozen source stage. No new public
identity error or failed foreign key detail. Distinct/revoked/threshold checks precede
math; every supplied eligible entry must validate, including invalid third. No change
to existing structural enums, IAM error codes or operational ordering.

## Supplemental T03 traceability

C=confirmed historical observation; H=conditional hypothetical path; O=outside
ROOT_POLICY crypto verification. Original threat model remains unchanged.

| Threat | Discrepancy / candidate implication | Required review / residual |
| --- | --- | --- |
| T03-01 forgery | C identity-A admitted; H bad pin permits forged vote | Full predicates/equation V04-21; host compromise persists |
| T03-02 stolen custodian | H weak second vote erodes threshold | Admissible independently pinned keys V04-03/17; custody external |
| T03-03 two-custodian collusion | O valid malicious quorum | Custody/ceremony; no algorithm can identify honest intent |
| T03-04 duplicate votes | H aliases/IDs simulate distinct votes | Canonical keys and duplicate rules V04-07; people independence external |
| T03-05 stale policy | O signature does not establish latest policy | Independent pins V04-19; source rollback remains |
| T03-06 revoked anchor | O valid point not eligible | Every entry revocation V04-17; live propagation unavailable |
| T03-07 cross-tenant replay | H valid crypto on foreign tenant | Independent context V04-08; caller context trust remains |
| T03-08 cross-deployment replay | H wrong site/environment | Expected binding/frame V04-09/10/22; migrations separate |
| T03-09 algorithm confusion | H permissive feature/mode selection | Fixed pure APIs/no fallback V04-11/21; build review |
| T03-10 canonical mismatch | H A/R encoding aliases plus body ambiguity | Exact bytes and canonical predicates V04-02/12/21 |
| T03-11 unknown fields | O curve library cannot reject extensions | Closed schema V04-13; upgrade review |
| T03-12 DB rollback | O unsupported current-state claim | Independent external state later; not solved |
| T03-13 checkpoint rollback | O no checkpoint purpose | Independent high-water/fork controls later |
| T03-14 recovery tampering | O recovery unsupported | Reject purpose V04-22; ceremony outside scope |
| T03-15 lost keys | O validator cannot recover custody | No quorum downgrade V04-05; availability loss |
| T03-16 malicious recovery | H valid-looking root substitution | No recovery purpose/TOFU V04-18/22; display/custody external |
| T03-17 SaaS escalation | H provider-selected pins | Customer-only anchors V04-25; infra admin access remains |
| T03-18 verifier compromise | O corrupted host fabricates result | Artifact review/no IAM consumer V04-26; no attestation claim |
| T03-19 time manipulation | O exact math not freshness | Explicit TEST time V04-17; trusted operational clock absent |
| T03-20 partial revocation | O verification not execution gate | Later serialization/freshness gate; TOCTOU/external effects |

Independent review acceptance is still PENDING. This packet does not constitute a
finished audit, named reviewer approval, tested correction or implementation grant.
