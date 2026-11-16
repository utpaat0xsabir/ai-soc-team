# TRUST-04A proposed TRUST-05 implementation boundary

2026-11-16. **Plan only: PROPOSED — NOT APPROVED. No files below are created now.**
[Owner proposals](iam03c-trust04a-owner-decision-package.md),
[dependency/vector prerequisites](iam03c-trust04a-dependency-and-vector-review.md),
[G1 authorization checklist](iam03c-trust04a-g1-authorization-checklist.md).

## 1. Entry gate and smallest outcome

Do not begin TRUST-05 until exact A01-TEST/A04-TEST/code/test decisions are explicit,
dependency/profile evidence is accepted and independent golden assets are approved.
No earlier structural-design authorization or READY_FOR_OWNER_REVIEW statement
opens that gate. If dependency/vector preparation needs additional activities,
authorize those separately first; do not hide them inside verifier implementation.

The sole accepted success output is the exact immutable TEST SignatureEvidence
specified by TRUST-04, not IAM ALLOW, authenticated identity, CURRENT authority,
issuer registration, snapshot or execution capability. Failure returns one fixed
safe code and no partial evidence. Production status stays NO-GO even after future
algorithm/quorum tests pass.

## 2. Exact recommended future file scope

All paths are proposals to approve, not permission to create them under TRUST-04A.
Keep existing trust contracts/serializer/diagnostics and package exports unchanged.

| Proposed new file | Minimal responsibility |
| --- | --- |
| `services/api/app/iam/trust/root_policy_contracts.py` | Closed frozen manifest/context/anchor/transport/diagnostic/evidence types; reuse existing RootTrustPolicy/TrustBinding/Identifier/Digest, no duplicate roles/grants or production trust type |
| `services/api/app/iam/trust/root_policy_wire.py` | Bounded strict parse, field validation/canonical byte comparison, exact frame extraction, typed duplicate/binding checks and acyclic key-set/manifest projections/hash boundaries |
| `services/api/app/iam/trust/root_policy_ed25519.py` | Tiny wrapper around the exact approved established verification API/profile; no signing, key generation, arithmetic, discovery, retry or alternative backend/key fallback |
| `services/api/app/iam/trust/root_policy_verifier.py` | Pure deterministic stage orchestration with explicit context/read-only TEST source, at-most-one source read, quorum/lifecycle/time checks and non-authorizing immutable result |
| `tests/iam/test_trust_root_policy_wire.py` | Frozen field/byte/digest/frame/canonical/budget/stage-negative tests |
| `tests/iam/test_trust_root_policy_anchors.py` | Independent TEST source/binding/lifecycle/quorum/duplicate/time/immutable-output tests |
| `tests/iam/test_trust_root_policy_crypto.py` | Approved published/project/adversarial signatures and exact strict-profile conformance; real test verification, no signer or expected-value generation |
| `tests/iam/test_trust_root_policy_boundary.py` | No operational imports, I/O or effects; diagnostics/counter order, synthetic/production exclusion and compatibility assertions |
| `tests/iam/trust05_vector_assets.py` | Imported immutable literal public fixture bytes/digests/signatures plus provenance/revision pins from separately approved assets; no generator, private seeds or runtime I/O |

No edits to existing `trust/contracts.py`, `canonical.py`, `validation.py`,
`denials.py` or `__init__.py` are proposed. Use explicit new submodule imports in
tests. If an existing file must change, stop and obtain exact expanded authorization.
A dependency pin in requirements.txt/lock material or installation is **outside**
this code/test file list and needs DEP-TEST's separately approved path/environment
scope. Do not rely on the observed unapproved system 3.4.8 merely to avoid this gate.

A future documentation report also needs an explicitly authorized path; none is
silently added to this list. No extra CLI, FastAPI route, background process,
production registry, recovery/key service, general-purpose signing framework or
new IAM package is justified for this first verifier.

## 3. Interface and dependency boundaries

Keep the exact TRUST-04 interfaces: assess_root_policy(proof_bytes;
expected_context, test_anchor_source) and read-only TestAnchorSource.read(context).
Source selection/registration is protected test-harness composition. The untrusted
wire cannot select keys/URLs/database/fixture registry, establish trust by self-signing
or set trusted/verified booleans. Preloaded immutable TEST observations only; no
implicit environment/default context, time, key selection or discovery.

Pure implementation may use approved standard parsing/hash utilities, existing
TRUST-02 records/serializer and the approved Ed25519 verification API. It must not
import operational admission/policy/auth/providers, app.db/settings/main/routes,
audit mutation, Wazuh/Ollama/Shuffle, analyst execution or external tools. Reusing
`app.iam.contracts` datatypes does not authorize policy evaluation or execution.
No network/filesystem/service dependency belongs in the pure functions; ordinary
Python module loading and test-asset preparation are separate harness activities.

Only ROOT_POLICY / IAM-TRUST-SIGNED-1 / IAM-TRUST-ASCII-1 /
ED25519-PURE-1 / ROOT_POLICY-TEST-1 / TEST may succeed. ROOT_TRANSITION,
ISSUANCE, CHECKPOINT, P-256, production environment and provider-recovery custodians
reject according to the exact existing proposed stage order, not a new fallback.

## 4. Authorized later sequence, if all owner gates are opened

1. Pin accepted specification/dependency/asset revisions; inspect current Git state
   and establish an approved offline baseline without overwriting existing work.
2. Write positive, negative, invalid-input, tenant/deployment/environment, duplicate,
   malformed/bounded and no-operational-integration tests first. Demonstrate initial
   failures where practical; never change expected values to fit implementation.
3. Implement exact closed parsing/framing/projection and TEST source contracts;
   preserve TRUST-02 bytes and exact field/code order. Ensure bounded preparse
   limits, not an unbounded JSON parse followed by a depth assertion.
4. Use the approved library for strict verification only after the published/adversarial
   compatibility gate passes. If APIs cannot enforce the frozen profile, stop;
   do not implement arithmetic or weaken acceptance. Reject one eligible vote
   before math; check every supplied entry when quorum is possible; invalid third
   signature defeats success.
5. Return immutable TEST-only evidence bound to exact frame/payload/pins/context and
   sorted verified signer pairs. No output constructor or successful signature may
   be used as a production capability. Keep all existing consumers unchanged.
6. Run only explicitly approved focused tests and existing safe selected regressions,
   compilation and diff/whitespace checks. Record actual counts, failures/exclusions
   and dependency/artifact versions. Stop at TRUST-05; do not activate any authority.

This sequence itself authorizes none of those actions. Current milestone runs no tests.

## 5. Future verification scope to approve

All 26 V04 cases need literal approved expected outcomes/counters. Preserve the
TRUST-04 distinctions: RFC messages versus framed messages; raw/canonical/schema
failures versus math failures; independent pins versus self-claims; two distinct
eligible keys versus real-person independence; historical mathematical validity
versus live authority. Source-read/crypto-call ordering must be asserted exactly.

Use the unchanged tests/offline-selection.json as the selected-regression source,
then explicitly add existing tests/iam/test_trust_structural.py and the four approved
new test modules. The historical selected baseline with the structural file is
2,034; future count increases must be reported, not predicted as passes. Do not
alter the manifest to conceal failures or run unrestricted pytest. The previously
excluded 214 cases must remain unexecuted unless a separate safe review/authorization
changes that scope. No database-backed test is authorized by an offline test decision.

Compatibility acceptance: all preexisting files/index/work preserved; unchanged
IAM-01 hashes/catalogs, IAM-02 policy, IAM-03A synthetic admission, IAM-03B provider,
IAM-03C false currency/denial/session behavior, API/OpenAPI, tenant isolation and
audit integrity. Compilation/test execution do not prove database concurrency,
custody, independent live storage, real revocation or production trust.

## 6. Stop and recovery boundaries

Stop on security-critical spec ambiguity, incompatible bytes/semantic drift,
unapproved dependency/install/path, missing independent fixtures, failed strict
vector/profile compatibility, operational import/effect, raw secret/error exposure,
unsafe test selection or newly required DB/network/config source. Report the
blocker; do not return permissive success or change the frozen error order.

Retain and report work for review; do not automatically delete files, overwrite
user changes, alter the index, commit/push or rewrite history. Recovery/revision
requires the owner's scope; it must never include trust activation or root recovery.
All real keys, customers, custodians, identity, persistence, checkpoint, recovery,
execution and deployment decisions remain outside this plan.

**TRUST-05 implementation authorization: PENDING**  
**CRYPTOGRAPHIC IMPLEMENTATION: NO-GO**  
**DATABASE SCHEMA IMPLEMENTATION: NO-GO**  
**OPERATIONAL IAM: NO-GO**  
**PRODUCTION DEPLOYMENT: NO-GO**
