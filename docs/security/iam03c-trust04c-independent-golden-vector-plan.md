# TRUST-04C independent project golden-vector plan

2026-11-16. **Plan only; PENDING_INDEPENDENT_DERIVATION.**
No project canonical/frame/hash/signature goldens were generated.
[Acquired public inputs](iam03c-trust04c-ed25519-public-vector-catalog.md),
[dependency candidate](iam03c-trust04c-authoritative-dependency-evidence.md),
[G1 review](iam03c-trust04c-g1-evidence-review.md).
The unchanged [wire specification](iam03c-trust04-root-policy-wire-spec.md),
[anchor contract](iam03c-trust04-anchor-and-verifier-contract.md) and
[15-code matrix](iam03c-trust04-vector-and-error-matrix.md) remain normative proposals.

## 1. Independent derivation procedure — future authorization required

1. Owner accepts exact specification revisions and TEST input/context/pin/key fixture
   identities; use three distinct published TEST public keys, never real customer
   enrollment or claims of independent real people. Assign separate reference-byte,
   cryptographic-oracle and parser/security reviewers. No reviewer is claimed assigned
   or to have signed off here; these are required responsibilities for owner staffing.
2. Freeze human-reviewed symbolic field values, original public-key source IDs and
   native vector semantics. Two independent reference encoders, not importing the
   future verifier or its serializer, reconstruct all literal bytes from the spec.
   Preserve lossless integers/ASCII and exact inner TRUST02 behavior, not JCS.
3. Independently calculate expected key fingerprints, key-set/manifest/payload/frame
   SHA-256 constants using separately reviewed standard tools only after explicit
   future hashing authorization. Compare whole preimages/bytes, not just digests.
4. Obtain independently prepared project-frame signatures under separate test-material
   authorization, using published non-production material if approved. No new root
   keys. Use established reviewed crypto implementations, no custom arithmetic.
   Different wrappers over the same backend are not automatically independent
   oracles; document shared dependencies and obtain separate review/known answers.
5. Pin literal bytes/digests/signatures, source/license/tool/version/reviewer evidence,
   exact mutations and expected diagnostics/counters. Tests consume those literals;
   they must not generate expected results exclusively with the implementation under
   test. Missing values stay pending, never dummy hashes/signatures or fake success.

Published RFC signatures apply to their original messages, not this frame. Copying
those signatures onto a different body does not supply valid two-of-three goldens.
No step above was executed in TRUST-04C. Three public RFC input records and the
upstream adversarial corpus were acquired; mathematical/project verification remains
unexecuted. New signatures, hashes and test code are outside this milestone.

## 2. Exact project fixture coverage

Every one of the seventeen body fields must have independently agreed literal values:
protocol_version, canonicalization_id, signature_profile_id, purpose, binding,
environment_id, environment_kind, root_policy_id, root_policy_version, root_set_digest,
operation_id, issued_at, expires_at, payload_type, payload_hex, payload_sha256,
purpose_context. Exact allowed constants and closed sidecar/payload fields stay
as TRUST-04 specifies; no issuer/transition/checkpoint fields are added.

Required expected assets: complete unchanged inner policy bytes; 14-field manifest
and exact 11-field key-set projection preimages; manifest excluding only its own
digest; payload hash; full canonical body; ASCII AI-SOC-IAM-ROOT-POLICY-1 (24 bytes),
one NUL, eight-byte unsigned big-endian body byte length, exact body; full-frame
digest; separate immutable expected tenant/domain/deployment/environment/operation
and independent TEST anchor map. Root-set/manifest hashes remain acyclic. No computed
hashes or framed bodies are included in the current asset directory.

Required signature/quorum fixtures: two and three eligible customer TEST signers,
all order permutations, invalid third signature at each sorted position, duplicate
custodian/key/material, unknown key, wrong policy/pin/version, revoked TEST signer,
time/source failure and unsupported purpose/profile/environment. Source valid,
invalid or acceptable labels are retained and mapped explicitly, not silently changed.

All fifteen diagnostics need fixed independent expected precedence/counters:
LIMIT_EXCEEDED, SYNTHETIC_SOURCE, STRUCTURE_INVALID, BINDING_MISMATCH,
SIGNER_DUPLICATE, CANONICAL_MISMATCH, DOMAIN_MISMATCH, ALGORITHM_UNSUPPORTED,
ANCHOR_UNAVAILABLE, POLICY_STALE, SIGNER_UNKNOWN, KEY_REVOKED, TIME_INVALID,
QUORUM_INSUFFICIENT, SIGNATURE_INVALID. Frame extraction and observable-budget
exceptions remain as frozen; zero/one eligible signature rejects before math and
all supplied signatures must verify for success.

Budgets remain inner 24,576; body 65,536; frame 65,569; combined 262,144; TEST
snapshot 16,384; context 4,096 bytes; depth 16; signatures <=3. Count raw transport,
hex expansion and decoded/input budgets exactly. Independently prepare cap/cap+1,
malformed/oversize-before-parse and multi-fault cases. At cap, a normal later rejection
can be correct; no new padding field or relaxation merely to make a maximal fixture.

## 3. All 26 vector readiness states

Input formats: ALG = exact original public key/message/signature bytes; FRAME =
frozen canonical transport/frame/body/policy plus separate TEST context/anchors;
MUT = literal mutation of a pinned FRAME/source/context fixture. Outputs are native
published verdicts, exact TEST SignatureEvidence, or frozen SignatureRejection plus
separate test-only counters. All project literal values remain pending.

Independence codes: PUB = publisher-supplied originals plus independent review;
REF = two separate encoders/hash tools and reviewers; CRYPTO = independent reviewed
project signing/checking; SEC = independent mutation/stage review. Role holders and
acceptance must be explicitly approved later. Existing V04 IDs appear exactly once.

| Vector ID | Objective | Category / source | Input | Expected result | Independence | Review status | Readiness |
| --- | --- | --- | --- | --- | --- | --- | --- |
| V04-01 | Known-answer pure signatures | Published / acquired RFC 8032 TEST 1–3 | ALG | Native valid, not locally checked | PUB | ACQUIRED, independent review pending | READY_FOR_REVIEW |
| V04-02 | Exact bytes/frame/digests | Project-specific / frozen wire derivation | FRAME/preimages | Exact literals/digests pending | REF | PROPOSED | PENDING_INDEPENDENT_DERIVATION |
| V04-03 | Valid 2-of-3 | Quorum / project TEST anchor/signatures | FRAME, two entries | TEST evidence, two sorted pairs pending | REF+CRYPTO | BLOCKED: signatures absent | PENDING_INDEPENDENT_DERIVATION |
| V04-04 | Three/all permutations | Quorum / project fixtures | FRAME variants | Same logical TEST evidence, three checks pending | CRYPTO+SEC | PROPOSED | PENDING_INDEPENDENT_DERIVATION |
| V04-05 | Zero/one vote denial | Quorum / fixed threshold recipe | MUT | QUORUM_INSUFFICIENT, zero math | SEC | PROPOSED, literal fixture absent | PENDING_INDEPENDENT_DERIVATION |
| V04-06 | Invalid signature | Negative / independent fixed mutation | MUT | SIGNATURE_INVALID | CRYPTO+SEC | PROPOSED | PENDING_INDEPENDENT_DERIVATION |
| V04-07 | Duplicate vote/material | Quorum / candidate/source duplicate recipe | MUT | SIGNER_DUPLICATE or malformed-source ANCHOR_UNAVAILABLE | SEC | PROPOSED | PENDING_INDEPENDENT_DERIVATION |
| V04-08 | Tenant isolation | Quorum/binding / independent expected tenant | MUT | BINDING_MISMATCH, zero lookup | SEC | PROPOSED | PENDING_INDEPENDENT_DERIVATION |
| V04-09 | Deployment/domain/customer | Quorum/binding / context recipe | MUT | BINDING_MISMATCH | SEC | PROPOSED | PENDING_INDEPENDENT_DERIVATION |
| V04-10 | Environment isolation | Quorum/binding / context recipe | MUT | BINDING_MISMATCH or PRODUCTION DOMAIN_MISMATCH | SEC | PROPOSED | PENDING_INDEPENDENT_DERIVATION |
| V04-11 | No algorithm fallback | Negative / profile recipe | MUT | ALGORITHM_UNSUPPORTED | SEC | PROPOSED | PENDING_INDEPENDENT_DERIVATION |
| V04-12 | Canonical/primitive aliases | Parsing / exact mutation recipe | MUT | CANONICAL_MISMATCH or STRUCTURE_INVALID, per stage | REF+SEC | PROPOSED | PENDING_INDEPENDENT_DERIVATION |
| V04-13 | Unknown fields | Parsing / closed schemas | MUT | STRUCTURE_INVALID | SEC | PROPOSED | PENDING_INDEPENDENT_DERIVATION |
| V04-14 | Wrong derived/pinned digests | Project-specific / independent preimages | FRAME/MUT | CANONICAL_MISMATCH or coherent wrong-pin POLICY_STALE | REF | PROPOSED | PENDING_INDEPENDENT_DERIVATION |
| V04-15 | Invalid third signature | Negative / two valid plus independently invalid | MUT | SIGNATURE_INVALID, no partial evidence | CRYPTO+SEC | BLOCKED: project signatures absent | PENDING_INDEPENDENT_DERIVATION |
| V04-16 | Wrong/unknown key | Negative / key-map and signature recipe | MUT | SIGNER_UNKNOWN or SIGNATURE_INVALID | CRYPTO+SEC | PROPOSED | PENDING_INDEPENDENT_DERIVATION |
| V04-17 | TEST lifecycle/time | Negative / explicit fixture observations | MUT | KEY_REVOKED before TIME_INVALID/threshold | SEC | PROPOSED | PENDING_INDEPENDENT_DERIVATION |
| V04-18 | No self-bootstrap | Negative / independent-source faults | MUT | ANCHOR_UNAVAILABLE | SEC | PROPOSED | PENDING_INDEPENDENT_DERIVATION |
| V04-19 | Stale/unapproved policy | Negative / independent policy pins | MUT | POLICY_STALE | REF+SEC | PROPOSED | PENDING_INDEPENDENT_DERIVATION |
| V04-20 | No synthetic promotion | Negative / protected input class | FRAME/context | SYNTHETIC_SOURCE | SEC | PROPOSED | PENDING_INDEPENDENT_DERIVATION |
| V04-21 | Adversarial A/R/S/lengths | Published / pinned Wycheproof 210 cases | ALG; later FRAME adaptation | Native 117 valid/64 invalid/29 acceptable; strict per-case verdict pending | PUB+CRYPTO | ACQUIRED, policy mapping/review pending | READY_FOR_REVIEW, NOT_PROFILE_APPROVED |
| V04-22 | Domain/NUL/length/trailing | Parsing / exact frame mutations | MUT | DOMAIN_MISMATCH, limit exceptions per spec | REF+SEC | PROPOSED | PENDING_INDEPENDENT_DERIVATION |
| V04-23 | Cap/cap+1 | Parsing / independent byte/depth/count accounting | MUT/source/context | LIMIT_EXCEEDED at observable cap+1; normal validation at cap | REF+SEC | PROPOSED | PENDING_INDEPENDENT_DERIVATION |
| V04-24 | Multi-fault precedence | Negative / frozen stage scenarios | MUT | Earliest fixed code and counters | SEC | PROPOSED | PENDING_INDEPENDENT_DERIVATION |
| V04-25 | No provider authority | Quorum/binding / provider variants | MUT | DOMAIN_MISMATCH or unknown platform SIGNER_UNKNOWN | SEC | PROPOSED | PENDING_INDEPENDENT_DERIVATION |
| V04-26 | Error/result isolation | Negative / source/backend faults | FRAME/harness | Fixed rejection, immutable TEST evidence, no operational consumer | SEC+CRYPTO | PROPOSED | PENDING_INDEPENDENT_DERIVATION |

READY_FOR_REVIEW refers only to source inputs acquired, not approved goldens, a
passing test, all strict-policy verdicts or an implementation gate. Twenty-four
cases still lack project-specific assets. Source data for two cases does not fill
the missing FRAME fixtures or signatures for the others.

## 4. Golden acceptance gates

Require stable IDs and exact original source/version/license/byte records; frozen
profile/canonicalization revision; complete input/output/preimage/hash/signature
literals; source/producer/tool versions; named independent review and independent
reconstruction/check results; explicit TEST-only classification and reproducible
instructions. Preserve native labels alongside separate project-policy verdicts.
No source-site hash alone authenticates the publisher or proves signature behavior.

Dependency gate needs current supported candidate/artifact/backend review, complete
reproducible pins, target/runtime approval and documented APIs; candidate evidence
is now reviewable but installation is not approved. Golden gate needs acceptance
of the above assets, not just this inventory. Compatibility gate requires actual
separately authorized strict positive/adversarial execution; it cannot pass here.

## 5. Proposed isolated compatibility environment — NOT EXECUTED

A future owner-authorized run must use a fresh disposable directory/environment,
only approved exported source/tests/public fixtures and complete offline artifacts;
no existing .venv reuse, .env/configuration, production credentials/key files or
persistent root state. Use a recorded Python/OS/architecture/backend and an approved
Python-3.10 lifecycle exception/downstream-support decision if retaining that target.
No DB/Wazuh/Shuffle/Ollama access, IAM admission/provider import or operational effect.

Network must be denied at OS/sandbox level during tests, not merely by pip flags.
A Linux user/network namespace is one proposed mechanism; if unavailable, stop and
approve a different isolation mechanism rather than silently run connected. Export
only approved files into the clean workspace; do not copy secret-bearing runtime
configuration or mounts. The pure test functions must prohibit service/file/network
lookups; no production Unix-socket/credential access is part of the harness.

The following are **future commands requiring separate authorization**, with exact
paths supplied only after owner review. No command was run. The test module and
complete dependency lock below do not exist yet and are not created by this task.

```bash
test ! -e /tmp/ai-soc-trust04c-compat-approved
python3.10 -m venv /tmp/ai-soc-trust04c-compat-approved
/tmp/ai-soc-trust04c-compat-approved/bin/python -m pip --isolated install --no-index --find-links=/approved/offline-wheelhouse --only-binary=:all: --require-hashes -r /approved/cryptography-50.0.2-complete.lock
cd /approved/clean-test-export
unshare --user --map-root-user --net -- /tmp/ai-soc-trust04c-compat-approved/bin/python -m pytest -p no:cacheprovider tests/iam/test_trust_ed25519_dependency_compat.py
```

The lock must include all reviewed transitive artifact hashes, not just the candidate
wheel. Environment recording includes artifact/publisher provenance, interpreter/
OS/glibc/architecture, actual backend, source/fixture/spec revisions and network
isolation evidence; no secret outputs. Test results must separate published-native
semantics, frozen-profile verdicts, and wrapper stage behavior. Missing backend/
profile/API compatibility stops the run; no arithmetic, fallback or skipped-failure
success. Installation, test code creation, hashing/signing and these commands all
remain unapproved beyond this documentation plan.

**PROJECT GOLDEN VECTORS: NOT_READY**  
**Compatibility execution: NOT_EXECUTED**
