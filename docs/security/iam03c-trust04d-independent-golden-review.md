# TRUST-04D independent golden-vector review

2026-11-16. **NOT_READY — no project golden derivation performed.**
[Dependency blocker](iam03c-trust04d-runtime-and-dependency-evidence.md),
[compatibility status](iam03c-trust04d-ed25519-compatibility-results.md),
[G1 assessment](iam03c-trust04d-g1-readiness-assessment.md).

The owner authorized TEST-only signing/hashing subject to the dependency/runtime
and mandatory stop gates. The dependency gate stopped before installation. No
TEST private key, signing-frame/body/preimage/digest/signature golden, reference
signer or compatibility harness was produced. No private material exists from
this task, and none was persisted outside the disposable environment.

Original public vectors remain source inputs, not newly verified project goldens.
The proposed independent method remains the unchanged TRUST-04C plan: distinct
reference byte derivations, independent hash/preimage review and a genuinely
independent cryptographic oracle. Different filenames or two callers of one library
do not establish independence. No reference oracle from future TRUST-05 is used.

## All 26 project cases retained as gaps

Every row is NOT_READY / NOT_RUN; there are no invented expected byte/digest values.
The source specification gives expected behaviors, not generated golden constants.

| Case | Required independent evidence still missing |
| --- | --- |
| V04-01 | Executed RFC known-answer conformance on selected runtime/backend |
| V04-02 | Independently matched canonical/body/key-set/manifest/frame preimages and digests |
| V04-03 | Valid project-frame two-of-three TEST signatures and independently checked evidence |
| V04-04 | Three valid signatures and all input permutations, exact sorted evidence/counters |
| V04-05 | Independent zero/one-vote negative fixtures and zero-math assertions |
| V04-06 | Independently known invalid signature mutation and result |
| V04-07 | Duplicate identity/material/source-map fixtures with exact stage results |
| V04-08 | Wrong-tenant and nested binding fixtures, no source lookup |
| V04-09 | Deployment/domain/customer/kind binding negatives |
| V04-10 | Environment UUID and PRODUCTION-domain negatives |
| V04-11 | Wrong/mixed/ph/ctx/profile negative assets and no-fallback results |
| V04-12 | Exact primitive/canonical/time/UUID/numeric alias fixtures |
| V04-13 | Unknown signed/unsigned field/URL/trusted-flag fixtures |
| V04-14 | Independent wrong-derived versus coherent-wrong-pin digest fixtures |
| V04-15 | Two valid plus invalid third at each sorted position, no partial evidence |
| V04-16 | Unknown/wrong key fixtures and mathematical rejection evidence |
| V04-17 | TEST key/root revocation and explicit time-window fixtures |
| V04-18 | Missing/self-selected/corrupt source fixtures |
| V04-19 | Old/new unapproved policy/version/generation/pin fixtures |
| V04-20 | Protected synthetic/production source-class rejection fixtures |
| V04-21 | Executed strict point/scalar/encoding comparison with original corpus verdicts retained |
| V04-22 | Label/NUL/length/purpose/trailing-byte and extraction-exception fixtures |
| V04-23 | Independent cap/cap+1/depth/entry/raw/decoded budget accounting and results |
| V04-24 | Independent multi-fault precedence/permutation oracle and counters |
| V04-25 | No provider recovery/customer authority fixtures |
| V04-26 | Backend/source faults, immutable result and no operational integration evidence |

Any later artifacts require exact specification/fixture/tool/runtime/dependency
revision pins and independent review; a local signing result must not declare its
own expected verification result authoritative. Original RFC signatures cannot be
reused for a different IAM frame. No criterion is waived due to this stop.

**Independent project assets produced: NONE**  
**PROJECT GOLDEN VECTORS: NOT_READY**

## Authorized continuation and final assessment — 2026-11-16

This section supersedes the earlier dependency-stop status without erasing it.
The owner separately authorized TRUST-04D TEST execution, official PyPI binary-wheel
acquisition/offline installation, and required typing-extensions. No broader A01/A04
or TRUST-05 approval follows.

No project-specific golden outputs were generated after the mandatory compatibility
stop. All V04-01 through V04-26 remain NOT_READY as complete project-fixture cases;
the existing inventory above retains each exact requirement. V04-01 has published
algorithm pass evidence, and V04-21 has partial adversarial evidence plus a blocker;
neither constitutes a complete project signing-frame oracle.

Canonical body/frame bytes, payload/frame/key-set/manifest digests, three-custodian
TEST signatures, valid quorum, invalid third signature, binding/purpose negatives,
malformed proofs and cap/cap+1 assets remain pending independent derivation and review.
No private keys were created or persisted, and no future verifier served as an oracle.
Independent reviewer approval and independent derivation remain required. Public
fixture provenance checks passed; no original verdict, bytes or license was changed.

PROJECT GOLDEN VECTORS: NOT_READY.
