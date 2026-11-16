# AI SOC Team — H-COMP-1 independent cryptographic assessment handoff

**Prepared:** 2026-11-16

**Review status:** no reviewer appointed; no external review performed

**Disclosure:** OWNER_DISCLOSURE_APPROVAL_REQUIRED before any material is shared

## Purpose and requested outcome

AI SOC Team is a local-first, multi-tenant security operations platform. Its future customer-controlled root of trust would let enrolled customer custodians endorse a bounded authority policy. The initial cryptographic work is restricted to an offline `ROOT_POLICY` test verifier; it cannot grant roles, authorize actions, establish current authority, or activate IAM.

This handoff asks an independent cryptographic reviewer to assess whether H-COMP-1 is mathematically and implementation-wise defensible for a separately authorized **TEST-only prototype**. The reviewer is free to reject it. The requested decision is one of `APPROVED_FOR_TEST_PROTOTYPE`, `APPROVED_WITH_CONDITIONS`, `MORE_EVIDENCE_REQUIRED`, or `REJECTED`. None is production approval or owner authorization.

## Security model

Root authority is customer-controlled. Three customer custodians are represented in an independently pinned test root set; two distinct eligible custodians must endorse the exact signed operation. SaaS provider identity does not imply customer authority and a provider-only quorum is forbidden. The external trust-anchor source, not a database claim or a self-signed manifest, supplies expected trust-domain, deployment, tenant and environment context and the exact approved public-key mapping.

Cryptographic validity is only evidence about bytes. The frozen 15-stage diagnostic precedence, signer uniqueness, revocation and quorum rules remain separate from signature mathematics. Even a complete TEST cryptographic pass is non-authorizing and must not be connected to IAM admission or execution.

## Frozen Ed25519 profile and proposal

The frozen project profile requires:

- **A (public key):** exactly 32 raw bytes, canonical encoding, valid curve point, prime-order subgroup membership, and nonidentity.
- **R (signature point):** the original first 32 signature bytes; canonical encoding, valid point, and prime-order subgroup membership. Identity R is permitted, but never constitutes success without all remaining checks and a valid equation.
- **S (signature scalar):** the original last 32 bytes interpreted as unsigned little-endian, with `0 ≤ S < L`, where `L = 2^252 + 27742317777372353535851937790883648493`. No reduction or clamping of input S.
- **Mode and message:** Pure Ed25519 over the exact frozen domain-separated signing frame; no Ed25519ph/ctx, algorithm negotiation, fallback, or alternate message normalization.
- **Equation:** E1 is the review candidate: `[S]B = R + [k]A`, where the challenge is derived from the exact encoded R, encoded A, and full frame M as Ed25519 specifies. The cofactored-equation equivalence is conditional on the full subgroup predicates and remains for reviewer confirmation.

H-COMP-1 proposes `curve25519-dalek 4.1.3` point/scalar primitives for explicit A/R/S validation, plus `ed25519-dalek 2.2.0` ordinary pure verification for the equation. It proposes canonical decode/re-encode equality; subgroup checks for both A and R; identity rejection only for A; canonical S range; then exact-byte equation verification. These are source-review candidates, **not** selected or verified runtime dependencies. Exact immutable source commits, artifacts, Rust/Cargo toolchain, feature graph, lockfile, target, and reproducible build are missing.

## Why profile-specific review is essential

An API named “strict” is not automatically correct for this profile. The reviewed `ed25519-dalek` strict path rejects small-order R, which conflicts with the frozen identity-R allowance. A generic verifier may also fail to enforce the project's full prime-order subgroup rule for A, or may accept identity A. The ordinary pure verifier is only a proposed equation component after explicit validation; its identity-R behavior and exact binary semantics have not been runtime-tested. Do not bypass a verifier rejection or silently tighten the accepted profile.

## Observed discrepancy and evidence

In the historical, owner-authorized TRUST-04D isolated run, Python 3.10.12 with `cryptography==50.0.2` and OpenSSL 4.0.3 accepted Wycheproof tcId 152. That vector's original verdict is `acceptable`; its public key is the canonical identity point. AI SOC Team's frozen A policy requires rejection. The corpus run stopped there. The recorded observation is a confirmed acceptance-boundary discrepancy for that tested combination, not proof of a general library vulnerability, not an OpenSSL internal equation finding, and not evidence about H-COMP-1.

The same TRUST-04D run reported 3/3 RFC 8032 vectors passed and 152/210 Wycheproof records executed: 88 valid accepted, 63 invalid rejected, and one acceptable case accepted. The remaining 58 records (tcId 153–210) are **NOT_RUN**. Original source verdicts remain unchanged. No H-COMP-1 code, identity-R positive vector, project golden signature, or independently reviewed golden digest exists.

## Claims still unverified

1. Full A/R predicate correctness and source-to-binary equivalence for a locked H-COMP-1 build.
2. Ordinary `ed25519-dalek` verification accepts a canonical identity R only when the full equation is valid, while rejecting identity R when it is invalid.
3. Exact E1 behavior, transcript preservation, S handling, and no extra backend rejection for the permitted profile.
4. Complete feature/transitive dependency set, current support/advisory status, toolchain/target, artifact authenticity, and reproducible build.
5. Independent golden-vector derivation and reviewer assessment of the 20 threats, 26 project cases, 15 diagnostics, 210 corpus records and three RFC vectors.

## Review requested

Please assess mathematical soundness, exact source/API behavior, composition safety, identity-R semantics, dependency/artifact requirements, and the proposed test acceptance criteria. Identify evidence gaps and required corrections. Do not treat any proposed design statement as an established runtime fact. Full engagement scope and the blank review record are in [the assessment SOW](iam03c-trust04j-reviewer-engagement-and-assessment-sow.md); evidence and disclosure dispositions are in [the manifest](iam03c-trust04j-evidence-manifest-and-disclosure-review.md).

No material has been sent. The owner must separately approve reviewer appointment, confidentiality terms and each item for disclosure. No production keys, customer trust anchors or operational credentials are needed for the design review.

## Readiness

This is a prepared handoff, not an independent assessment. The reviewer is NOT_APPOINTED, sign-off is PENDING, remaining Wycheproof cases are 58 NOT_RUN, project golden vectors are NOT_READY, G1 is BLOCKED, and TRUST-05/operational IAM/production remain NO-GO.
