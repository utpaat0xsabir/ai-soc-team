# TRUST-04I — H-COMP-1 review baseline and artifact requirements

**Status:** design proposal for independent review only; no verifier, runtime, artifact, approval, or operational authority is established by this document. Prepared 2026-11-16.

## Scope and authoritative project baseline

This package consolidates the frozen TRUST-04 wire/anchor/error specifications, TRUST-04F A/R/S profile, and TRUST-04G/H source assessment. The controlling project references are [wire format](iam03c-trust04-root-policy-wire-spec.md), [anchor and verification contract](iam03c-trust04-anchor-and-verifier-contract.md), [diagnostic/vector matrix](iam03c-trust04-vector-and-error-matrix.md), [04F normative profile](iam03c-trust04f-strict-ed25519-normative-profile.md), [04G source ledger](iam03c-trust04g-source-level-verification-evidence.md), and [04H proposed composition](iam03c-trust04h-exact-verification-composition.md). The [04H reviewer packet](iam03c-trust04h-independent-reviewer-appointment-package.md) carries the detailed 20-threat, 26-vector, 15-diagnostic and corpus inventories. TRUST-02 structural serialization remains unchanged.

H-COMP-1 is proposed as one possible **TEST-only** composition:

1. Parse the bounded, closed ROOT_POLICY proof and preserve exact original bytes; require 32-byte A and 64-byte signature, pure Ed25519 only, frozen frame M, and no negotiation/fallback.
2. Decode A; require canonical re-encoding equality, valid point, membership in prime-order subgroup H, and A ≠ identity.
3. Decode R, the original first 32 signature bytes; require canonical re-encoding equality, valid point, and membership in H. Do not exclude identity R.
4. Parse S, the original last 32 bytes, as unsigned little-endian; require `0 ≤ S < L`, with `L = 2^252 + 27742317777372353535851937790883648493`; do not reduce or clamp the input.
5. Verify the exact pure Ed25519 equation/transcript using the ordinary `ed25519-dalek` verification entry point only after the reviewed preconditions. Proposed reference equation: ` [S]B = R + [k]A`, `k = SHA-512(encoded_R || encoded_A || M)` reduced as Ed25519 specifies. The ordinary API's behavior on identity R and the exact selected binary are not runtime-proven.
6. Independently establish TEST anchor/context, customer-custodian mapping, uniqueness, root-policy/environment binding, and revocation before signature math according to the frozen diagnostic precedence.
7. Require at least two distinct eligible votes among exactly three enrolled customer custodians; verify every supplied entry, and reject the whole proof if any extra supplied signature is invalid. No provider-only quorum.
8. On total success, produce only non-authorizing TEST cryptographic evidence. No IAM admission, `is_current()`, operational provider, or execution gate is called.

The eight logical stages do not reorder the frozen fifteen observable diagnostics. Crypto PASS does not establish human custody, authorization, current authority, freshness, or permission to act.

## Candidate identity and evidence state

| Component | Research candidate | Evidence state | Open gate |
|---|---|---|---|
| A/R point operations | `curve25519-dalek 4.1.3` source tag | `SOURCE_VERIFIED` for inspected source predicates only: decompression, canonical recompression capability, torsion-free predicate; separate identity predicate | Exact commit/artifact, feature lock, toolchain, binary equivalence, independent review and runtime tests absent |
| A-only identity check | dalek identity predicate | `SOURCE_VERIFIED` interface exists | Correct call composition and test evidence absent |
| S range | `curve25519-dalek 4.1.3` canonical scalar constructor | `SOURCE_VERIFIED` source behavior; `ed25519-dalek` scalar path has legacy-compatibility feature risk | Feature graph must exclude compatibility behavior; tests absent |
| Equation | `ed25519-dalek 2.2.0` ordinary pure verifier, not `verify_strict` | `SOURCE_VERIFIED` source path reconstructs E1 and compares encoded R; strict entry rejects small-order R and is incompatible with frozen identity-R allowance | Ordinary entry's identity-R behavior, exact resolved build/features, binary/runtime conformance absent |
| Full composition | H-COMP-1 | `PROPOSED` | Independent review, artifacts, reproducible build, implementation and authorized test evidence all absent |

Primary source locations from the TRUST-04G ledger:

- [curve25519-dalek 4.1.3 `edwards.rs`](https://raw.githubusercontent.com/dalek-cryptography/curve25519-dalek/curve25519-4.1.3/curve25519-dalek/src/edwards.rs): `CompressedEdwardsY::decompress`, `EdwardsPoint::compress`, `is_small_order`, `is_torsion_free`.
- [curve25519-dalek 4.1.3 `scalar.rs`](https://raw.githubusercontent.com/dalek-cryptography/curve25519-dalek/curve25519-4.1.3/curve25519-dalek/src/scalar.rs): `Scalar::from_canonical_bytes`.
- [curve25519-dalek 4.1.3 `traits.rs`](https://raw.githubusercontent.com/dalek-cryptography/curve25519-dalek/curve25519-4.1.3/curve25519-dalek/src/traits.rs): identity predicate interface.
- [ed25519-dalek 2.2.0 `verifying.rs`](https://raw.githubusercontent.com/dalek-cryptography/curve25519-dalek/ed25519-2.2.0/ed25519-dalek/src/verifying.rs): `raw_verify`, `RCompute`, ordinary `Verifier::verify`, and stricter `verify_strict`.
- [ed25519-dalek 2.2.0 `signature.rs`](https://raw.githubusercontent.com/dalek-cryptography/curve25519-dalek/ed25519-2.2.0/ed25519-dalek/src/signature.rs): scalar parsing and `legacy_compatibility` concern.
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032), §§5.1.2, 5.1.3, 5.1.7, 8.4: algorithm context, not the project's stronger complete anchor profile.

Inspected tags are not immutable commit pins or authenticated build artifacts. Cargo manifests provide minimum Rust metadata (1.81 for ed25519-dalek 2.2.0; 1.60 for curve25519-dalek 4.1.3), not a selected compiler/runtime or lock. TRUST-04G's source review is not runtime evidence or an independent audit. Historical Quarkslab review does not certify these exact tags or H-COMP-1.

## Reproducibility and artifact acceptance requirements

No dependency acquisition or Rust build is authorized here. A later proposal must provide, before execution:

- immutable source commit IDs corresponding to official releases; authenticated release/source provenance and licenses;
- exact Rust compiler and Cargo versions, target triple/architecture, OS, build profile, backend/CPU feature selection, and build environment;
- complete committed lockfile and resolved feature graph, including every transitive crate; prove one compatible curve implementation is resolved and prohibit `legacy_compatibility`, prehash/context/batch/alternate verification paths, implicit feature activation, and fallback;
- source-to-artifact linkage, artifact checksums and reproducible-build evidence or a documented limit where reproduction is unavailable;
- current maintenance/support and advisory review for the exact resolved graph, plus update/review triggers;
- exact source and artifact evidence for the selected APIs and an independent reviewer’s disposition;
- test evidence for the actual selected artifact. Source inspection alone never upgrades a status to `ARTIFACT_VERIFIED` or `RUNTIME_VERIFIED`.

Status vocabulary: **PROPOSED** means not selected; **SOURCE_VERIFIED** means a named source path was inspected; **ARTIFACT_VERIFIED** means provenance and exact artifact identity are evidenced; **RUNTIME_VERIFIED** means authorized tests exercised that exact build; **INDEPENDENTLY_REVIEWED** means an authentic, scoped reviewer report exists. Current H-COMP-1 is PROPOSED with selected source paths SOURCE_VERIFIED only.

## Known evidence and gaps

- TRUST-04D recorded Python 3.10.12, cryptography 50.0.2 and OpenSSL 4.0.3 in an isolated TEST environment. Three RFC vectors passed. In the ascending Wycheproof run, 152 cases were executed and case 152 was accepted; the frozen A rule requires rejection of identity A. The run stopped immediately. This is a confirmed acceptance-boundary discrepancy for that tested combination, not a general insecurity claim about PyCA/OpenSSL.
- The original Wycheproof case 152 verdict remains `acceptable`; project profile is stricter. Raw-message input was used for the corpus, not the ROOT_POLICY frame. The recorded result and exact public bytes remain in [04D results](../../tests/iam/fixtures/trust04d_offline_validation/results.json), and case reconstruction in [04E](iam03c-trust04e-case152-evidence-reconstruction.md).
- 58 Wycheproof records remain NOT_RUN (tcId 153–210); do not change original verdicts or infer results.
- All 26 project-specific V04 cases remain NOT_READY for complete independently reviewed golden validation. RFC component vectors and partial corpus results are not project-frame goldens. No project golden signatures were created.
- TRUST-02 source-only structural contracts are non-authorizing and not connected to IAM authority paths; this review does not change them.

## Review acceptance boundary

The independent reviewer is asked to assess the proposal, not to authorize it. Any unresolved semantic mismatch, unproven A/R/S predicate, identity-R over-rejection, unsupported feature path, unclear equation, missing artifact provenance, or absent reproducible evidence must produce a conditional/reject/more-evidence outcome. No inference from this review packet may enable production roots, schemas, admission, or operations.

Related TRUST-04I materials: [reviewer statement of work](iam03c-trust04i-independent-reviewer-statement-of-work.md), [evidence/decision record](iam03c-trust04i-review-evidence-and-decision-record.md), and [owner gates](iam03c-trust04i-owner-actions-and-g1-readiness.md).
