# H-COMP-1 isolated TEST prototype — results

**Classification:** experimental, offline, non-authorizing TEST evidence. No IAM integration, trust-anchor enrollment, customer material, or production authority.

## Environment and build

- Rust: `rustc 1.100.0 (0ef1bc386 2026-11-09)`, target `x86_64-unknown-linux-gnu`.
- Cargo: `cargo 1.100.0 (3acc79c0c 2026-11-05)`.
- Dependencies: `curve25519-dalek = 4.1.3`, default features disabled; `ed25519-dalek = 2.2.0`, default features disabled, features `std`, `zeroize`.
- Lockfile: copied from the isolated dependency audit because package version and exact dependency/features match; SHA-256 `abd67bf1716726da4cd4dbfe2eed528c0db1096646ef02769088b167fd1791ea`.
- Cargo registry/cache: isolated `/home/son-of-anton/ai-soc-hcomp1-toolchain/cargo`; target output under this prototype `target/`.
- Command: `cargo test --offline --locked`, with `CARGO_NET_OFFLINE=true`; no network access or dependency installation.
- Baseline before harness hardening: **8 passed, 0 failed**; doc tests: 0. Final offline run after this change: **9 passed, 0 failed**; doc tests: 0.
- The first test attempt exposed a test fixture index error (empty RFC message selected as signature); the selector was corrected, then the complete final suite passed. No expected cryptographic verdict was changed.

## Frozen-profile implementation boundary

- A and R: exact 32-byte input, Dalek decompression, recompression equality, and `is_torsion_free()`; A identity rejected, R identity allowed.
- S: exact 32-byte input and `Scalar::from_canonical_bytes`; no modulo reduction.
- Equation: ordinary `ed25519_dalek::Verifier::verify` pure path, after all A/R/S checks; no `verify_strict`, ph/ctx, fallback, or alternate algorithm.
- Source inspection of the locked `ed25519-dalek 2.2.0` path shows `Verifier::verify` calls `raw_verify::<Sha512>`; it hashes exact R||A||message and recomputes `[S]B - [k]A`, compressing and comparing with encoded R. Its signature parser uses canonical S absent `legacy_compatibility`. Runtime evidence is limited to tests below; no independent cryptographic audit is claimed.
- Public-key construction retains and exposes the input compressed bytes; the prototype checks byte equality before equation verification. The same signature and message bytes are passed through unchanged.
- Deterministic errors cover input lengths, point encoding/canonicality/subgroup membership, identity A, scalar canonicality, backend key/byte mismatch, and equation mismatch. These are prototype errors, not the frozen 15 IAM diagnostics.

## A/R/S and equation tests

- A: canonical RFC key accepted; identity rejected; invalid/malformed and noncanonical encodings rejected; canonical small-order point rejected; Wycheproof tcId 160 mixed-order key rejected; wrong length rejected.
- R: RFC R accepted; identity R accepted by point validation; invalid, noncanonical, non-prime-order, and wrong-length values rejected. A deterministic positive identity-R fixture now passes full verification.
- S: zero and L−1 accepted as canonical scalar encodings; L, L+1, and wrong-length input rejected.
- Equation: changed message, changed signature, and wrong public key rejected. Identity-A regression rejected with `PublicKeyIdentity`. Existing Wycheproof tcId 15 has identity R and an invalid equation and was rejected with `SignatureEquationMismatch`; identity R was not accepted by shortcut.
- Positive identity-R fixture: `tests/identity-r-positive.tsv`, reproducible with `python3 tests/generate_identity_r_fixture.py`. The fixture is synthetic and public TEST material: `R=O`, `A=B`, and `a=1` are deliberately chosen, so `k=SHA-512(R||A||M) mod L` and `S=k`; therefore `[S]B = O + [k]A` by direct substitution. The script uses only Python's standard-library SHA-512 and integer arithmetic; it does not call the verifier or a signing API. It asserts `0 < k < L-1`. This algebraic derivation supports the expected ACCEPT result but is not an independent curve implementation or cryptographic review.
- Positive identity-R result: point validation passed and `verify_hcomp1` accepted the full signature. Wrong S, modified message, a different valid public key, noncanonical S=`L`, identity A, and truncated signature were rejected. Thus identity R is not accepted without satisfying the equation and other profile checks.

## RFC 8032 vectors

All inputs/messages/signatures are the unchanged public RFC 8032 section 7.1 TEST vectors. These verify raw RFC messages, not the project signing frame.

| Vector ID | Expected | Actual | Result |
|---|---|---|---|
| RFC8032-7.1-TEST-1 | ACCEPT | ACCEPT | PASS |
| RFC8032-7.1-TEST-2 | ACCEPT | ACCEPT | PASS |
| RFC8032-7.1-TEST-3 | ACCEPT | ACCEPT | PASS |

## Wycheproof Ed25519 corpus

Input file: unchanged TRUST-04C corpus at commit `a3d5d1423f2592d6646836a45a21a1b209da9f4d`; original POSIX `cksum` recorded in its manifest and rechecked before prototype extraction. Original verdicts are retained below. Profile expectation maps source `valid` to ACCEPT, `invalid` to REJECT, and `acceptable` to REJECT only where source flags identify `SmallOrderPublicKey` or `MixedOrderPublicKey` (the frozen A rule); other acceptable inputs would remain REVIEW_REQUIRED. The 29 acceptable cases all carry those A flags.

Before cryptographic processing, the harness now parses every line (blank rows are malformed), requires seven TSV fields and exactly 210 rows, validates canonical decimal IDs, rejects duplicates and out-of-range IDs, and compares the observed set with exactly `1..=210`. A focused test verifies rejection of duplicate, missing, unexpected (`211`), malformed, and duplicate-plus-missing IDs; the last input still has 210 rows. These are harness-integrity checks only and do not alter corpus verdicts.

| tcId | Original verdict | Project-profile expected | Actual | Result | Error category |
|---:|---|---|---|---|---|
| 1 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 2 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 3 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 4 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 5 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 6 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 7 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 8 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 9 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 10 | invalid | REJECT | REJECT | PASS | Err(SignatureRNotPrimeOrder) |
| 11 | invalid | REJECT | REJECT | PASS | Err(SignatureRNotPrimeOrder) |
| 12 | invalid | REJECT | REJECT | PASS | Err(SignatureRNotPrimeOrder) |
| 13 | invalid | REJECT | REJECT | PASS | Err(SignatureRNotPrimeOrder) |
| 14 | invalid | REJECT | REJECT | PASS | Err(SignatureRNotPrimeOrder) |
| 15 | invalid | REJECT | REJECT | PASS | Err(SignatureEquationMismatch) |
| 16 | invalid | REJECT | REJECT | PASS | Err(SignatureEquationMismatch) |
| 17 | invalid | REJECT | REJECT | PASS | Err(SignatureEquationMismatch) |
| 18 | invalid | REJECT | REJECT | PASS | Err(SignatureScalarNonCanonical) |
| 19 | invalid | REJECT | REJECT | PASS | Err(SignatureScalarNonCanonical) |
| 20 | invalid | REJECT | REJECT | PASS | Err(SignatureREncoding) |
| 21 | invalid | REJECT | REJECT | PASS | Err(SignatureREncoding) |
| 22 | invalid | REJECT | REJECT | PASS | Err(SignatureREncoding) |
| 23 | invalid | REJECT | REJECT | PASS | Err(SignatureREncoding) |
| 24 | invalid | REJECT | REJECT | PASS | Err(SignatureREncoding) |
| 25 | invalid | REJECT | REJECT | PASS | Err(SignatureRNonCanonical) |
| 26 | invalid | REJECT | REJECT | PASS | Err(SignatureRNonCanonical) |
| 27 | invalid | REJECT | REJECT | PASS | Err(SignatureRNonCanonical) |
| 28 | invalid | REJECT | REJECT | PASS | Err(SignatureRNonCanonical) |
| 29 | invalid | REJECT | REJECT | PASS | Err(SignatureRNonCanonical) |
| 30 | invalid | REJECT | REJECT | PASS | Err(SignatureLength) |
| 31 | invalid | REJECT | REJECT | PASS | Err(SignatureLength) |
| 32 | invalid | REJECT | REJECT | PASS | Err(SignatureLength) |
| 33 | invalid | REJECT | REJECT | PASS | Err(SignatureLength) |
| 34 | invalid | REJECT | REJECT | PASS | Err(SignatureLength) |
| 35 | invalid | REJECT | REJECT | PASS | Err(SignatureLength) |
| 36 | invalid | REJECT | REJECT | PASS | Err(SignatureLength) |
| 37 | invalid | REJECT | REJECT | PASS | Err(SignatureLength) |
| 38 | invalid | REJECT | REJECT | PASS | Err(SignatureLength) |
| 39 | invalid | REJECT | REJECT | PASS | Err(SignatureLength) |
| 40 | invalid | REJECT | REJECT | PASS | Err(SignatureLength) |
| 41 | invalid | REJECT | REJECT | PASS | Err(SignatureLength) |
| 42 | invalid | REJECT | REJECT | PASS | Err(SignatureRNotPrimeOrder) |
| 43 | invalid | REJECT | REJECT | PASS | Err(SignatureREncoding) |
| 44 | invalid | REJECT | REJECT | PASS | Err(SignatureEquationMismatch) |
| 45 | invalid | REJECT | REJECT | PASS | Err(SignatureREncoding) |
| 46 | invalid | REJECT | REJECT | PASS | Err(SignatureREncoding) |
| 47 | invalid | REJECT | REJECT | PASS | Err(SignatureRNotPrimeOrder) |
| 48 | invalid | REJECT | REJECT | PASS | Err(SignatureEquationMismatch) |
| 49 | invalid | REJECT | REJECT | PASS | Err(SignatureRNotPrimeOrder) |
| 50 | invalid | REJECT | REJECT | PASS | Err(SignatureREncoding) |
| 51 | invalid | REJECT | REJECT | PASS | Err(SignatureRNotPrimeOrder) |
| 52 | invalid | REJECT | REJECT | PASS | Err(SignatureRNotPrimeOrder) |
| 53 | invalid | REJECT | REJECT | PASS | Err(SignatureRNotPrimeOrder) |
| 54 | invalid | REJECT | REJECT | PASS | Err(SignatureREncoding) |
| 55 | invalid | REJECT | REJECT | PASS | Err(SignatureREncoding) |
| 56 | invalid | REJECT | REJECT | PASS | Err(SignatureEquationMismatch) |
| 57 | invalid | REJECT | REJECT | PASS | Err(SignatureRNotPrimeOrder) |
| 58 | invalid | REJECT | REJECT | PASS | Err(SignatureREncoding) |
| 59 | invalid | REJECT | REJECT | PASS | Err(SignatureEquationMismatch) |
| 60 | invalid | REJECT | REJECT | PASS | Err(SignatureRNotPrimeOrder) |
| 61 | invalid | REJECT | REJECT | PASS | Err(SignatureRNonCanonical) |
| 62 | invalid | REJECT | REJECT | PASS | Err(SignatureRNotPrimeOrder) |
| 63 | invalid | REJECT | REJECT | PASS | Err(SignatureScalarNonCanonical) |
| 64 | invalid | REJECT | REJECT | PASS | Err(SignatureScalarNonCanonical) |
| 65 | invalid | REJECT | REJECT | PASS | Err(SignatureScalarNonCanonical) |
| 66 | invalid | REJECT | REJECT | PASS | Err(SignatureScalarNonCanonical) |
| 67 | invalid | REJECT | REJECT | PASS | Err(SignatureScalarNonCanonical) |
| 68 | invalid | REJECT | REJECT | PASS | Err(SignatureScalarNonCanonical) |
| 69 | invalid | REJECT | REJECT | PASS | Err(SignatureScalarNonCanonical) |
| 70 | invalid | REJECT | REJECT | PASS | Err(SignatureScalarNonCanonical) |
| 71 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 72 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 73 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 74 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 75 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 76 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 77 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 78 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 79 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 80 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 81 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 82 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 83 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 84 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 85 | invalid | REJECT | REJECT | PASS | Err(SignatureScalarNonCanonical) |
| 86 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 87 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 88 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 89 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 90 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 91 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 92 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 93 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 94 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 95 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 96 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 97 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 98 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 99 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 100 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 101 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 102 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 103 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 104 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 105 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 106 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 107 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 108 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 109 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 110 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 111 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 112 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 113 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 114 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 115 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 116 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 117 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 118 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 119 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 120 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 121 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 122 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 123 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 124 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 125 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 126 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 127 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 128 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 129 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 130 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 131 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 132 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 133 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 134 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 135 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 136 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 137 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 138 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 139 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 140 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 141 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 142 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 143 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 144 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 145 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 146 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 147 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 148 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 149 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 150 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 151 | invalid | REJECT | REJECT | PASS | Err(SignatureRNonCanonical) |
| 152 | acceptable | REJECT | REJECT | PASS | Err(PublicKeyIdentity) |
| 153 | acceptable | REJECT | REJECT | PASS | Err(PublicKeyNotPrimeOrder) |
| 154 | acceptable | REJECT | REJECT | PASS | Err(PublicKeyNotPrimeOrder) |
| 155 | acceptable | REJECT | REJECT | PASS | Err(PublicKeyNotPrimeOrder) |
| 156 | acceptable | REJECT | REJECT | PASS | Err(PublicKeyNotPrimeOrder) |
| 157 | acceptable | REJECT | REJECT | PASS | Err(PublicKeyNotPrimeOrder) |
| 158 | acceptable | REJECT | REJECT | PASS | Err(PublicKeyNotPrimeOrder) |
| 159 | acceptable | REJECT | REJECT | PASS | Err(PublicKeyNotPrimeOrder) |
| 160 | acceptable | REJECT | REJECT | PASS | Err(PublicKeyNotPrimeOrder) |
| 161 | acceptable | REJECT | REJECT | PASS | Err(PublicKeyNotPrimeOrder) |
| 162 | acceptable | REJECT | REJECT | PASS | Err(PublicKeyNotPrimeOrder) |
| 163 | acceptable | REJECT | REJECT | PASS | Err(PublicKeyNotPrimeOrder) |
| 164 | acceptable | REJECT | REJECT | PASS | Err(PublicKeyNotPrimeOrder) |
| 165 | acceptable | REJECT | REJECT | PASS | Err(PublicKeyNotPrimeOrder) |
| 166 | acceptable | REJECT | REJECT | PASS | Err(PublicKeyNotPrimeOrder) |
| 167 | acceptable | REJECT | REJECT | PASS | Err(PublicKeyNotPrimeOrder) |
| 168 | acceptable | REJECT | REJECT | PASS | Err(PublicKeyNotPrimeOrder) |
| 169 | acceptable | REJECT | REJECT | PASS | Err(PublicKeyNotPrimeOrder) |
| 170 | acceptable | REJECT | REJECT | PASS | Err(PublicKeyNotPrimeOrder) |
| 171 | acceptable | REJECT | REJECT | PASS | Err(PublicKeyNotPrimeOrder) |
| 172 | acceptable | REJECT | REJECT | PASS | Err(PublicKeyNotPrimeOrder) |
| 173 | acceptable | REJECT | REJECT | PASS | Err(PublicKeyNotPrimeOrder) |
| 174 | acceptable | REJECT | REJECT | PASS | Err(PublicKeyNotPrimeOrder) |
| 175 | acceptable | REJECT | REJECT | PASS | Err(PublicKeyNotPrimeOrder) |
| 176 | acceptable | REJECT | REJECT | PASS | Err(PublicKeyNotPrimeOrder) |
| 177 | acceptable | REJECT | REJECT | PASS | Err(PublicKeyNotPrimeOrder) |
| 178 | acceptable | REJECT | REJECT | PASS | Err(PublicKeyNotPrimeOrder) |
| 179 | acceptable | REJECT | REJECT | PASS | Err(PublicKeyNotPrimeOrder) |
| 180 | acceptable | REJECT | REJECT | PASS | Err(PublicKeyNotPrimeOrder) |
| 181 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 182 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 183 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 184 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 185 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 186 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 187 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 188 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 189 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 190 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 191 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 192 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 193 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 194 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 195 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 196 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 197 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 198 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 199 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 200 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 201 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 202 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 203 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 204 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 205 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 206 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 207 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 208 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 209 | valid | ACCEPT | ACCEPT | PASS | Ok(()) |
| 210 | invalid | REJECT | REJECT | PASS | Err(PublicKeyNotPrimeOrder) |

- Total: **210/210 executed**, 117 ACCEPT and 93 REJECT; 0 expected-result mismatches.
- Original verdict totals: 117 valid, 64 invalid, 29 acceptable. Actual: all 117 valid accepted; all 64 invalid rejected; all 29 acceptable rejected under the stricter A subgroup/identity requirements.
- tcId 152: original `acceptable`, profile expected REJECT, actual REJECT (`PublicKeyIdentity`). Original Wycheproof verdict is unchanged.
- Identity-R negative cases tcId 15–19: original invalid, profile expected REJECT, actual REJECT; R point admissibility is not treated as equation success.

## Project-specific V04 cases

Only complete case objectives with reproducible inputs and expected results are counted as executed. No signed ROOT_POLICY frame, manifest/root-set golden, quorum fixture, or customer/custodian signature was created; the separate identity-R fixture is synthetic public TEST data only.

| ID | Objective | Status | Inputs / expectation / scope / evidence |
|---|---|---|---|
| V04-01 | RFC positive vectors, separate from project frames | IMPLEMENTED_PASS | Inputs: approved RFC 8032 fixtures; expected ACCEPT is source-published; 3/3 executed and passed. Raw RFC messages do not cover project frames. |
| V04-02 | Canonical body, manifest, key-set, frame bytes/digests | NOT_READY | No project-specific approved golden inputs/expected bytes; requires ROOT_POLICY canonicalization and digest components beyond this signature-only verifier. |
| V04-03 | Valid two-custodian TEST quorum | OUTSIDE_PROTOTYPE_SCOPE | No quorum fixture/evaluator; requires independently pinned anchors and custodian policy. |
| V04-04 | Three signatures and all permutations | OUTSIDE_PROTOTYPE_SCOPE | Requires quorum evaluator and custodian binding; no approved fixtures. |
| V04-05 | Zero/one vote denial | OUTSIDE_PROTOTYPE_SCOPE | Requires quorum evaluator and policy inputs. |
| V04-06 | Modified signature rejection | IMPLEMENTED_PASS | Approved RFC signature with mutation; expected REJECT; executed and rejected. |
| V04-07 | Duplicate identities/keys/material | OUTSIDE_PROTOTYPE_SCOPE | Requires identity/anchor uniqueness policy, not a single-signature verifier. |
| V04-08 | Wrong tenant binding | OUTSIDE_PROTOTYPE_SCOPE | Requires signed ROOT_POLICY envelope and independently supplied expected context. |
| V04-09 | Wrong deployment/customer/domain | OUTSIDE_PROTOTYPE_SCOPE | Requires binding/context verifier. |
| V04-10 | Wrong environment / production classification | OUTSIDE_PROTOTYPE_SCOPE | Requires environment and purpose policy parser. |
| V04-11 | Unsupported/mixed algorithm profiles | OUTSIDE_PROTOTYPE_SCOPE | Low-level API is fixed pure Ed25519; protocol/profile negotiation rejection belongs to envelope parser. |
| V04-12 | Noncanonical JSON/identifier/time/numeric forms | OUTSIDE_PROTOTYPE_SCOPE | Requires closed ROOT_POLICY parser/canonicalizer. |
| V04-13 | Unknown fields/trust flags/key URLs | OUTSIDE_PROTOTYPE_SCOPE | Requires envelope schema and trust-source rejection rules. |
| V04-14 | Incorrect/inconsistent digest claims | OUTSIDE_PROTOTYPE_SCOPE | Requires payload, root-set, manifest, and frame digest verification. |
| V04-15 | Two valid plus invalid third signature | OUTSIDE_PROTOTYPE_SCOPE | Requires quorum verifier; this prototype does not define extra-signature policy. |
| V04-16 | Unknown signer/wrong key | OUTSIDE_PROTOTYPE_SCOPE | Wrong-key equation rejection is covered at the primitive level; identifying unknown signers requires anchor/custodian policy, so the full case is not tested. |
| V04-17 | Revoked/expired/future-time cases | OUTSIDE_PROTOTYPE_SCOPE | Requires lifecycle, revocation, and time policy. |
| V04-18 | Missing/self-selected/corrupt TEST anchor | OUTSIDE_PROTOTYPE_SCOPE | Requires independently supplied trust-anchor view. |
| V04-19 | Stale/unapproved policy or pin | OUTSIDE_PROTOTYPE_SCOPE | Requires current-policy and anchor-pin source. |
| V04-20 | Synthetic/production source rejection | OUTSIDE_PROTOTYPE_SCOPE | Requires trusted source classification; the synthetic positive fixture is not an authority anchor. |
| V04-21 | A/R/S malformed, subgroup, scalar and corpus edge cases | IMPLEMENTED_PASS | A/R/S boundary tests, identity-R positive and negative equation tests, all 210 Wycheproof cases; passed under project-profile expectations. |
| V04-22 | Wrong domain/frame/purpose/trailing bytes | OUTSIDE_PROTOTYPE_SCOPE | Requires frame and purpose parser; RFC vectors use raw messages. |
| V04-23 | Size/depth/entry limits and boundaries | OUTSIDE_PROTOTYPE_SCOPE | Requires bounded envelope parser. |
| V04-24 | Multi-fault precedence and counters | OUTSIDE_PROTOTYPE_SCOPE | Requires frozen 15-code diagnostic engine. |
| V04-25 | Provider/customer authority separation | OUTSIDE_PROTOTYPE_SCOPE | Requires authority model; no authority is represented by this prototype. |
| V04-26 | Backend/source error, mutation and no IAM consumer | NOT_READY | Message/signature mutations and isolated crate boundary are covered; backend fault injection and a separate consumer-boundary review remain absent. |

**Project case count:** 3/26 complete test objectives `IMPLEMENTED_PASS` (V04-01, V04-06, V04-21); 0 `IMPLEMENTED_FAIL`; 2 `NOT_READY` (V04-02, V04-26); 21 `OUTSIDE_PROTOTYPE_SCOPE`. No case is promoted based only on a lower-level primitive result.

## Limits and status

- No canonical signed-body/frame/root-set/manifest goldens, customer/custodian signatures, quorum, trust-anchor, revocation, time, or ROOT_POLICY tests.
- No implementation of the frozen 15 diagnostic precedence, JSON schema, policy freshness, tenant/deployment binding, authority provider, or IAM admission.
- Upstream public-vector authenticity remains pending. The local fixture content and IDs are preserved; manifest POSIX CRC values are not publisher authentication, and ID-set validation does not establish source authenticity.
- The identity-R fixture's expected result follows from the stated algebraic construction, but it is synthetic, publicly forgeable, and not an independently reviewed golden vector. The source-level equation analysis is not independent cryptographic review; point checks are composed from one Dalek family and package sources are the locked crates.io artifacts.
- H-COMP-1 remains experimental and non-production. A successful signature check alone grants no permission.
