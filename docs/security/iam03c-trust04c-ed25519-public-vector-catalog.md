# TRUST-04C public Ed25519 verification vector catalog

Acquired **2026-11-16**. **PUBLIC, NON-SECRET, TEST-ONLY.** No verification, signing,
key generation or cryptographic hashing was executed. Existing published signatures
were copied, never generated. No private-key/seed fields were saved.
[Asset manifest](../../tests/iam/fixtures/trust04c_public_vectors/manifest.json),
[golden derivation plan](iam03c-trust04c-independent-golden-vector-plan.md),
[G1 review](iam03c-trust04c-g1-evidence-review.md).

## 1. Acquired assets and provenance

All files are confined to tests/iam/fixtures/trust04c_public_vectors/. They are data
or license text, not executable modules. No package/archive or RFC example code was
saved. The manifest contains source URLs/versions/date/reuse constraints/CRC sizes/
review status for each acquired asset; it is metadata, not a trust anchor.

| File | Original source / version | Contents and source expected result |
| --- | --- | --- |
| [rfc8032-section7_1-verification-only.json](../../tests/iam/fixtures/trust04c_public_vectors/rfc8032-section7_1-verification-only.json) | [RFC Editor plaintext](https://www.rfc-editor.org/rfc/rfc8032.txt), RFC 8032 January 2017, section 7.1 TEST 1, 2, 3 | Three exact public keys/messages/signatures, expected valid. Messages contain 0, 1, 2 bytes. SECRET KEY sections omitted; factual verification-only extraction, not an original artifact mirror |
| [wycheproof-ed25519-a3d5d142.json](../../tests/iam/fixtures/trust04c_public_vectors/wycheproof-ed25519-a3d5d142.json) | [C2SP pinned file](https://raw.githubusercontent.com/C2SP/wycheproof/a3d5d1423f2592d6646836a45a21a1b209da9f4d/testvectors_v1/ed25519_test.json), commit a3d5d1423f2592d6646836a45a21a1b209da9f4d | Exact upstream JSON bytes, 210 verification cases; native results 117 valid, 64 invalid, 29 acceptable. Original keys, messages, signatures, tcId, flags/comments and notes unchanged |
| [LICENSE.wycheproof.txt](../../tests/iam/fixtures/trust04c_public_vectors/LICENSE.wycheproof.txt) | [same-commit license](https://raw.githubusercontent.com/C2SP/wycheproof/a3d5d1423f2592d6646836a45a21a1b209da9f4d/LICENSE) | Original Apache-2.0 text retained; not executed |
| manifest.json | Prepared provenance metadata for this acquisition | Public TEST classification, exact file references, source authenticity limitations and independent review PENDING; not a cryptographic golden oracle |

RFC test records retain source ID, original expected result and local verification
NOT_EXECUTED. The public bytes can be read directly from the linked assets; none
is a customer key or an approved root. Original messages are not IAM signing frames.
RFC reuse remains subject to its BCP78/IETF Trust notices; no implementation code or
secret example seed is copied. Apache reuse requirements accompany the Wycheproof
asset; independent license/provenance review remains required before adoption.

## 2. Integrity and authenticity limits

GitHub contents metadata for the pinned corpus supplied git blob object ID
`3f991dd56496129e3a99b6b486408ef8f3df6945` and a matching byte count. This is a
publisher-site object identifier, not a locally verified file SHA-256. No Git/SHA
computation was run to verify it. No publisher RFC checksum was obtained.

The manifest records permitted non-cryptographic POSIX cksum CRC/byte counts:

| Asset | CRC | Bytes |
| --- | --- | --- |
| RFC verification-only JSON | 1429421017 | 1848 |
| Original Wycheproof JSON | 2425208181 | 172628 |
| Original Wycheproof license | 608758943 | 11357 |

The upstream license lacks a final newline; that original byte form is deliberately
preserved. All four new data/license/manifest files have no trailing-whitespace
lines. No source data was reformatted to satisfy a whitespace convention.

CRC is accidental-change detection/file identity evidence, **not** publisher
cryptographic authenticity or a signing-frame digest. HTTPS publisher identity,
commit-pinned URL and metadata are acquisition evidence; no independent release
signature/attestation was verified. Independent reviewer sign-off is PENDING.
Assets are ACQUIRED_PENDING_INDEPENDENT_REVIEW, not approved verifier fixtures or
production trust. A future authenticity failure must quarantine/reject the asset.

## 3. Original semantics versus the frozen strict policy

[RFC 8032 section 5.1.7](https://www.rfc-editor.org/rfc/rfc8032#section-5.1.7)
requires decoded points/scalar range and permits verification equations involving
cofactor clearing; the project additionally fixes prime-subgroup/nonidentity-key
restrictions. A general RFC-compatible verifier need not enforce every project rule.

The acquired corpus's own notes explicitly distinguish SmallOrderPublicKey and
MixedOrderPublicKey, with acceptable equation-valid cases under a cofactored policy.
There are 8 small-order-flagged and 22 mixed-order-flagged tests (flags are counted,
not asserted as independently established point properties). The original 29
acceptable results are not converted to valid or invalid in the acquired file.

[ZIP 215](https://zips.z.cash/zip-0215), Final, consulted 2026-11-16, illustrates
another explicitly different policy permitting noncanonical encodings/cofactored
validation. It is comparison evidence, not the project's acceptance rule. Frozen
TRUST-04 excludes that permissive substitution; it is not changed here.

For each adversarial case, a future independent reviewer must retain the native
result/flags, identify its point/encoding assumptions and record a separate
ED25519-PURE-1 verdict/justification. Source acceptable is **PENDING_PROFILE_REVIEW**,
never automatic success. Source valid also does not prove local library conformity.
Small/mixed-order classes contradict the project's admitted key subgroup if accepted;
they must test rejection under the frozen policy, without relabelling the publisher's
native semantics. If no safe per-case reconciliation or vetted enforcing API exists,
stop for owner review; do not alter the source data or weaken the profile.

## 4. Compatibility evidence classes

| Requirement | Evidence class / source | Remaining work |
| --- | --- | --- |
| Raw 32-byte key loading and verify(data) API | DOCUMENTED API SUPPORT, [PyCA 50.0.2 API](https://cryptography.io/en/50.0.2/hazmat/primitives/asymmetric/ed25519/) | Actual candidate/backend behavior and exact exceptions require tests |
| Pure message versus ph/ctx, scalar/point decoding | PUBLISHED COMPATIBILITY EVIDENCE, RFC 8032 sections 5.1/7 | Project wrapper must pass full exact frame and forbid variants; no test executed |
| Backend delegation | PUBLISHED COMPATIBILITY EVIDENCE, [50.0.2 implementation](https://raw.githubusercontent.com/pyca/cryptography/50.0.2/src/rust/src/backend/ed25519.rs) | No-digest one-shot OpenSSL call is source evidence, not subgroup proof |
| Canonical S/A/R, low-/mixed-order rejection | REQUIRES LOCAL COMPATIBILITY TEST, corpus/source-policy differences above | Exact selected package/backend must demonstrate frozen behavior with reviewed vectors |
| Quorum/unknown/revoked/cross-context behavior | UNVERIFIED future wrapper behavior; not a library signature feature | Independent TEST pin/context fixtures and all frozen stage/counter tests |
| Overall ED25519-PURE-1 conformance | UNVERIFIED | No library was imported, no signature checked, no passing result inferred |

**PUBLIC VECTORS: ACQUIRED** means source data obtained, not cryptographically
verified, independently approved, sufficient for all 26 cases or operationally trusted.
