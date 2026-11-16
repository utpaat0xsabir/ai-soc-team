# TRUST-04G source-level verification evidence

2026-11-16. TRUST-04G read-only research and documentation. No cryptographic execution, dependency changes, new trust, owner approval or independent cryptographic sign-off. Existing frozen proposals remain unchanged.

## Evidence method and source identities

Read-only primary HTTPS research retrieved 2026-11-16. Tags below are exact inspected
version references, not locally authenticated immutable commit pins; future review
must resolve full commits and publisher artifacts. No external source was installed,
imported or executed. Claims about functions are SOURCE_CONFIRMED only within the
inspected paths; DOCUMENTED_ONLY, AUDIT_SUPPORTED and TEST_EVIDENCE_REQUIRED have
separate meanings. UNVERIFIED is an explicit gap, not a permissive assumption.

| ID / title | Exact source, version and location | Evidence and uncertainty |
| --- | --- | --- |
| S1 RFC 8032 EdDSA | [RFC](https://www.rfc-editor.org/rfc/rfc8032), January2017, sections5.1.2/3/7 and8.4 | Algorithm specification; project adds stronger subgroup/key rules. Not a runtime test |
| S2 PyCA backend | [ed25519.rs](https://raw.githubusercontent.com/pyca/cryptography/50.0.2/src/rust/src/backend/ed25519.rs), pyca/cryptography tag50.0.2, Ed25519PublicKey::verify | SOURCE_CONFIRMED no-digest OpenSSL one-shot delegation; does not establish internal OpenSSL equation |
| S3 libsodium predicate | [core_ed25519.c](https://raw.githubusercontent.com/jedisct1/libsodium/1.0.22-RELEASE/src/libsodium/crypto_core/ed25519/core_ed25519.c), tag1.0.22-RELEASE, crypto_core_ed25519_is_valid_point, lines8–19 | SOURCE_CONFIRMED calls canonical/small-order/decode/curve/subgroup gates; helper correctness and runtime remain separate |
| S4 libsodium subgroup helper | [ed25519_ref10.c](https://raw.githubusercontent.com/jedisct1/libsodium/1.0.22-RELEASE/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c), same tag, ge25519_is_on_main_subgroup lines986–995 | SOURCE_CONFIRMED multiplies by L and checks projective identity coordinates; not an audit of arithmetic |
| S5 libsodium detached verifier | [open.c](https://raw.githubusercontent.com/jedisct1/libsodium/1.0.22-RELEASE/src/libsodium/crypto_sign/ed25519/ref10/open.c), same tag, _crypto_sign_ed25519_verify_detached lines11–58 | SOURCE_CONFIRMED scalar/small-order gates, hash/reconstruction/compare; public pure entry passes prehashed=0. ED25519_COMPAT changes checks |
| S6 dalek point primitives | [edwards.rs](https://raw.githubusercontent.com/dalek-cryptography/curve25519-dalek/curve25519-4.1.3/curve25519-dalek/src/edwards.rs), tagcurve25519-4.1.3, decompress183, compress524, is_small_order1141, is_torsion_free1170 | SOURCE_CONFIRMED distinct decoding, encoding and subgroup predicates; identity is torsion-free, so A still needs exclusion |
| S7 dalek signature verifier | [verifying.rs](https://raw.githubusercontent.com/dalek-cryptography/curve25519-dalek/ed25519-2.2.0/ed25519-dalek/src/verifying.rs), taged25519-2.2.0, raw_verify187, verify_strict338, RCompute456, Verifier::verify530 | SOURCE_CONFIRMED ordinary pure SHA512 reconstruction/encoded comparison and extra small-order rejection in strict path; no full profile runtime proof |
| S8 dalek scalar parsing | [signature.rs](https://raw.githubusercontent.com/dalek-cryptography/curve25519-dalek/ed25519-2.2.0/ed25519-dalek/src/signature.rs), same tag, check_scalar63/84 | SOURCE_CONFIRMED canonical scalar constructor normally; legacy_compatibility weakens check. Must prohibit through entire feature graph |
| S9 scalar constructor | [scalar.rs](https://raw.githubusercontent.com/dalek-cryptography/curve25519-dalek/curve25519-4.1.3/curve25519-dalek/src/scalar.rs), tagcurve25519-4.1.3, Scalar::from_canonical_bytes | SOURCE_CONFIRMED high-bit and canonical-range predicate at lines249–252; arithmetic/backend correctness still needs review; no reduction constructor for input S |
| S10 Rust metadata | [ed25519 Cargo](https://raw.githubusercontent.com/dalek-cryptography/curve25519-dalek/ed25519-2.2.0/ed25519-dalek/Cargo.toml) and [curve Cargo](https://raw.githubusercontent.com/dalek-cryptography/curve25519-dalek/curve25519-4.1.3/curve25519-dalek/Cargo.toml) | DOCUMENTED_ONLY versions2.2.0/4.1.3, BSD-3-Clause, Rust minimum1.81/1.60 respectively; dependency ranges not a reproducible lock |
| S11 libsodium release/security history | [official releases](https://github.com/jedisct1/libsodium/releases), observed1.0.22 and1.0.21 entries | DOCUMENTED_ONLY1.0.21 includes point-validator security fix; prior1.0.20 release-source mention is not clearance of that predicate |
| S12 PyCA security policy | [50.0.2 security](https://cryptography.io/en/50.0.2/security/) | DOCUMENTED_ONLY reporting/advisory process, not a conformance or vulnerability-free certification |
| S13 historical independent assessment | [Quarkslab audit summary](https://blog.quarkslab.com/security-audit-of-dalek-libraries.html), 2019-08-26 | AUDIT_SUPPORTED historical limited scope; Edwards/Scalar and selected backends reviewed, only quick look at Ed25519. Does not cover these release tags, proposed wrapper or Python binary |
| S14 signing advisory | [RUSTSEC-2022-0093](https://rustsec.org/advisories/RUSTSEC-2022-0093.html), issued2023-08-14, modified2025-10-28 | Maintainer-ecosystem advisory reports double-public-key signing issue, patched>=2; not this verification discrepancy or blanket safety of2.2.0 |
| S15 timing advisory | [RUSTSEC-2024-0344](https://rustsec.org/advisories/RUSTSEC-2024-0344.html), issued2024-06-18, modified2025-10-28 | Reports scalar subtraction timing issue patched>=4.1.3; public verification scope differs from signing but feature/backend review remains required |
| S16 licenses | [libsodium ISC](https://raw.githubusercontent.com/jedisct1/libsodium/1.0.22-RELEASE/LICENSE), same tag; S10 BSD declarations | Source-supported license identifiers only; binding/transitive/legal compatibility pending |

The official libsodium security-document URL was unavailable through research tool;
no absent advisory or audit result is inferred. Official dalek release pages were
consulted but did not establish a support window for reviewed tags. Search results
for third-party audit summaries were not used as security proof. The Quarkslab
publisher summary is the acquired audit evidence; full report-to-exact-tag mapping
has not been performed. No audit supports our complete composition yet.

## Source findings by component

A: libsodium S3 exposes the intended sequence of validation gates. S4 supplies more
than a function name for subgroup intent. Historical S3-at-1.0.20 is not sufficient
selection evidence because S11 documents a later fix. The complete helper/build path
and negative cases still need review. Dalek S6 supports explicit decompress/recompress
byte equality, torsion-free membership and separate identity predicate. Decompression
alone must not be treated as canonical acceptance. No binary is validated here.

R: S6 supplies subgroup predicates without conflating torsion-free with nonidentity.
Both S5 and S7 strict path reject small-order R, therefore the permitted identity case
cannot use those entries unchanged. An ordinary S7 equation path has no explicit
small-order-R rejection; after separate full validation it is a promising component,
not a claim that unvalidated ordinary verification meets the profile. Need an
independent equation-valid identity-R positive; no source-only shortcut around tests.

S: S8 normally enforces canonical scalar range. Compatibility features change that
behavior, so names/versions alone are inadequate. Fixed32 unsigned LE and S<L are
required; zero is not forbidden. Constructor success is not signature success.

Equation: S7's RCompute hashes original encoded R/A and M, reduces challenge, and
uses double-scalar reconstruction with encoded R comparison. Source supports pure
non-cofactored verification intent. S5 similarly reconstructs and compares; it has
additional rejection semantics that cannot be repaired by only rejecting more inputs.
S2 source confirms delegation only: no internal equation is attributed to the
installed OpenSSL binary. No code changes, mode substitution or verification occurred.

For canonical A/R in prime subgroup H and in-range S, E1/E8 equivalence follows
because the residual is in H and multiplication by8 is invertible there. All these
assumptions are in the frozen candidate. Missing subgroup gates, changed transcript
or extra backend rejection invalidates a claim of complete equivalence. R=O remains
allowed subject to equation. Do not infer full protocol correctness from that algebra.

## tcId152 and level of proof

[Recorded results](../../tests/iam/fixtures/trust04d_offline_validation/results.json)
and [04E reconstruction](iam03c-trust04e-case152-evidence-reconstruction.md) establish
canonical identity A accepted on raw message bytes in the exact recorded environment.
The source original verdict is acceptable; project A restriction still rejects.
S3 or the strict paths' small-order gates would reject that class according to source;
this is TEST_EVIDENCE_REQUIRED for any new binary. Rejecting this one case proves
neither all subgroup behavior nor R/S compatibility. No general PyCA/OpenSSL
insecurity, production enrollment or operational exploit is established.

## Required evidence before selecting any prototype dependency

Resolve exact tag->commit->artifact correspondence and authentication; inspect full
feature/transitive graph and prohibitions, CPU/compiler/backends, failure handling,
round-trip canonical behavior, reviewer findings and current advisories/support.
Record no source/binary equivalence without reproducible artifacts. No new release,
Rust runtime, Python binding, package list or installation is approved. Independent
review must verify low-level helper semantics and actual code composition, followed
by separately authorized vectors. SOURCE_SUPPORTED is not cryptographic sign-off.
