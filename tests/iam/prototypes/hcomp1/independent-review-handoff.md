# H-COMP-1 Independent Cryptographic Review Handoff

**Prepared:** 2026-11-16
**Status:** Internal review package prepared; no reviewer appointed and no external assessment performed.
**Disclosure:** Owner approval is required before any listed material is shared. No files were transmitted.

## A. Executive summary

H-COMP-1 is an isolated, non-authorizing Ed25519 verifier prototype for a proposed customer-controlled root-of-trust design. Its recorded internal offline run reports 9 Rust tests passing, including 3 RFC 8032 vectors, all 210 Wycheproof cases, identity-A rejection, and a synthetic valid identity-R case. The separate provenance report records exact RFC field matches, byte-identical pinned C2SP corpus content, and byte-identical TSV reproduction. These are internal results, not independent certification. Wycheproof publisher signature authenticity remains unverified. This handoff asks a qualified independent reviewer to assess the mathematics, exact dependency implementation, composition, and test sufficiency, and to identify defects even if the reported tests pass. H-COMP-1 remains proposed and unapproved for production or operational IAM.

## B. Review scope

**Included:** the standalone implementation in `tests/iam/prototypes/hcomp1/`; exact dependency declarations and lockfile; the profile and composition requirements below; source fixtures, extraction rules, recorded tests, and provenance evidence in the manifest.

**Excluded:** production deployment approval; full ROOT_POLICY parsing/enforcement; trust-anchor custody or enrollment; quorum ceremonies; tenant/IAM authorization; database schema or access; Wazuh, Shuffle, or Ollama integration; operational authority-provider behavior. The prototype must remain disconnected from operational IAM. A cryptographic PASS is evidence about the supplied bytes only and does not authorize a signer or action.

The reviewer is free to challenge the profile itself as well as its implementation. The reviewer must distinguish mathematical concerns, implementation defects, test gaps, and policy choices. No new tests or cryptographic execution were performed for this handoff.

## C. Cryptographic profile

H-COMP-1 uses `curve25519-dalek = 4.1.3` and `ed25519-dalek = 2.2.0` as declared in the included manifest and lockfile. The intended profile, still subject to independent review and owner decisions, is:

- **A (public key):** exactly 32 bytes; canonical compressed Edwards encoding; valid decompression/on-curve point; prime-order subgroup membership; identity rejected.
- **R (signature point):** exactly the first 32 signature bytes; canonical encoding; valid point; prime-order subgroup membership; identity permitted at point-validation stage and accepted only if the complete signature equation passes.
- **S (signature scalar):** exactly the final 32 bytes, unsigned little-endian, canonical and `0 ≤ S < L`; no reduction of a noncanonical value.
- **Mode/equation:** pure Ed25519 over the exact input message; the proposed ordinary pure verification path is intended to enforce the non-cofactored equation. No Ed25519ph/ctx, algorithm negotiation, fallback, or alternate verifier is permitted.
- **Composition:** A/R/S prevalidation followed by verification of the same unchanged key, signature, and message bytes. No identity-R shortcut. No trust, quorum, or operational authorization is produced by the primitive.

The reviewer should verify that code and locked features actually enforce each property and may reject the profile or composition as unsuitable.

## D. Evidence manifest

SHA-256 is an inventory integrity aid for the exact bytes inspected; it does not establish publisher authenticity, reviewer approval, or safety. Paths are repository-relative. Build outputs, caches, Git internals, environment files, credentials, private keys, logs, database dumps, and unrelated project files are excluded. Public vectors are non-secret. The source, specifications, and internal test artifacts contain internal security design details; obtain owner disclosure approval before transfer.

| Repository-relative path | Bytes | SHA-256 | Type | Purpose |
|---|---:|---|---|---|
| `tests/iam/prototypes/hcomp1/src/lib.rs` | 17012 | `82280d58ad65c7e83bf9b412f709d6416cd9f3ce0e3bb8cdb3be8ed00756c2c5` | Prototype source | Rust verifier implementation |
| `tests/iam/prototypes/hcomp1/Cargo.toml` | 258 | `d76a6814b97ffa54504342423235bb8b87970f4b60986cd127cff61daaf1df93` | Dependency manifest | Pinned direct dependencies and features |
| `tests/iam/prototypes/hcomp1/Cargo.lock` | 8418 | `abd67bf1716726da4cd4dbfe2eed528c0db1096646ef02769088b167fd1791ea` | Dependency lockfile | Resolved dependency graph |
| `tests/iam/prototypes/hcomp1/test-results.md` | 24855 | `2e26d6eadaac782f916deaca06c00db8d98f0e8806ef9b7b0e2dcbf7d4ecb85c` | Test evidence | Recorded offline build, test counts, vector results, and limitations |
| `tests/iam/prototypes/hcomp1/upstream-provenance-report.md` | 28661 | `22435ba4fa8528c9c75e7a3d5dcc2a7e00bcd6d1bfe19611aea8fcd6c7c8f150` | Provenance evidence | RFC and Wycheproof source comparisons and provenance limitations |
| `tests/iam/prototypes/hcomp1/tests/prepare_vectors.py` | 1657 | `99c2fab503fdc7103a905a072c139833131ca860d0e9438f07ce7a49efb47fec` | Test utility | Local vector-to-TSV extraction rules |
| `tests/iam/prototypes/hcomp1/tests/generate_identity_r_fixture.py` | 947 | `815c2ec55043e61d2564b4a052078fd40765a4e6721fa3926139eb54096062b3` | Test utility | Synthetic identity-R fixture derivation |
| `tests/iam/prototypes/hcomp1/tests/rfc8032.tsv` | 688 | `ef7e1d147aacd35987858421b9ead6cfa5b6de719e7ca8afdc607220cf65a7bb` | Test fixture | Three RFC 8032 verification cases |
| `tests/iam/prototypes/hcomp1/tests/wycheproof.tsv` | 54891 | `0999ed91e329f37fd3285e56f45d390a940597b408d1f31a710edde59f02e92e` | Test fixture | 210 Wycheproof Ed25519 cases and retained verdicts |
| `tests/iam/prototypes/hcomp1/tests/identity-r-positive.tsv` | 306 | `75e6ff4575d79859e386873b03e215be9f8d6e4b6b9f223d38ead29de7f72e8e` | Test fixture | Public synthetic identity-R positive case |
| `tests/iam/fixtures/trust04c_public_vectors/manifest.json` | 3232 | `6ab7408744b0af0779efc31ba873ba90379dc042d606b9c0092622367bf8b482` | Provenance evidence | Original fixture source claims and local integrity metadata |
| `tests/iam/fixtures/trust04c_public_vectors/rfc8032-section7_1-verification-only.json` | 1848 | `fe800b1c0011d9a7ccedec69fabaaef72806e183b216dff699d6d8d2546e32ee` | Test fixture | Locally extracted public RFC fields |
| `tests/iam/fixtures/trust04c_public_vectors/wycheproof-ed25519-a3d5d142.json` | 172628 | `ea80ffebac085e21cb9d3e903e7fa2b448d96702da5b31f061d0b83b430b74b3` | Test fixture | Commit-pinned public C2SP source corpus |
| `tests/iam/fixtures/trust04c_public_vectors/LICENSE.wycheproof.txt` | 11357 | `58d1e17ffe5109a7ae296caafcadfdbe6a7d176f0bc4ab01e12a689b0499d8bd` | License evidence | Upstream corpus license text |
| `docs/security/iam03c-trust04f-strict-ed25519-normative-profile.md` | 10360 | `86b939da7ae59bcf7d70bb88fdc544d8b63387b0c53d8663824ce4f90281e534` | Specification | Proposed frozen A/R/S and equation profile |
| `docs/security/iam03c-trust04h-exact-verification-composition.md` | 11086 | `218b47625fe7389f27d4cf548a46eafc0650e5aba61eeba9de00b1f90293dbd4` | Specification | H-COMP-1 composition proposal and source references |
| `docs/security/iam03c-trust04-root-policy-wire-spec.md` | 20577 | `b2f4731cb4c8752252aa19cbef9b26716ad632596716ff2bdd504d65c53b17f7` | Specification | Frozen ROOT_POLICY wire contract |
| `docs/security/iam03c-trust04-vector-and-error-matrix.md` | 22227 | `b42f71df03aeefbb5b0573cc46a3df97abc9e1eed8c1193c454bf68dbda0d918` | Specification | Project vector objectives and ordered diagnostics |
| `docs/security/iam03c-trust04i-hcomp1-review-baseline-and-artifact-requirements.md` | 9715 | `2c18bce806ae3159051a5f925e9b720b769eaa79137f12fcd4131c67103f1265` | Review requirements | Assessment baseline and artifact requirements |
| `docs/security/iam03c-trust04i-independent-reviewer-statement-of-work.md` | 7361 | `0e0fcf5d33f86fe6246c43f21af20a201f5e4d9ccc417ed0ae1d095df971271c` | Review requirements | Prior reviewer scope draft |
| `docs/security/iam03c-trust04i-review-evidence-and-decision-record.md` | 5649 | `cb18e0b08d96e0c057ba974e724c5dafea21ade7e0dc690219f96e3698cf52de` | Review template | Blank reviewer evidence and decision record |
| `docs/security/iam03c-trust04i-owner-actions-and-g1-readiness.md` | 6805 | `7dbbf549a1b101e100dba8986f6a83b642efc3ed95d527667e70d29970bb4c11` | Decision evidence | Owner gates and pending D04F decisions |
| `docs/security/iam03c-trust04j-external-reviewer-handoff.md` | 6986 | `c359aa4d439220e07562ee6059e6f5b72ec0794ea80c6f5b2c8740365d90f023` | Prior handoff | Earlier chronological handoff; predates implemented prototype |
| `docs/security/iam03c-trust04j-evidence-manifest-and-disclosure-review.md` | 25343 | `5298bbb6dec430610d5b70b6099147d994126f90ca7d861dcff104c9d50a7f8b` | Disclosure evidence | Prior evidence inventory and sharing constraints |
| `docs/security/iam03c-trust04j-reviewer-engagement-and-assessment-sow.md` | 8548 | `24b8e0ccb1c42e300a768cfde461b2172e8a175a33b1a4b87c0be9f21199ac46` | Review requirements | Prior engagement and assessment scope |
| `docs/security/iam03c-trust04j-owner-actions-and-review-decision-tracker.md` | 8216 | `5c6b9e24b592e3524c58528df5599b1e684e8cb964590f2c524eba69ed0b9b53` | Decision evidence | Reviewer appointment, disclosure, and owner decision status |

## E. Internal verification results

The current prototype record (`test-results.md`) reports the last completed run as `cargo test --offline --locked`, Rust 1.100.0 / Cargo 1.100.0, with 9 passed and 0 failed Rust tests. It records:

- RFC 8032: 3/3 pass.
- Wycheproof: 210/210 pass; the hardened harness checks all IDs are unique and exactly `1..=210`.
- Identity-A regression: pass, including rejection of tcId 152 under the stricter project profile.
- Identity-R: point validation permits identity; a deterministic synthetic positive signature passes the full verifier; negative identity-R cases are rejected.
- A/R/S boundary tests and equation-negative tests: recorded as passing in the prototype results.

The provenance report records the official RFC 8032 Section 7.1 fields matching the three local RFC vectors, the pinned C2SP corpus matching local JSON byte-for-byte, source SHA-256/Git blob identity matching the manifest, all 210 corpus IDs/verdicts accounted for, and both local TSVs reproducing byte-for-byte. The source corpus verdicts remain distinct from project expectations. tcId 152 has upstream verdict `acceptable` and `SmallOrderPublicKey`; the project profile expects rejection. `PUBLISHER_SIGNATURE: NOT_VERIFIED` remains an assurance limitation and is not evidence that the source is compromised.

These results are taken from existing records and were not rerun for this handoff. The earlier TRUST-04J handoff predates the later prototype and provenance work; use the newer prototype result and provenance files for current internal status. Neither replaces external review.

## F. Reviewer questions

1. Are the canonical encoding, curve membership, subgroup membership, and identity checks for A and R correct and sufficient?
2. Does the selected ordinary Ed25519 verification path enforce the intended pure, non-cofactored verification equation without unintended normalization or alternate acceptance behavior?
3. Is accepting identity R while rejecting identity A cryptographically coherent and appropriate for the intended root-policy signature profile?
4. Are the selected dependencies, enabled features, implementation boundaries, and failure behavior suitable for a security-sensitive verifier?
5. Do the RFC, Wycheproof, synthetic identity-R, negative, and boundary tests provide adequate assurance? What additional cases or formal analysis are required?

Please identify weaknesses even where existing tests pass. Findings should cite exact source lines, dependency versions/features, mathematical assumptions, and reproducible evidence. Distinguish confirmed defects from hypotheses and unverified assumptions.

## G. Reviewer deliverables

Request a written assessment containing:

- Review methodology, reviewed artifacts and exact versions, and explicit scope limitations.
- Findings with severity, affected code/specification, and reproducible evidence.
- Mathematical and cryptographic correctness assessment of A/R/S and the verification equation.
- Dependency, feature, source-to-binary, failure-handling, and implementation-composition assessment.
- Test and provenance coverage assessment, including recommended additional vectors or analysis.
- Recommended corrective actions and evidence required to close them.
- Explicit conclusion whether the isolated primitive is suitable for further controlled TEST development, with any conditions.
- Reviewer identity, qualifications, independence/conflict declaration, date, and authenticated decision record.

Permitted reviewer outcomes in the existing record are `APPROVED_FOR_TEST_PROTOTYPE`, `APPROVED_WITH_CONDITIONS`, `MORE_EVIDENCE_REQUIRED`, or `REJECTED`. Any such outcome is not production approval or owner authorization.

## H. Open limitations and decisions

- Wycheproof publisher signature authenticity is **not verified**. Content identity is reproducible; this limitation alone does not imply compromise.
- No independent cryptographic reviewer is appointed; no signed independent assessment exists.
- D04F-01 through D04F-06 remain **PROPOSED — NOT APPROVED**.
- No production implementation authorization exists.
- No complete application ROOT_POLICY verifier or quorum evaluator is implemented in this prototype.
- No completed operational IAM verifier or operational integration exists.
- No production root enrollment, database schema implementation, or deployment is authorized.
- Owner disclosure approval, reviewer appointment, confidentiality/engagement approval, and transmission approval are pending. This document does not authorize sharing.

## I. Handoff status

**Package readiness:** prepared for owner review and possible controlled disclosure.
**External sharing:** pending owner approval of recipient, confidentiality terms, and exact file allowlist.
**Independent review:** not performed; reviewer not appointed.
**Security sign-off / production readiness:** not established. G1 remains BLOCKED; TRUST-05 and operational IAM remain NO-GO.
