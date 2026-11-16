# TRUST-04E corrective test and vector plan

2026-11-16. Documentation-only TRUST-04E. No cryptographic execution, hashing, signing, installation or profile amendment. All proposed decisions are unapproved.

## Existing coverage and future-only rules

[Evidence reconstruction](iam03c-trust04e-case152-evidence-reconstruction.md) confirms
the stop; no remaining case was run here. Every future test needs separate scope,
pinned reviewed environment and offline execution. Native corpus verdicts remain
unchanged; actual library result and strict-boundary result must be separate columns.

Remaining 58: tcId 153–159 (seven acceptable SmallOrderPublicKey), 160–180 (21
acceptable MixedOrderPublicKey), 181–209 (29 valid), 210 (one invalid mixed-order).
Reject all forbidden A classes under the profile even when native verdict is
acceptable. Valid labels require review for full profile admissibility, not blind
promotion. The table below enumerates every unexecuted source ID. G1-S means strict
conformance; G1-V means positive/vector compatibility. Existing result is absent for
all rows; future test means exact source bytes through both backend and candidate
boundary, comparing original and strict expectations.

| Case ID | Security objective / source flag | Existing evidence / coverage | Required strict behavior | Gap / future test | Gate |
| --- | --- | --- | --- | --- | --- |
| tcId 153 | SmallOrderPublicKey; native acceptable | Metadata only / NOT_EXECUTED | REJECT forbidden A | No result; exact-input comparison and independent predicate review | G1-S |
| tcId 154 | SmallOrderPublicKey; native acceptable | Metadata only / NOT_EXECUTED | REJECT forbidden A | No result; exact-input comparison and independent predicate review | G1-S |
| tcId 155 | SmallOrderPublicKey; native acceptable | Metadata only / NOT_EXECUTED | REJECT forbidden A | No result; exact-input comparison and independent predicate review | G1-S |
| tcId 156 | SmallOrderPublicKey; native acceptable | Metadata only / NOT_EXECUTED | REJECT forbidden A | No result; exact-input comparison and independent predicate review | G1-S |
| tcId 157 | SmallOrderPublicKey; native acceptable | Metadata only / NOT_EXECUTED | REJECT forbidden A | No result; exact-input comparison and independent predicate review | G1-S |
| tcId 158 | SmallOrderPublicKey; native acceptable | Metadata only / NOT_EXECUTED | REJECT forbidden A | No result; exact-input comparison and independent predicate review | G1-S |
| tcId 159 | SmallOrderPublicKey; native acceptable | Metadata only / NOT_EXECUTED | REJECT forbidden A | No result; exact-input comparison and independent predicate review | G1-S |
| tcId 160 | MixedOrderPublicKey; native acceptable | Metadata only / NOT_EXECUTED | REJECT forbidden A | No result; exact-input comparison and independent predicate review | G1-S |
| tcId 161 | MixedOrderPublicKey; native acceptable | Metadata only / NOT_EXECUTED | REJECT forbidden A | No result; exact-input comparison and independent predicate review | G1-S |
| tcId 162 | MixedOrderPublicKey; native acceptable | Metadata only / NOT_EXECUTED | REJECT forbidden A | No result; exact-input comparison and independent predicate review | G1-S |
| tcId 163 | MixedOrderPublicKey; native acceptable | Metadata only / NOT_EXECUTED | REJECT forbidden A | No result; exact-input comparison and independent predicate review | G1-S |
| tcId 164 | MixedOrderPublicKey; native acceptable | Metadata only / NOT_EXECUTED | REJECT forbidden A | No result; exact-input comparison and independent predicate review | G1-S |
| tcId 165 | MixedOrderPublicKey; native acceptable | Metadata only / NOT_EXECUTED | REJECT forbidden A | No result; exact-input comparison and independent predicate review | G1-S |
| tcId 166 | MixedOrderPublicKey; native acceptable | Metadata only / NOT_EXECUTED | REJECT forbidden A | No result; exact-input comparison and independent predicate review | G1-S |
| tcId 167 | MixedOrderPublicKey; native acceptable | Metadata only / NOT_EXECUTED | REJECT forbidden A | No result; exact-input comparison and independent predicate review | G1-S |
| tcId 168 | MixedOrderPublicKey; native acceptable | Metadata only / NOT_EXECUTED | REJECT forbidden A | No result; exact-input comparison and independent predicate review | G1-S |
| tcId 169 | MixedOrderPublicKey; native acceptable | Metadata only / NOT_EXECUTED | REJECT forbidden A | No result; exact-input comparison and independent predicate review | G1-S |
| tcId 170 | MixedOrderPublicKey; native acceptable | Metadata only / NOT_EXECUTED | REJECT forbidden A | No result; exact-input comparison and independent predicate review | G1-S |
| tcId 171 | MixedOrderPublicKey; native acceptable | Metadata only / NOT_EXECUTED | REJECT forbidden A | No result; exact-input comparison and independent predicate review | G1-S |
| tcId 172 | MixedOrderPublicKey; native acceptable | Metadata only / NOT_EXECUTED | REJECT forbidden A | No result; exact-input comparison and independent predicate review | G1-S |
| tcId 173 | MixedOrderPublicKey; native acceptable | Metadata only / NOT_EXECUTED | REJECT forbidden A | No result; exact-input comparison and independent predicate review | G1-S |
| tcId 174 | MixedOrderPublicKey; native acceptable | Metadata only / NOT_EXECUTED | REJECT forbidden A | No result; exact-input comparison and independent predicate review | G1-S |
| tcId 175 | MixedOrderPublicKey; native acceptable | Metadata only / NOT_EXECUTED | REJECT forbidden A | No result; exact-input comparison and independent predicate review | G1-S |
| tcId 176 | MixedOrderPublicKey; native acceptable | Metadata only / NOT_EXECUTED | REJECT forbidden A | No result; exact-input comparison and independent predicate review | G1-S |
| tcId 177 | MixedOrderPublicKey; native acceptable | Metadata only / NOT_EXECUTED | REJECT forbidden A | No result; exact-input comparison and independent predicate review | G1-S |
| tcId 178 | MixedOrderPublicKey; native acceptable | Metadata only / NOT_EXECUTED | REJECT forbidden A | No result; exact-input comparison and independent predicate review | G1-S |
| tcId 179 | MixedOrderPublicKey; native acceptable | Metadata only / NOT_EXECUTED | REJECT forbidden A | No result; exact-input comparison and independent predicate review | G1-S |
| tcId 180 | MixedOrderPublicKey; native acceptable | Metadata only / NOT_EXECUTED | REJECT forbidden A | No result; exact-input comparison and independent predicate review | G1-S |
| tcId 181 | Valid; native valid | Metadata only / NOT_EXECUTED | ACCEPT if independently profile-admissible | No result; exact-input comparison and independent predicate review | G1-V |
| tcId 182 | Valid; native valid | Metadata only / NOT_EXECUTED | ACCEPT if independently profile-admissible | No result; exact-input comparison and independent predicate review | G1-V |
| tcId 183 | Valid; native valid | Metadata only / NOT_EXECUTED | ACCEPT if independently profile-admissible | No result; exact-input comparison and independent predicate review | G1-V |
| tcId 184 | Valid; native valid | Metadata only / NOT_EXECUTED | ACCEPT if independently profile-admissible | No result; exact-input comparison and independent predicate review | G1-V |
| tcId 185 | Valid; native valid | Metadata only / NOT_EXECUTED | ACCEPT if independently profile-admissible | No result; exact-input comparison and independent predicate review | G1-V |
| tcId 186 | Valid; native valid | Metadata only / NOT_EXECUTED | ACCEPT if independently profile-admissible | No result; exact-input comparison and independent predicate review | G1-V |
| tcId 187 | Valid; native valid | Metadata only / NOT_EXECUTED | ACCEPT if independently profile-admissible | No result; exact-input comparison and independent predicate review | G1-V |
| tcId 188 | Valid; native valid | Metadata only / NOT_EXECUTED | ACCEPT if independently profile-admissible | No result; exact-input comparison and independent predicate review | G1-V |
| tcId 189 | Valid; native valid | Metadata only / NOT_EXECUTED | ACCEPT if independently profile-admissible | No result; exact-input comparison and independent predicate review | G1-V |
| tcId 190 | Valid; native valid | Metadata only / NOT_EXECUTED | ACCEPT if independently profile-admissible | No result; exact-input comparison and independent predicate review | G1-V |
| tcId 191 | Valid; native valid | Metadata only / NOT_EXECUTED | ACCEPT if independently profile-admissible | No result; exact-input comparison and independent predicate review | G1-V |
| tcId 192 | Valid; native valid | Metadata only / NOT_EXECUTED | ACCEPT if independently profile-admissible | No result; exact-input comparison and independent predicate review | G1-V |
| tcId 193 | Valid; native valid | Metadata only / NOT_EXECUTED | ACCEPT if independently profile-admissible | No result; exact-input comparison and independent predicate review | G1-V |
| tcId 194 | Valid; native valid | Metadata only / NOT_EXECUTED | ACCEPT if independently profile-admissible | No result; exact-input comparison and independent predicate review | G1-V |
| tcId 195 | Valid; native valid | Metadata only / NOT_EXECUTED | ACCEPT if independently profile-admissible | No result; exact-input comparison and independent predicate review | G1-V |
| tcId 196 | Valid; native valid | Metadata only / NOT_EXECUTED | ACCEPT if independently profile-admissible | No result; exact-input comparison and independent predicate review | G1-V |
| tcId 197 | Valid; native valid | Metadata only / NOT_EXECUTED | ACCEPT if independently profile-admissible | No result; exact-input comparison and independent predicate review | G1-V |
| tcId 198 | Valid; native valid | Metadata only / NOT_EXECUTED | ACCEPT if independently profile-admissible | No result; exact-input comparison and independent predicate review | G1-V |
| tcId 199 | Valid; native valid | Metadata only / NOT_EXECUTED | ACCEPT if independently profile-admissible | No result; exact-input comparison and independent predicate review | G1-V |
| tcId 200 | Valid; native valid | Metadata only / NOT_EXECUTED | ACCEPT if independently profile-admissible | No result; exact-input comparison and independent predicate review | G1-V |
| tcId 201 | Valid; native valid | Metadata only / NOT_EXECUTED | ACCEPT if independently profile-admissible | No result; exact-input comparison and independent predicate review | G1-V |
| tcId 202 | Valid; native valid | Metadata only / NOT_EXECUTED | ACCEPT if independently profile-admissible | No result; exact-input comparison and independent predicate review | G1-V |
| tcId 203 | Valid; native valid | Metadata only / NOT_EXECUTED | ACCEPT if independently profile-admissible | No result; exact-input comparison and independent predicate review | G1-V |
| tcId 204 | Valid; native valid | Metadata only / NOT_EXECUTED | ACCEPT if independently profile-admissible | No result; exact-input comparison and independent predicate review | G1-V |
| tcId 205 | Valid; native valid | Metadata only / NOT_EXECUTED | ACCEPT if independently profile-admissible | No result; exact-input comparison and independent predicate review | G1-V |
| tcId 206 | Valid; native valid | Metadata only / NOT_EXECUTED | ACCEPT if independently profile-admissible | No result; exact-input comparison and independent predicate review | G1-V |
| tcId 207 | Valid; native valid | Metadata only / NOT_EXECUTED | ACCEPT if independently profile-admissible | No result; exact-input comparison and independent predicate review | G1-V |
| tcId 208 | Valid; native valid | Metadata only / NOT_EXECUTED | ACCEPT if independently profile-admissible | No result; exact-input comparison and independent predicate review | G1-V |
| tcId 209 | Valid; native valid | Metadata only / NOT_EXECUTED | ACCEPT if independently profile-admissible | No result; exact-input comparison and independent predicate review | G1-V |
| tcId 210 | MixedOrderPublicKey; native invalid | Metadata only / NOT_EXECUTED | REJECT forbidden A | No result; exact-input comparison and independent predicate review | G1-S |

## All 26 project cases

Source objectives and results are preserved from the [frozen matrix](iam03c-trust04-vector-and-error-matrix.md).
All complete project fixtures remain NOT_READY. G1-W=wire, G1-P=policy,
G1-S=strict math, G1-I=isolation, G1-V=independent oracle.

| Case ID | Security objective | Existing evidence / coverage | Required strict behavior | Gap / proposed future test | Gate |
| --- | --- | --- | --- | --- | --- |
| V04-01 | RFC 8032 positive message/key/signatures | 3 RFC positives PASS; project frame NOT_EXECUTED | Exact published algorithm success, separate from project frame acceptance | Missing approved literal assets/review; execute exact frozen mutation with stage/call counters after authorization | G1-S/G1-V |
| V04-02 | Frozen canonical body, key-set, manifest and full frame | Specification only / NOT_EXECUTED | Exact independently pinned bytes, byte counts and all five digest boundaries; no self-reference | Missing approved literal assets/review; execute exact frozen mutation with stage/call counters after authorization | G1-W/G1-V |
| V04-03 | Two distinct eligible TEST customer signatures | Specification only / NOT_EXECUTED | SignatureEvidence with exactly two sorted signer pairs, non-operational fixed status; one source read/two crypto checks | Missing approved literal assets/review; execute exact frozen mutation with stage/call counters after authorization | G1-P/G1-I |
| V04-04 | Three valid entries, all six input permutations | Specification only / NOT_EXECUTED | Same frame digest and three sorted pairs; three crypto checks; no third ignored | Missing approved literal assets/review; execute exact frozen mutation with stage/call counters after authorization | G1-P/G1-I |
| V04-05 | Zero/one otherwise eligible signature | Specification only / NOT_EXECUTED | QUORUM_INSUFFICIENT, zero crypto; one-unknown or revoked variants follow earlier codes | Missing approved literal assets/review; execute exact frozen mutation with stage/call counters after authorization | G1-P/G1-I |
| V04-06 | Flip one bit of otherwise well-shaped signature | Specification only / NOT_EXECUTED | SIGNATURE_INVALID, zero evidence; fixed sorted check order | Missing approved literal assets/review; execute exact frozen mutation with stage/call counters after authorization | G1-S/G1-V |
| V04-07 | Duplicate custodian/key entries; manifest duplicate key/material; source duplicate map | Specification only / NOT_EXECUTED | Candidate SIGNER_DUPLICATE before lookup; malformed independent source ANCHOR_UNAVAILABLE after one attempted read | Missing approved literal assets/review; execute exact frozen mutation with stage/call counters after authorization | G1-P/G1-I |
| V04-08 | Well-typed wrong tenant in expected versus proof; nested payload/manifest mismatch | Specification only / NOT_EXECUTED | BINDING_MISMATCH, zero lookup/crypto; no foreign IDs in diagnostic | Missing approved literal assets/review; execute exact frozen mutation with stage/call counters after authorization | G1-P/G1-I |
| V04-09 | Wrong deployment UUID/kind/customer/domain with otherwise valid bytes | Specification only / NOT_EXECUTED | BINDING_MISMATCH; same identifiers do not erase enterprise/SaaS boundary | Missing approved literal assets/review; execute exact frozen mutation with stage/call counters after authorization | G1-P/G1-I |
| V04-10 | Wrong environment UUID; environment_kind=PRODUCTION | Specification only / NOT_EXECUTED | UUID mismatch BINDING_MISMATCH; otherwise valid PRODUCTION input DOMAIN_MISMATCH, no production lookup | Missing approved literal assets/review; execute exact frozen mutation with stage/call counters after authorization | G1-P/G1-I |
| V04-11 | Ed25519ph/ctx/P-256 or mixed signature profiles | Specification only / NOT_EXECUTED | ALGORITHM_UNSUPPORTED after earlier shape/domain/canonical checks; no fallback | Missing approved literal assets/review; execute exact frozen mutation with stage/call counters after authorization | G1-W/G1-V |
| V04-12 | Whitespace, escaped alias, unsorted object/set, time/UUID spelling alias; bool/float/exponent counter | Specification only / NOT_EXECUTED | CANONICAL_MISMATCH for typed aliases; STRUCTURE_INVALID for bad primitive type; duplicate keys STRUCTURE_INVALID | Missing approved literal assets/review; execute exact frozen mutation with stage/call counters after authorization | G1-W/G1-V |
| V04-13 | Unknown field in body/manifest/context/signature, including trusted flag or key URL | Specification only / NOT_EXECUTED | STRUCTURE_INVALID before lookup, no ignored extension | Missing approved literal assets/review; execute exact frozen mutation with stage/call counters after authorization | G1-W/G1-V |
| V04-14 | Wrong computed root-set/manifest/payload digest, internally consistent outer claims | Specification only / NOT_EXECUTED | CANONICAL_MISMATCH; separately coherent different pinned manifest/set POLICY_STALE | Missing approved literal assets/review; execute exact frozen mutation with stage/call counters after authorization | G1-W/G1-V |
| V04-15 | Two valid plus invalid third signature | Specification only / NOT_EXECUTED | SIGNATURE_INVALID, no partial evidence; include each failing sorted position | Missing approved literal assets/review; execute exact frozen mutation with stage/call counters after authorization | G1-S/G1-V |
| V04-16 | Unknown custodian/key pair, wrong key signature under known pair | Specification only / NOT_EXECUTED | SIGNER_UNKNOWN before crypto; known pair with signature from other key SIGNATURE_INVALID | Missing approved literal assets/review; execute exact frozen mutation with stage/call counters after authorization | G1-S/G1-V |
| V04-17 | Revoked root/key, expired source/body/key, or future test_time | Specification only / NOT_EXECUTED | KEY_REVOKED before TIME_INVALID/threshold; no history-to-current claim | Missing approved literal assets/review; execute exact frozen mutation with stage/call counters after authorization | G1-P/G1-I |
| V04-18 | Missing, self-selected, corrupt or non-TEST anchor source/pin | Specification only / NOT_EXECUTED | ANCHOR_UNAVAILABLE; missing authenticated production source never synthesized | Missing approved literal assets/review; execute exact frozen mutation with stage/call counters after authorization | G1-P/G1-I |
| V04-19 | Older/newer policy/version/generation, wrong independent pin reference | Specification only / NOT_EXECUTED | POLICY_STALE; neither old nor unapproved next can self-activate | Missing approved literal assets/review; execute exact frozen mutation with stage/call counters after authorization | G1-P/G1-I |
| V04-20 | Synthetic IAM provenance or production request classification | Specification only / NOT_EXECUTED | SYNTHETIC_SOURCE; protected fixture channel distinction, zero operational imports | Missing approved literal assets/review; execute exact frozen mutation with stage/call counters after authorization | G1-P/G1-I |
| V04-21 | Malformed/noncanonical point/scalar, torsion/mixed-order keys, scalar >= L, corpus edge vectors | 152 corpus cases executed; identity mismatch; rest NOT_EXECUTED | Frozen strict acceptance; no library-specific permissive success. Length/hex shape STRUCTURE_INVALID; mathematical invalidity SIGNATURE_INVALID; unusable fixture pin blocks registration | Missing approved literal assets/review; execute exact frozen mutation with stage/call counters after authorization | G1-S/G1-V |
| V04-22 | Wrong label/NUL/length/purpose/trailing bytes; future purpose | Specification only / NOT_EXECUTED | DOMAIN_MISMATCH once bounded readable; cap+1 declared length LIMIT_EXCEEDED | Missing approved literal assets/review; execute exact frozen mutation with stage/call counters after authorization | G1-W/G1-V |
| V04-23 | Body/payload/frame/combined/depth/entry limit cap and cap+1 | Specification only / NOT_EXECUTED | At cap proceed to ordinary validation, not necessarily success; cap+1 LIMIT_EXCEEDED before expensive work, per budget definition | Missing approved literal assets/review; execute exact frozen mutation with stage/call counters after authorization | G1-W/G1-V |
| V04-24 | Multi-fault fixtures from section 2 and permutations | Specification only / NOT_EXECUTED | Exact earliest code, source-read/crypto-call counters; no raw input or inventory | Missing approved literal assets/review; execute exact frozen mutation with stage/call counters after authorization | G1-W/G1-V |
| V04-25 | SaaS provider-recovery custodian/delegation or platform key as signer | Specification only / NOT_EXECUTED | Unsupported domain -> DOMAIN_MISMATCH; ordinary unknown platform signer -> SIGNER_UNKNOWN; no provider authority | Missing approved literal assets/review; execute exact frozen mutation with stage/call counters after authorization | G1-P/G1-I |
| V04-26 | Erroring backend/source or mutated result object/caller success flag | Specification only / NOT_EXECUTED | Fixed rejection; no exception text, no returned partial evidence, immutable TEST output and no IAM consumer | Missing approved literal assets/review; execute exact frozen mutation with stage/call counters after authorization | G1-P/G1-I |

## Corrective stages and acceptance criteria — not authorization

1. Independent security reviewer specifies A/R/scalar/equation predicate coverage
   against frozen section 4, including R identity exception. Review any native API
   composition and exact dependency/binding source; no custom curve arithmetic.
   PASS: every requirement mapped to vetted enforcing code and an independent oracle.
   FAIL/STOP: undocumented behavior, blacklist-only proposal, or changed acceptance.
2. Separately authorize disposable TEST-only harness changes and pinned dependencies.
   First reproduce exact case 152 backend result and demonstrate candidate-boundary
   rejection. Preserve original acceptable and backend ACCEPT in separate records.
   PASS: strict rejection with no evidence or partial vote; original RFC positives pass.
3. Cover other small-order and mixed-order A, canonical/noncanonical y/sign encodings,
   invalid curve points, malformed lengths, canonical S<L and boundary scalars, invalid
   signatures, R torsion/mixed order and permitted identity R with an independently
   sourced equation-valid fixture. Test exact frames and wrong-mode/domain negatives.
   PASS: exact frozen acceptance, no fallback; FAIL: either forbidden acceptance or
   rejection of an explicitly permitted, otherwise-valid input.
4. Only after the first incompatibility is resolved, authorize full 210-case run.
   For each native acceptable case, document profile predicates and review. Add a
   maintained independent implementation comparison; disagreements STOP the gate,
   not automatic majority vote. Preserve all 210 source IDs/bytes/verdicts. PASS:
   all strict expectations satisfied, any conditional policies resolved and reviewed.
5. Authorize isolated application-boundary tests later: rejected anchor registration,
   unknown/revoked keys, duplicates, invalid third signature, insufficient quorum,
   tenant/deployment/environment confusion and fixed fifteen-code precedence.
   No production admission/provider imports or operational evidence may result.
6. Resume project goldens only after approved strict boundary and explicit scope.
   Independently derive canonical bytes, frame, digests and TEST signatures outside
   future verifier; require second reviewer/implementation, literal outputs and pins.
   No single library-generated success oracle. All V04-01–26 must have exact assets,
   expected result, independent derivation record, review and reproducible command.

A narrow initial reproduction may stop on forbidden acceptance. A later complete
comparison run requires explicit permission to collect all discrepancies safely;
otherwise existing stop rules remain. Tests run offline with no databases/services,
production keys, persistent roots or IAM integration. Do not reuse expired approvals
as authorization for new packages, corrective implementation or TRUST-05.

All 15 diagnostics remain at frozen stage order. Length/shape -> STRUCTURE_INVALID;
well-shaped forbidden A/R/S/equation -> SIGNATURE_INVALID at math stage. Invalid
independent anchor material also makes that source unusable/registration fail; source
failure maps ANCHOR_UNAVAILABLE under its stage. No new identity-specific public code
or cross-tenant key detail is proposed. Test counters and earlier-fault precedence.
