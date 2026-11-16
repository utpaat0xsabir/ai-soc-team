# TRUST-04 deterministic errors, future vectors and threat traceability

2026-11-16. **PROPOSED FREEZE. No crypto executed or vectors generated.**
Normative companions: [wire](iam03c-trust04-root-policy-wire-spec.md),
[anchor/verifier](iam03c-trust04-anchor-and-verifier-contract.md),
[G1 review](iam03c-trust04-g1-readiness-review.md).

## 1. Fixed observable-stage order

The first failing stage returns one SignatureRejection code and **no evidence**.
Validate schema fields in the defined schema order, not incoming member order.
For a well-formed stage, gather its applicable failures and choose the listed code;
do not depend on exception text, signature arrival order or library iteration order.
Do not inspect later stages to override an earlier failure. Source/crypto exceptions
never escape as raw text. Actual exceptions in a selected crypto API return
SIGNATURE_INVALID; source exceptions return ANCHOR_UNAVAILABLE.

A hard limit is checked as soon as its extent is observable: raw bytes before parse,
length/count before decode/entry validation, bounded depth during tokenization, and
snapshot/combined length when the source returns. An earlier malformed prefix may
make later limits unobservable. This exception is deterministic parser progress,
not permission to parse unbounded input to find a higher-priority code.

| Order / stage | Code | Trigger | Anchor lookup? | Crypto attempted? | Cross-tenant information |
| --- | --- | --- | --- | --- | --- |
| 00 budget guard, repeated at each decode/source boundary | LIMIT_EXCEEDED | Observable raw/declared/decoded/combined/depth/entry cap+1 | No before source stage; one if discovered in returned snapshot | Never after limit discovered | Counts only; do not expose inventory |
| 01 protected input-class gate | SYNTHETIC_SOURCE | Harness input_classification is not TEST_WIRE_FIXTURE; no synthetic IAM object conversion or production request | No | No | None |
| 02 bounded parse / closed shape | STRUCTURE_INVALID | Wrong runtime type, invalid/duplicate JSON keys, missing/extra fields, bad field grammar, numeric coercion, impossible interval or malformed 32/64-byte representation | No | No | None |
| 03 typed context / internal bindings | BINDING_MISMATCH | Binding/environment UUID/operation or inner/outer policy/reference/digest claims contradict expected context or one another | No | No | None; do not list expected foreign IDs |
| 04 candidate duplicate preflight | SIGNER_DUPLICATE | Repeated candidate custodian/key/anchor/material identities or signature custodian/key entries; never deduplicate | No | No | Only malformed candidate, not source inventory |
| 05 byte/digest canonical checks | CANONICAL_MISMATCH | Byte alias/order/whitespace/encoding/profile ID, inconsistent payload/public-material/root-set/manifest digest derivation | No | No | None |
| 06 domain / test-subset gate | DOMAIN_MISMATCH | Wrong label/protocol/purpose/payload type/profile_id/TEST kind, provider-recovery custodian, future purpose, bad/trailing/truncated within-cap framing | No | No | None |
| 07 algorithm gate | ALGORITHM_UNSUPPORTED | Any body/manifest/signature entry uses another well-typed algorithm/profile/encoding, mixed profiles or variants | No | No | None |
| 08 independent source | ANCHOR_UNAVAILABLE | No registered TEST source/snapshot, exception, malformed/inconsistent source, unknown fixture or non-TEST provenance | At most one attempted | No | Same fixed code for absence/source error; no key list |
| 09 independent policy/pin comparison | POLICY_STALE | Candidate policy/version/generation/root-set/full manifest/full inner payload pin differs, or pin reference not approved; newer unapproved also rejects | One | No | No expected version/key inventory returned |
| 10 independent signer mapping | SIGNER_UNKNOWN | Candidate signature custodian/key pair absent from exact approved TEST map | One | No | Fixed code only, no alternative key suggestions |
| 11 revocation eligibility | KEY_REVOKED | Current root or any supplied key/custodian revoked by signed manifest or stricter snapshot observation | One | No | Fixed code only; prior tenant guard prevents foreign lookup |
| 12 explicit test-time eligibility | TIME_INVALID | Body, source observation or any supplied-key window not valid/covering at explicit test_time | One | No | No detailed source timestamps returned |
| 13 threshold precheck | QUORUM_INSUFFICIENT | Fewer than two distinct eligible supplied entries | One | No | No hint about missing custodian names |
| 14 strict mathematical verification | SIGNATURE_INVALID | Well-shaped selected key/point/scalar/signature or exact-frame equation fails strict profile; backend/API failure | One | Yes, up to three, sorted custodian order; stop on first failure | No raw library errors or failed key identity |

TIME_INVALID is the **one additional proposed diagnostic** beyond the requested
fourteen, to avoid labeling an unrevoked expired key as revoked or claiming a
historical signature is current. It is not added to existing TRUST-02 or IAM enums.
These are TEST diagnostics, not authorization denials or public HTTP responses.

Closed-schema/type preflight must not accidentally let Pydantic's aggregate validator
or constructor order decide the public code. Specifically, candidate duplicate
checks are staged after typed binding checks but before canonical/pin checks. Perform
leaf/field validation first, then fixed duplicate preflight, and only accept the
full unchanged RootTrustPolicy after its aggregate checks pass. Existing helpers
and denial enums remain unchanged; a future adapter maps failures into this new
ordered boundary. Unknown fields always reject before later semantic checks.

Binding precheck compares expected binding, environment_id and operation_id, plus
internal duplicated identity/ref/digest fields. Constant environment_kind and purpose
eligibility belong to the domain gate; algorithm constants belong to the algorithm
gate. Independent current-policy comparisons belong only after lookup. For UUID/digest/hex/time comparisons, use decoded typed values while preserving
original bytes for canonical rejection; a spelling alias alone must not become a
false binding mismatch. No normalization yields success. Test-only
customer kind eligibility is a domain check, not issuer authority. Noncanonical
syntactically valid aliases reject at 05; wrong primitive numeric type rejects at 02.
A duplicate escaped key rejects at 02 even though TRUST-02's separate parser reports
its own noncanonical diagnostic; no existing behavior is changed.

## 2. Conceptual multi-fault decisions — not executed tests

| Fault combination, assuming bounded readable input | Required first result / work |
| --- | --- |
| Raw cap+1 and unsupported profile | LIMIT_EXCEEDED before parse/lookup |
| Protected source is SYNTHETIC_IAM and body otherwise valid | SYNTHETIC_SOURCE; zero lookup/crypto |
| Unknown body field and wrong tenant | STRUCTURE_INVALID; no lookup |
| Well-typed wrong tenant plus duplicate signer, stale pin and invalid signature | BINDING_MISMATCH, independent of dictionary/signature order |
| Same candidate key twice plus canonical whitespace alias | SIGNER_DUPLICATE; no lookup |
| Canonical whitespace alias plus unsupported algorithm | CANONICAL_MISMATCH; no lookup |
| Future purpose plus unsupported algorithm | DOMAIN_MISMATCH; no lookup |
| Unsupported algorithm plus missing source | ALGORITHM_UNSUPPORTED; no lookup |
| Coherent wrong pinned policy plus unknown signer | POLICY_STALE; one source read, zero crypto |
| Unknown signer plus known revoked signer | SIGNER_UNKNOWN; do not leak which key is revoked |
| Revoked supplied signer plus expired interval or only one vote | KEY_REVOKED; zero crypto |
| One eligible signature with mathematically invalid bytes | QUORUM_INSUFFICIENT; math not attempted |
| Two valid plus third invalid | SIGNATURE_INVALID, no partial success |
| All three valid but source currentness unknown operationally | TEST SignatureEvidence only; never B7/current authority |

An unreadable/malformed frame cannot be searched for a tenant or purpose inside
arbitrary bytes. Incomplete framing uses the wire document's explicit extraction rules (short header, zero L or insufficient body -> early
DOMAIN_MISMATCH); readable wrong labels/NUL/trailing suffixes defer to stage 06; malformed transport types/hex use STRUCTURE_INVALID. Declared body length
over cap is LIMIT_EXCEEDED even if incomplete. These are explicit refinements of
TRUST-03 B1–B8 for the first TEST subset: duplicate and profile eligibility are
cheap early checks, B7 operational currency is not implemented at all, B8 yields
only TEST diagnostics. No IAM-03A or IAM-02 precedence changes.

## 3. Independent future vector assets

No seed, private key, signature, canonical body, frame digest or generated vector
asset is created by TRUST-04. This is a reproducible **future vector specification**,
not a claim those golden constants already exist. Exact expected body/frame/hash/
signature values must be materialized and independently reviewed before a future
verifier can pass its implementation acceptance gate.

Distinguish these two mandatory suites in every fixture/report:

- ALG-RFC8032: published RFC 8032 section 7.1 TEST 1, TEST 2, TEST 3 plus further
  selected positive vectors. Retain exact published public key/message/signature,
  vector ID, source bytes/version and license/provenance. Verify the published
  message directly; these messages are **not project signing frames**. Publicly
  published example secret seeds are non-production material and must not be
  copied into root configuration or reports. No new key generation is required.
- FRAME-ROOT-POLICY-1: project-specific TEST wire/body/manifest/key-set/frame vectors,
  using three separately named published test-key identities with provenance.
  Different IDs represent fixture signers, not proof of three real custodians.
  Future signature creation over these project frames needs separate explicit
  authorization, using published non-production vector material only, never new
  operational keys. Never pretend an RFC signature authenticates a different frame.

Published adversarial candidate: Wycheproof Ed25519 corpus, with exact release/
commit/file digest/license and upstream valid/invalid/acceptable labels recorded.
Source locations for later separately authorized acquisition:
[RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) and
[Wycheproof](https://github.com/C2SP/wycheproof). Not fetched or status-verified here.
Strict acceptance must be evaluated explicitly; do not blindly accept an upstream
"acceptable" vector. Cases for noncanonical S/points, torsion/mixed-order/small-order
keys and signature encodings must match the frozen profile, or implementation stops.

Each future FRAME fixture manifest must contain these exact entries (references
name separately retained public fixture files; not runnable examples here):

| Entry | Required independent expected asset |
| --- | --- |
| vector_id, suite_id, spec_revision | Stable fixture ID, FRAME-ROOT-POLICY-1, approved wire-document content digest |
| source_vector_ids, source_artifact_digests | Published key/vector provenance and independent review reference |
| expected_context_ref, anchor_snapshot_ref | Exact separate pre-registered TEST context/anchor fixture references |
| root_policy_bytes_hex | Full expected immutable TRUST02 bytes derived by a reviewed reference encoder, not the verifier under test |
| key_set_bytes_hex, manifest_without_digest_bytes_hex | Exact independently derived canonical projection/preimage bytes |
| expected_public_material_digests, expected_root_set_digest, expected_manifest_digest | SHA-256 expected values from those exact preimages, lowercase D constants |
| body_bytes_hex, expected_payload_sha256 | Full canonical body bytes and hash of exact inner policy bytes |
| frame_bytes_hex, expected_frame_sha256 | Exact label + 00 + U64BE(length) + body, and SHA-256 over that exact frame |
| signature_entries | Explicit expected published-key fixture mapping and separately generated project-frame signatures, never produced by the verifier |
| mutation_recipe, expected_code_or_result, expected_source_reads, expected_crypto_calls | Exact negative transformation and frozen stage/result/count assertions |
| independent_review_ref | Review of bytes/hash/signatures by a second implementation/person; not a self-generated success flag |

Independence procedure: first freeze human-reviewed symbolic fixture input and field
values; have a reference encoder isolated from the future verifier derive complete
literal bytes; independently reconstruct field order/framing/length using a second
reviewed implementation and calculate all SHA-256 expected constants with a separate
standard tool. Compare byte-for-byte and pin the resulting literals. Use a different
reviewed Ed25519 implementation to create/check project signatures under the explicit
future test-material authorization. Do not call the verifier's canonicalizer/hash/
verification code to generate its own expected results. Provenance and matching
tools/versions are recorded without private inputs. No such execution occurs now.

Changing the spec invalidates the golden revision pin and requires independent
regeneration/review; do not silently recompute expected fixtures in tests. An absent
golden constant is an unmet acceptance requirement, not a placeholder accepted by
code. Pin both positive and negative outcomes, including exact side-effect counters.

## 4. Future ROOT_POLICY vector matrix — all SPECIFIED, NOT EXECUTED

V04 cases refine the matching TRUST-03 K cases; none authorizes test execution.

| Case | Fixture / transformation | Required result and independent evidence | Trace |
| --- | --- | --- | --- |
| V04-01 | RFC 8032 positive message/key/signatures | Exact published algorithm success, separate from project frame acceptance | K01/K35 |
| V04-02 | Frozen canonical body, key-set, manifest and full frame | Exact independently pinned bytes, byte counts and all five digest boundaries; no self-reference | K10/K35 |
| V04-03 | Two distinct eligible TEST customer signatures | SignatureEvidence with exactly two sorted signer pairs, non-operational fixed status; one source read/two crypto checks | K01 |
| V04-04 | Three valid entries, all six input permutations | Same frame digest and three sorted pairs; three crypto checks; no third ignored | K01/K06 |
| V04-05 | Zero/one otherwise eligible signature | QUORUM_INSUFFICIENT, zero crypto; one-unknown or revoked variants follow earlier codes | K07 |
| V04-06 | Flip one bit of otherwise well-shaped signature | SIGNATURE_INVALID, zero evidence; fixed sorted check order | K02 |
| V04-07 | Duplicate custodian/key entries; manifest duplicate key/material; source duplicate map | Candidate SIGNER_DUPLICATE before lookup; malformed independent source ANCHOR_UNAVAILABLE after one attempted read | K06 |
| V04-08 | Well-typed wrong tenant in expected versus proof; nested payload/manifest mismatch | BINDING_MISMATCH, zero lookup/crypto; no foreign IDs in diagnostic | K04 |
| V04-09 | Wrong deployment UUID/kind/customer/domain with otherwise valid bytes | BINDING_MISMATCH; same identifiers do not erase enterprise/SaaS boundary | K05 |
| V04-10 | Wrong environment UUID; environment_kind=PRODUCTION | UUID mismatch BINDING_MISMATCH; otherwise valid PRODUCTION input DOMAIN_MISMATCH, no production lookup | K05 |
| V04-11 | Ed25519ph/ctx/P-256 or mixed signature profiles | ALGORITHM_UNSUPPORTED after earlier shape/domain/canonical checks; no fallback | K14 |
| V04-12 | Whitespace, escaped alias, unsorted object/set, time/UUID spelling alias; bool/float/exponent counter | CANONICAL_MISMATCH for typed aliases; STRUCTURE_INVALID for bad primitive type; duplicate keys STRUCTURE_INVALID | K10 |
| V04-13 | Unknown field in body/manifest/context/signature, including trusted flag or key URL | STRUCTURE_INVALID before lookup, no ignored extension | K22 |
| V04-14 | Wrong computed root-set/manifest/payload digest, internally consistent outer claims | CANONICAL_MISMATCH; separately coherent different pinned manifest/set POLICY_STALE | K09/K11 |
| V04-15 | Two valid plus invalid third signature | SIGNATURE_INVALID, no partial evidence; include each failing sorted position | K02 |
| V04-16 | Unknown custodian/key pair, wrong key signature under known pair | SIGNER_UNKNOWN before crypto; known pair with signature from other key SIGNATURE_INVALID | K03 |
| V04-17 | Revoked root/key, expired source/body/key, or future test_time | KEY_REVOKED before TIME_INVALID/threshold; no history-to-current claim | K08/K24 |
| V04-18 | Missing, self-selected, corrupt or non-TEST anchor source/pin | ANCHOR_UNAVAILABLE; missing authenticated production source never synthesized | K16 |
| V04-19 | Older/newer policy/version/generation, wrong independent pin reference | POLICY_STALE; neither old nor unapproved next can self-activate | K09 |
| V04-20 | Synthetic IAM provenance or production request classification | SYNTHETIC_SOURCE; protected fixture channel distinction, zero operational imports | K15 |
| V04-21 | Malformed/noncanonical point/scalar, torsion/mixed-order keys, scalar >= L, corpus edge vectors | Frozen strict acceptance; no library-specific permissive success. Length/hex shape STRUCTURE_INVALID; mathematical invalidity SIGNATURE_INVALID; unusable fixture pin blocks registration | K02/K14/K35 |
| V04-22 | Wrong label/NUL/length/purpose/trailing bytes; future purpose | DOMAIN_MISMATCH once bounded readable; cap+1 declared length LIMIT_EXCEEDED | K14 |
| V04-23 | Body/payload/frame/combined/depth/entry limit cap and cap+1 | At cap proceed to ordinary validation, not necessarily success; cap+1 LIMIT_EXCEEDED before expensive work, per budget definition | K29 |
| V04-24 | Multi-fault fixtures from section 2 and permutations | Exact earliest code, source-read/crypto-call counters; no raw input or inventory | K29 |
| V04-25 | SaaS provider-recovery custodian/delegation or platform key as signer | Unsupported domain -> DOMAIN_MISMATCH; ordinary unknown platform signer -> SIGNER_UNKNOWN; no provider authority | K19 |
| V04-26 | Erroring backend/source or mutated result object/caller success flag | Fixed rejection; no exception text, no returned partial evidence, immutable TEST output and no IAM consumer | K15/K28 |

Cap fixtures must not introduce an accepted padding/metadata field. Some caps cannot
be attained by a semantically valid ROOT_POLICY object because narrower field limits
bind first. Use exact-length malformed inputs to exercise preparse gates: at cap a
later STRUCTURE_INVALID/CANONICAL_MISMATCH/DOMAIN_MISMATCH is expected; cap+1 is
LIMIT_EXCEEDED. For body cap use declared L and bounded body buffers; for decoded
payload use exact hex lengths; for combined budget use length-accounting boundary
fixtures before semantic validation. Snapshot/context caps remain checked on their
own inputs. Depth 16/17 and entries 3/4 are independent tests. Never weaken closed
schemas just to construct a positive maximal fixture.

## 5. All TRUST-03 threats mapped to this subset

A = addressed at the proposed offline byte/signature boundary; P = partially
addressed; S = requires independent storage/custody evidence; O = requires operational
IAM/DB enforcement; N = not applicable to this first purpose. Labels never claim
implementation or proof of mitigation. Threats refer to the existing
[TRUST-03 threat model](iam03c-trust03-threat-model.md).

| Threat | Classification / initial coverage | Residual / excluded claim | V04 coverage |
| --- | --- | --- | --- |
| T03-01 forged signatures | A, subject to approved strict library | Library/verifier compromise remains | 01–06, 15, 21 |
| T03-02 one stolen custodian key | P/S; two eligible votes required | Custody and incident revocation source are external | 03–07, 17 |
| T03-03 two colluding/coerced custodians | S; not prevented | Valid malicious quorum indistinguishable cryptographically | 03, 26; separate ceremony evidence |
| T03-04 duplicate counting | A/P | IDs/keys are distinct, not proof of distinct real people | 04, 07 |
| T03-05 stale root policy | P/S | Compare TEST pins only; no real latest-pin storage | 14, 19 |
| T03-06 revoked anchor | P/S/O | Reject supplied TEST revocation; no live propagation | 17–19 |
| T03-07 cross-tenant replay | A/P | Expected-context composition still trusted | 08, 24 |
| T03-08 cross-deployment replay | A/P | No migration, production enrollment or old-site fencing | 09, 10, 22 |
| T03-09 algorithm confusion | A | New algorithms unsupported; strict library compatibility still needed | 11, 21, 22 |
| T03-10 canonical mismatch | A | Cross-language vectors not yet materialized | 02, 12, 23 |
| T03-11 unknown signed fields | A | No permissive schema evolution | 13 |
| T03-12 DB rollback | O/N | No DB/current-state proof in ROOT_POLICY | None; retain K12/K21/K33 |
| T03-13 checkpoint rollback/fork | S/O/N | No checkpoint/high-water source consulted | None; retain K11/K30/K31 |
| T03-14 recovery journal tampering | S/O/N | No journal/recovery protocol | None; retain K13/K26/K33 |
| T03-15 lost keys | S/P | Insufficient votes reject; no recovery promise | 05; retain K18/K34 |
| T03-16 malicious recovery | N/S | Recovery purpose unsupported; compromised signing display still dangerous | 22; retain K17–K19/K27 |
| T03-17 SaaS operator escalation | P/S/O | No provider signer in subset; plaintext/runtime admin access not prevented | 09, 10, 25 |
| T03-18 verifier/display compromise | S/P | Same-host compromise can falsify local result; process separation not attestation | 26; retain K28 |
| T03-19 time manipulation | P/S | Explicit fixture time checked, authentic real clock not established | 17 |
| T03-20 partial revocation propagation | O/P | TEST observation cannot prove live freshness or final execution ordering | 17; retain K25/K30/K33 |

All project-specific signatures, golden bytes/digests, dependency compatibility and
future cases remain unexecuted and unapproved. Verification of documentation is
separate from accepting any cryptographic or operational claim.
