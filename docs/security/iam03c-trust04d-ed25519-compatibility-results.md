# TRUST-04D Ed25519 compatibility results

2026-11-16. **NOT_RUN — dependency resolution stopped before installation.**
[Runtime/blocker](iam03c-trust04d-runtime-and-dependency-evidence.md),
[golden gaps](iam03c-trust04d-independent-golden-review.md),
[G1 decision](iam03c-trust04d-g1-readiness-assessment.md).

## Actual execution boundary

Only runtime/OS metadata, namespace isolation preflight, environment creation and
initial official PyPI dependency metadata parsing ran. No Ed25519 public-key load,
signature verification, signing, private-key generation, application policy,
quorum evaluator or operational IAM import ran. No cryptographic test command was
executed. No test backend/OpenSSL version or duration is fabricated.

The stop was the unexpected active typing-extensions requirement absent from the
initial three-package candidate set, as required by the owner's dependency stop
condition. This is **not** evidence for or against the dependency's signature
security or the frozen ED25519-PURE-1 profile.

## Public corpus inventory, not test results

The original TRUST-04C assets and source verdicts remain unchanged:

| Suite | Original input records | Mathematical tests executed | Result |
| --- | --- | --- | --- |
| RFC 8032 section 7.1 TEST 1–3 | 3, source expected valid | 0 | NOT_RUN |
| Wycheproof source valid | 117 | 0 | NOT_RUN |
| Wycheproof source invalid | 64 | 0 | NOT_RUN |
| Wycheproof source acceptable | 29 | 0 | NOT_RUN |
| Total Wycheproof | 210 | 0 | NOT_RUN |

Public source checksum/provenance checks are distinct from signature conformance.
No acceptable case was converted to an unconditional local pass/fail and no original
verdict/encoding was rewritten. No PROFILE_COMPATIBLE/PROFILE_INCOMPATIBLE result
is asserted without execution. The entire behavioral comparison remains NOT_RUN;
review requirements and original subgroup-policy differences remain applicable.

## Frozen diagnostic coverage boundary

No application diagnostic engine is implemented. Table entries are planned scope,
not tests passed. Relevant original cases come from TRUST-04's unchanged matrix.

| Code | Required behavior / layer | Compatibility coverage now | Supporting cases / remaining gap |
| --- | --- | --- | --- |
| LIMIT_EXCEEDED | Bounded wrapper input/decode/count/depth guards | NOT_RUN; not a library feature | V04-23; future exact cap/counter fixtures |
| SYNTHETIC_SOURCE | Protected TEST source gate | NOT_RUN; wrapper only | V04-20; no operational imports |
| STRUCTURE_INVALID | Length/hex/type/unknown-field rejection | NOT_RUN; API length behavior also untested | V04-12/13/21; parser versus math distinction |
| BINDING_MISMATCH | Independent context/internal binding | NOT_RUN; wrapper only | V04-08/09/10; exact expected TEST context |
| SIGNER_DUPLICATE | Distinct custodian/key/material preflight | NOT_RUN; wrapper only | V04-07; never deduplicate into success |
| CANONICAL_MISMATCH | Exact bytes/digest/preimages | NOT_RUN; wrapper only | V04-02/12/14; independent goldens absent |
| DOMAIN_MISMATCH | Fixed purpose/frame/profile subset | NOT_RUN; wrong-message math test also untested | V04-10/22; no automatic purpose from signatures |
| ALGORITHM_UNSUPPORTED | Fixed pure profile, no fallback | NOT_RUN; wrapper owns identifiers | V04-11; actual ph/ctx negatives need independent assets |
| ANCHOR_UNAVAILABLE | Independently registered TEST source | NOT_RUN; wrapper only | V04-18; no self-signed bootstrap |
| POLICY_STALE | Exact independent policy/pin comparison | NOT_RUN; wrapper only | V04-19; current operational freshness excluded |
| SIGNER_UNKNOWN | Exact independently selected key pair | NOT_RUN; wrong-key math also untested | V04-16; no alternate-key search |
| KEY_REVOKED | Supplied TEST key/root eligibility | NOT_RUN; wrapper only | V04-17; library cannot fetch revocation state |
| TIME_INVALID | Explicit fixture time/windows | NOT_RUN; wrapper only | V04-17; no implicit clock |
| QUORUM_INSUFFICIENT | Fixed two eligible votes before math | NOT_RUN; wrapper only | V04-05; no operational permission |
| SIGNATURE_INVALID | Strict key/point/scalar/exact-message math | NOT_RUN; main future dependency test surface | V04-01/06/15/16/21; no backend conformance established |

Incorrect lengths/keys/signatures/messages/domains, scalar ranges, noncanonical/
invalid/small-order points and variant confusion all remain untested. No frozen
rule, canonical serializer or reason precedence is changed to bypass the block.

**RFC 8032 VECTORS: NOT_RUN**  
**WYCHEPROOF COMPATIBILITY: NOT_RUN**  
**STRICT ED25519 PROFILE: NOT_RUN**

## Authorized continuation and final assessment — 2026-11-16

This section supersedes the earlier dependency-stop status without erasing it.
The owner separately authorized TRUST-04D TEST execution, official PyPI binary-wheel
acquisition/offline installation, and required typing-extensions. No broader A01/A04
or TRUST-05 approval follows.

All three RFC 8032 vectors passed. Wycheproof ran in ascending tcId order and stopped
at case 152: 88 original valid cases accepted; 63 original invalid cases rejected;
one original acceptable case accepted. Remaining 58 cases were NOT_RUN_AFTER_STOP:
29 valid, one invalid, 28 acceptable. Original total: 117 valid, 64 invalid, 29 acceptable.

**Confirmed frozen-profile incompatibility:** tcId 152, SmallOrderPublicKey,
"identity public key universal forgery", was accepted with no exception.
The exact public inputs and native verdict are preserved in
[results.json](../../tests/iam/fixtures/trust04d_offline_validation/results.json).
Its public key is the canonical identity encoding (01 followed by 31 zero bytes).
The frozen [anchor contract](iam03c-trust04-anchor-and-verifier-contract.md) requires
A to be a nonidentity prime-order point. Acceptance therefore violates that restriction.
Wycheproof's original acceptable verdict is retained; this is not a claim that PyCA
fails Wycheproof's own acceptance policy or that every use of the library is unsafe.

Mandatory STOP was enforced immediately. No subsequent crypto operation, private-key
generation, signing, project digest derivation or broader strict smoke test was performed.
No custom point arithmetic, parser or permissive fallback was introduced.

The earlier 15-row diagnostic mapping remains applicable to wrapper responsibilities.
SIGNATURE_INVALID now has partial library coverage through RFC/invalid/public-key cases
and a demonstrated strict-profile gap (V04-21). Every other diagnostic remains a future
wrapper responsibility; no application diagnostic engine was implemented. Dedicated
length, wrong-domain, ph/ctx, all scalar/point and multi-fault tests were not completed.

RFC 8032 VECTORS: PASS. WYCHEPROOF COMPATIBILITY: REVIEW_REQUIRED.
STRICT ED25519 PROFILE: FAILED for the tested dependency/backend combination.
