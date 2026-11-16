# IAM-03C-TRUST-03 cryptographic threat model

2026-11-15. **PROPOSED controls; not implemented or verified.** Read with the
[architecture](iam03c-trust03-cryptographic-architecture.md) and
[future verification cases](iam03c-trust03-verification-plan.md).
Existing [persistence threats](iam03c-authority-threat-model.md) remain applicable.

## Assets, actors and boundaries

Assets are customer root/key identity, exact signed intent, tenant/deployment/
environment isolation, issuer scope, current complete authority state, revocations,
independent latest checkpoints and attributable audit history. A valid signature
is evidence of a key's endorsement of bytes, not correct business intent or a grant.

Adversaries include untrusted requests/LLMs/providers, an authenticated tenant without
a grant, another customer, a stolen key holder, dishonest custodians, privileged
DB/backup/platform administrators, compromised signer displays/verifiers and stale
workers. Customer root ceremony and authenticated independent pin/current-head
storage are explicit proposed trust boundaries. No DB record or verifier-returned
boolean can bootstrap these boundaries.

The default profile tolerates one unavailable/compromised custodian only if the
other two and their signing paths remain independently trustworthy. It does not
tolerate compromise/collusion of two eligible custodians. A protected local journal
cannot withstand co-compromise/restore of its administrator/host and database.
The stronger witness profile moves, rather than eliminates, that trust boundary.

## Attack paths, controls and residual risks

K-numbers refer to future cases in the companion plan. Severity is potential impact
if future controls are absent, not evidence of a bypass through today's denying IAM.

| ID / severity | Preconditions | Attack path | Security impact | Required mitigation / failure behavior | Residual risk | Future cases |
| --- | --- | --- | --- | --- | --- | --- |
| T03-01 Critical — forged signature | Attacker can submit proof bytes | Fabricate, truncate, alter or use malformed point/scalar/signature encoding | Fabricated root or issuer endorsement | Strict established-library verification of pinned key/profile/exact frame; bad supplied entry denies even if two others pass | Library or trusted verifier compromise | K01–K03, K14, K29, K35 |
| T03-02 Critical — one stolen custodian key | One key/device compromised | Submit malicious transition as that custodian; relabel aliases to add votes | Attempted root replacement/recovery | Two independent eligible custodians; key/custodian/material duplicate rejection; current revocation and incident quarantine | Thief can cause denial; second compromise defeats ordinary two-of-three | K03, K06–K08, K17 |
| T03-03 Critical — two custodians collude/coerced | Two eligible customer keys/people controlled | Jointly sign malicious but cryptographically valid intent | Root/policy takeover | Independent custody and trusted displays, explicit ceremony review/incident evidence; no claim cryptography distinguishes honest intent | Quorum cannot cryptographically reject authorized collusion; loss of trust needs owner-led re-establishment | K18, K28, K34 |
| T03-04 Critical — duplicate counting | Key aliases or repeated signatures accepted | Count same key/person twice or two keys under one custodian | One compromise supplies apparent quorum | Independent enrolled mapping; reject duplicate custodian/key/material before counting; every entry valid | False enrollment can pretend two people are independent | K06, K07, K34 |
| T03-05 Critical — stale root policy | Old signed policy/key set available | Replay policy with lower threshold/retired issuer or different pin | Resurrection of retired authority | Independent minimum/current version/root-set pin, monotonic activation and explicit old/new transition; no threshold from candidate | Pin-store co-rollback defeats version comparison | K09, K17, K31 |
| T03-06 Critical — revoked anchor | Old signature/key valid historically | Supply expired/revoked signer under cached state | Revoked authority becomes current | Current authenticated key lifecycle, revocation epoch/checkpoint and protected time; historical signature is not current authority | Truly disconnected verifier cannot learn new revocation; must withhold current evidence | K08, K24, K25, K30 |
| T03-07 Critical — cross-tenant replay | Proof for tenant A obtained | Substitute request context/inner subject/scope for B | Cross-customer privilege or data exposure | Independent expected tenant, signed full inner/outer bindings, scoped key set and post-verify semantic comparison | Compromised trusted context composition can lie about tenant | K04, K23, K28 |
| T03-08 Critical — cross-deployment replay | Valid proof from another installation/test environment | Reuse same IDs after clone, enterprise-to-SaaS move or production restore | Wrong deployment authority accepted | Sign and independently pin trust domain/deployment/environment/incarnation; explicit migration transition and old-site fencing | Infrastructure unable to fence old writers prevents safe activation | K05, K27, K30 |
| T03-09 Critical — algorithm confusion | Header/algorithm API is attacker selectable | Ed25519ph substitution, double hash, DER/raw ambiguity, RSA parameter downgrade or key-type confusion | Forged/misinterpreted verification | Independent fixed algorithm/profile; exact public/signature encodings and parameters; signed profile/domain; no trial/fallback | Device incompatibility and module/provider mistakes | K14, K20, K29, K35 |
| T03-10 Critical — canonicalization mismatch | Two parsers/serializers differ | Duplicate escaped keys, Unicode aliases, integer rounding, changed time/defaults, trailing bytes | Signer/verifier endorse different operations | Frozen ASCII/versioned profile; lossless integers; reject duplicates before parse, exact canonical bytes/frame length, cross-language vectors | Unreviewed serializer upgrade or display ambiguity | K10, K29, K35 |
| T03-11 Critical — unknown signed fields | Verifier ignores metadata another consumer uses | Sign valid unknown grant/critical flag or add unsigned actor/scope override | Downstream privilege interpretation | Closed schemas for body/purpose/header; all consequential fields signed and compared; unknown fields/versions deny | Schema evolution requires coordinated review; no permissive forward compatibility | K10, K22, K23 |
| T03-12 Critical — DB rollback | DBA/backup control can restore valid old full image | Replay old graph, revocations, revision and audit prefix | Revoked grants appear current | Fresh primary state vs independent latest checkpoint/high-water proof; pending intent and full-state verification; no counter reset | Simultaneous compromise/restore of DB and independent head is outside local guarantee | K11–K13, K21, K31, K33 |
| T03-13 Critical — checkpoint rollback/fork | Checkpoint administrator or store compromised/unavailable | Replay signed old prefix, fork equal revision, hide newer checkpoint | DB rollback detection bypass | Separately current authenticated high-water state, protected compare-and-append, generation/previous digest, no cached/older fallback; conflict/unavailable denies | Witness/admin quorum compromise can lie or halt availability; signatures alone do not make latest head discoverable | K11, K30, K31 |
| T03-14 High — journal tampering/partial recovery | External journal file or publish window attacked | Delete pending intent, claim missing file means CLEAR, alter intent after DB commit | Partial or restored authority accepted | Authenticated durable journal generation/intent, writer serialization, no inferred CLEAR; uncertain state quarantines; independent recovery | Cross-store atomicity absent; availability can be lost even after successful DB commit | K13, K26, K31, K33 |
| T03-15 High — lost keys/backups | One/two devices unavailable or common backup lost | Recovery pressure causes quorum reduction or vendor master override | Availability loss or bypass | Tested separate custody/backup; one loss uses remaining two; two losses quarantine and owner-authenticated re-establishment only | Irrecoverable authority continuity without independent evidence; recovery is not guaranteed | K07, K17, K18, K34 |
| T03-16 Critical — malicious recovery request | Operator/provider can propose intent or compromise common signer display | Trick honest quorum into wrong destination, new root or reverted privileges | Root substitution, replay and unauthorized regrant | Signed exact incident/state/destination/old checkpoint and eligible signers; trusted review display, new-set acknowledgement, old-site fencing, no automatic regrant | Two deceived/compromised signers may endorse valid malicious intent | K17–K19, K27, K34 |
| T03-17 Critical — SaaS operator escalation | Provider controls infrastructure or recovery key | Treat platform login, shared key or delegation_ref as customer root; bootstrap own delegation | Unauthorized customer authority or runtime access | Customer-specific independent root/witness; no vendor root, no provider-only quorum; explicit bounded customer delegation; provider excluded from root/policy replacement | Host/plaintext DB controller can bypass runtime or read data outside signature model; needs separate confidentiality/runtime controls | K04, K19, K23, K28 |
| T03-18 Critical — verifier compromise | Host/build/config or library compromised | Replace pins, claim arbitrary verification success, log keys or send fabricated evidence | All local verification decisions unreliable | Pinned reviewed build/dependencies, isolated bounded parser, authenticated composition/evidence delivery, independent pins/keys; no public verified flag | Same-host administrator can replace verifier/client; process isolation is not remote attestation or host integrity | K15, K16, K28, K29, K35 |
| T03-19 High — time manipulation | Clock/evaluation input/uncertainty compromised | Roll clock back to revive expired keys or forward to deny service | Expired authority accepted or outage | Explicit protected time source and bounded uncertainty; interval checks and current epochs; unknown/backward trusted time denies | Compromised time source within trust boundary; time cannot prove latest revision | K24, K30 |
| T03-20 Critical — partial revocation propagation | Cached/async workers or multiple writers not serialized | Accept once-valid proof after key/session/grant revoke; acknowledge too early | Post-revocation privileged action | Common mutation/gate ordering, current independent state, pending publication blocks new gates; completion after durable publication/serialization; revalidate on dispatch | Already ordered work may finish first; DB lock cannot cancel external effects | K08, K25, K26, K30, K33 |

## Related failures that every test must consider

Partial signed subsets do not prove complete state. All relevant tombstones,
credential/resource identity and policy facts must be committed and reconstructed;
unknown/truncated groups deny (K21). Signatures on changed timestamp projections
must not be attributed to old source bytes (K23). A signed scope still needs current
issuer ceiling and unchanged IAM role/action/resource/approval evaluation.

A commit acknowledgement failure may follow successful durable effect/audit.
Return UNKNOWN, reconcile by immutable operation/intent and independent head;
do not assert no effect, silently retry or publish a false denial audit claiming
rollback (K33). Audit omission and concurrency require real isolated DB evidence,
not a successful pure verifier test (K26).

## Required owner risk decisions

A01 must accept custody/collusion/recovery and local-host co-rollback limits or
choose the stronger independent witness/control boundary. A04 must freeze exact
purpose schemas, complete-state proof, verifier source authenticity and execution
handoff semantics. Provider-assisted recovery eligibility is a proposed refinement,
not granted delegation. A02/A03/A05 are still pending.

No current test result proves the proposed mitigations. The existing PostgreSQL
provider remains denying and TRUST-02 remains STRUCTURAL_ONLY. Operational,
cryptographic implementation, schema and production deployment remain NO-GO.
