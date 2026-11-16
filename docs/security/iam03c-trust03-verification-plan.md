# IAM-03C-TRUST-03 future verification plan

2026-11-15. **Plan only. No cryptographic tests, keys or verifier implemented.**
Read the [architecture](iam03c-trust03-cryptographic-architecture.md) and
[threat model](iam03c-trust03-threat-model.md). Retain the existing
[TRUST-01 matrix](iam03c-trust-verification-matrix.md) and
[isolated database plan](iam03d-isolated-verification-plan.md); this plan adds crypto
cases and does not authorize their execution.

## Evidence classes and safe sequencing

- **O — future offline verifier tests:** published non-production vectors and
  independently pinned explicit TEST fixtures, no DB/services/network. Require
  separate implementation/test authorization. Positive crypto tests demonstrate
  the selected algorithm/profile/bytes only, never operational IAM or customer
  authority. No production key generation is implied.
- **S — future isolated signer/store tests:** approved test HSM/token, time source,
  external checkpoint/journal/witness and controlled crash/filesystem fixtures.
  Real device/storage/independence assertions cannot be proven by fake ports.
  Device setup, test material, destructive recovery and service access need explicit
  scope; no production credentials or roots.
- **D — future IAM-03D disposable PostgreSQL integration:** exact approved isolated
  target/credentials/roles/injected connections, independent test root/witness.
  Access neither ai_soc nor ai_soc_test. A03 and the dedicated guard exception are
  required; current app settings/default connection paths cannot be reused.
- **E — future IAM-04 enforcement integration:** authenticated identity source,
  reviewed production admission contract and actual final gate. External actions
  remain disabled without their separately approved fencing semantics.

O can test a pure comparison/state machine with fixed observations; S/D/E evidence
is still necessary for claims about actual storage durability, connected identity,
transaction isolation, revocation ordering and protected effects. No fake latest
checkpoint or synthetic registry is production trust.

Record for each case: protocol/schema/profile/code/library/provider versions,
expected context and fixture class, independent anchor provenance, exact canonical
frame/payload/public-key fingerprints or safe reference digests, fault/ordering,
expected/actual fixed result and side-effect calls. Keep private keys, credentials,
raw source payloads, signatures and recovery secrets out of reports. Approved public
vectors may be retained only in future dedicated test fixtures, not operational
configuration. A failed or unapproved case stays unmet, never skipped into success.

## Future test matrix — all SPECIFIED, NOT EXECUTED

Positive cases assume the independently supplied TEST pins/context are trustworthy
within that test. Multi-fault cases assert fixed stage/within-stage priority once
frozen under A04. Crypto reasoning never invents real user/provider authorization.

| Case | Preconditions / input and required evidence | Expected result / failure assertion | Evidence class |
| --- | --- | --- | --- |
| K01 — Positive signature/quorum | Published RFC 8032 vectors plus exact signed-frame vectors; independently enrolled three TEST custodian keys, two signatures over identical root frame; all required state fixtures current | Exact signature/quorum evidence bound to frame/pin/context; no IAM ALLOW, mutation or execution; known-answer signatures verified by established library | O |
| K02 — Invalid signature | Alter one payload/signature byte, truncate/extend signature, malformed scalar/point, or supply invalid third signature alongside two valid | SIGNATURE_INVALID; all supplied entries checked; no usable current evidence or ignored extra | O |
| K03 — Wrong key | Valid signature under another customer/purpose/key; header changed to approved key ID | Wrong key cannot verify; SIGNATURE_INVALID or SIGNER_UNKNOWN at declared stage; no key discovery/fallback | O |
| K04 — Wrong tenant | Independently expected tenant A; valid root/issuance inner or outer B or subject/scope reference B | BINDING_MISMATCH; early tenant guard and post-verify comparison both exercised; no B key inventory disclosure | O; D/E composed tenant isolation |
| K05 — Wrong deployment/environment | Same UUIDs or keys replayed under different deployment kind/UUID, TEST/PRODUCTION environment or source incarnation | BINDING_MISMATCH; structural record cannot select expected context | O; E real context delivery |
| K06 — Duplicate signer | Duplicate custodian ID, key ID, material fingerprint or two enrolled keys sharing one custodian; reorder inputs | SIGNER_DUPLICATE; no double count, same result under permutations | O; S enrollment evidence |
| K07 — Insufficient quorum | Zero/one signature, revoked second signer, changed candidate threshold, quorum-loss pressure | No threshold downgrade; QUORUM_INSUFFICIENT or earlier lifecycle rejection; no vendor/master fallback | O |
| K08 — Revoked key | Historically valid signature with independently current revoked key/custodian/issuer epoch | KEY_REVOKED/current evidence denied; historical signature validity not misreported as current authority | O; S/D/E actual revocation publication |
| K09 — Stale policy | Valid old policy/profile/set with older current-pin generation, including retired algorithm | POLICY_STALE; candidate cannot choose policy/threshold; same-version/different-digest conflict denies | O; S pin persistence |
| K10 — Canonical mismatch | Duplicate escaped keys, aliases, changed defaults/nulls/time/UUID ordering, non-ASCII, numeric bool/float/exponent/overflow/lossy integer, BOM/trailing bytes | STRUCTURE_INVALID/CANONICAL_MISMATCH as frozen; no normalization that changes signed meaning; existing TRUST02 bytes unchanged | O |
| K11 — Checkpoint mismatch | Validly signed equal-revision conflicting state/epoch/event or wrong audit-prefix/checkpoint/source/environment binding | CHECKPOINT_CONFLICT; never choose by timestamp, silently re-anchor or accept signed subset | O; S/D actual observations |
| K12 — Database rollback | Independent current checkpoint R+1 and fresh committed primary R versus separate control old snapshot R/current head R+1 | ROLLBACK_DETECTED only for real fresh-head rollback; old snapshot with fresh matching R+1 yields REVISION_STALE | O state model; D real restore/concurrent reads |
| K13 — Journal inconsistency | Missing/unreadable/tampered journal, wrong pending digest/generation, PREPARED/uncertain intent and absent DB operation | RECOVERY_INCOMPLETE; no inferred CLEAR or automatic rollback conclusion; hold new evidence/gates | O; S/D crash/storage proof |
| K14 — Unsupported algorithm/domain | Change profile/key type, Ed25519ph/ctx, RSA salt/MGF/hash, P-256 curve/encoding, frame label/length/purpose | ALGORITHM_UNSUPPORTED/DOMAIN_MISMATCH; no alternate-key/algorithm trial; exact parameter/length validation | O |
| K15 — Synthetic authority | StructuralAssessment, SyntheticProvider/for_tests objects or caller verified=True supplied as production proof | SYNTHETIC_SOURCE/STRUCTURE_INVALID; no relabeling or synthetic registry conversion | O; E bridge boundary |
| K16 — Missing independent anchor | Body/DB supplies keys but authenticated anchor source is missing, stale, unavailable or substituted | ANCHOR_UNAVAILABLE; self-signature cannot bootstrap trust; no trust-on-first-use | O; S authenticated store |
| K17 — Rotation/replacement | Exact transition has old eligible quorum, new acknowledgement array, pinned next key set and state publication; alter one transition digest/array/version | Valid TEST transition only when all match; old signatures cannot sign a different new root; interrupted activation denies; old retired set never resurrects | O; S/D real publication |
| K18 — Recovery/quorum compromise | One lost key, then two lost/compromised keys; malicious recovery/destination; independent incident and owner evidence fixtures | One loss requires remaining two; no trustworthy quorum means quarantine/re-establishment gate, not automatic crypto success | O workflow; S approved ceremony simulation |
| K19 — Provider delegation | SaaS platform key/login, nil/dead delegation_ref, provider-only signatures or provider voting for root replacement; separate exact approved restore-delegation fixture | Provider gets no default customer/issuer right; ISSUER_UNAUTHORIZED unless exact eligible customer-delegated scope with required customer participation. Self-hosted assistance unsupported initially | O; S/E real customer delegation identity |
| K20 — Alternative hardware/profile | Approved P-256 candidate with actual device/provider output and low-S/raw/DER adversarial encodings; compliance module evidence | Only frozen encoding/parameters accepted; device mismatch blocks profile; no unsupported FIPS/module assertion | O vectors; S actual device/configuration review |
| K21 — Full-state completeness | Valid signature over partial/truncated graph, omitted tombstones, credential/resource facts or wrong group manifest; exceed completeness budget | STATE_INCOMPLETE or state commitment mismatch; no truncation, signed subset or missing table treated as empty trusted data | O; D actual complete reads |
| K22 — Unknown signed/header fields | Add signed role/critical/metadata field or unsigned actor/scope/algorithm override; otherwise valid signature | Closed schema rejects before interpretation; nothing consequential derives from unsigned display metadata | O |
| K23 — Issuer scope/record projection | Valid key outside root-authorized purpose/role/source ceiling; self-escalation; retimestamp original receipt or change projected record digest | ISSUER_UNAUTHORIZED/BINDING_MISMATCH; original and new projection attestations bind their own exact bytes; valid signature supplies no grant | O; D/E IAM parity |
| K24 — Time manipulation | Explicit aware clock/uncertainty before issuance, at expiry, clock rollback or unknown source; signed interval otherwise valid | TIME_UNTRUSTED/EXPIRED; no implicit current time, grace extension or temporal substitute for current revision | O; S/E real clock delivery |
| K25 — Concurrent revocation | Barriers order gate-first versus revoker-first; cached worker/session/key/issuer revoked before dispatch; multiple tenants/hosts | No stale action after completed revocation; operation ordered first may finish before revocation acknowledgement; final gate required, no once-only revision claim | O state model; D/E actual locks/dispatch |
| K26 — Audit atomicity | Fault each authority/revision/audit/checkpoint publication point, including denial audit and audit source attribution | Known rollback has no partial durable grant/revision/success audit; unknown outcome handled separately; unchanged chain/hash/lock semantics | S/D/E |
| K27 — Legitimate migration/restore | Signed old/new deployment/environment/incarnation and state/checkpoint intent, new key acknowledgement if changed, verified destination enrollment, old-site fencing | Exact transition only; missing old fencing or stale source replay blocks activation; no copying files/DB/host rename as authorization | O; S/D/E actual fencing |
| K28 — Verifier/display compromise | Replace verifier/source result or pins, forge runtime success, compromise common signer display in test model | Reject unauthenticated evidence source; demonstrate host/display trust limitation rather than claim same-host process isolation prevents it; incident gates mandatory | O composition faults; S/E trusted-build/custody assessment |
| K29 — Bounds and parsing robustness | Cap/cap+1 bytes/depth/signatures, mixed fault orders, malformed point/length/JSON inputs, parser/library errors | Deterministic bounded rejection, no raw input/secret echo or I/O side effects, no uncaught retry-to-other-profile | O |
| K30 — Offline freshness/partition | Signature valid but current pin/revocation/checkpoint unavailable or cached older, independent witness partitioned | Historical signature diagnostic only, no current VerifiedProvenanceEvidence/ALLOW; no cached older-head fallback | O; S/D/E actual availability |
| K31 — Witness/checkpoint replay/fork | Old signed checkpoint prefix, co-restored local journal and DB, equal revision fork, or compromised witness model | Independently current high-water detects replay/fork; co-compromise without outside evidence is explicitly an unmet guarantee, not test success | O; S/D independent storage/recovery |
| K32 — Two quorum arrays | Valid old transition signatures but missing/wrong new-set acknowledgements, duplicate keys between aliased sets, mutation after one party signs | Same exact frame required for both sets; invalid/missing acknowledgement blocks activation; no self-reference in digests | O; S real rotation ceremony |
| K33 — Unknown commit outcome | Lose commit acknowledgement between DB commit and external publication/clear; replay immutable intent | UNKNOWN/reconciliation required; may already have effect/audit; no success, blind retry, pending deletion or false no-effect assertion | O state model; S/D/E failure injection |
| K34 — Bootstrap independence | Manifest self-signature, IdP admin/root-row claim, same operator renamed as two custodians; separate authenticated enrollment/pin ceremony fixture | No self-establishment of root; missing independent owner/custody/pin evidence blocks establishment; approved ceremony evidence is not manufactured by unit tests | O workflow; S separately authorized enrollment review |
| K35 — Cross-implementation vectors | Published algorithm positive/adversarial vectors plus frozen independent frame/encoding expected bytes verified by two reviewed implementations | Exact bytes and acceptance/rejection agree, no regenerated expected values from implementation under test; dependency/profile update reruns vectors | O; S for hardware variant |

## Production-readiness gates — distinct, all currently closed

| Gate | Approval and evidence needed before that activity | Stop conditions |
| --- | --- | --- |
| G1 Offline crypto implementation | Separate TRUST-04 authorization; A01/A04 accepted implementation subset; exact initial purpose/body/manifest fields and profile, framing/budgets/error priority frozen; approved maintained library/version/API and vector provenance; no production roots | Missing purpose schema, incompatible TRUST02/IAM change, crypto ambiguity, need for real keys/services or operational trusted output |
| G2 Real customer root establishment | Production A01 approval of named independent custodians, key/device/backup/rotation/recovery and loss/collusion/host/witness risks; exact owner-authenticated ceremony/pins and separately authorized key generation/custody | Missing quorum/identity/independence, provider master root, self-approval, ambiguous restore or pin source |
| G3 Provenance-to-IAM integration | Production A04 proof/source/complete-state/projection/admission contract approved; A02 where human identity applies; authentic verifier delivery; current key/policy/state evidence and IAM-01/02/03A semantic parity | Synthetic promotion, fabricated issuer/context, absent completeness/currency, changed policy/approval semantics or missing identity source |
| G4 PostgreSQL authority persistence | A03 exact disposable isolation/privileges/guard exception and separate schema/migration/role authorization; A05 chosen profile/FK closure; approved A01/A04 persistence-proof prerequisites; real IAM-03D cases | Any protected database/default connection, unapproved role/DDL, unaudited mutation, false snapshot currency or missing provenance |
| G5 Execution-time authorization | Separate IAM-04 approval and G3/G4 evidence; shared writer/gate protocol, actual concurrency/revocation/audit/UNKNOWN tests; session/issuer source verified; remote fencing only if separately designed | Snapshot ALLOW used as capability, missing final gate, external side effect assumed atomic with DB lock |
| G6 Self-hosted production | G2–G5 as applicable plus approved local/witness threat boundary, independently protected pins/journal/current state, custody/restore drills, least-privilege deployment, trusted time/build and operational sign-off | Host co-rollback risk unaccepted, missing live verification or shared unsafe admin/backup domain; documentation/tests alone insufficient |
| G7 Managed SaaS production | G2–G5 plus customer-specific enrollment/signers/context, provider/customer admin separation, approved independent witness/current-state service, tenant isolation at real scale, recovery delegation and confidentiality/runtime threat model | Provider identity becomes customer authority, shared universal root, missing old-site fencing, unavailable independent current evidence or unaddressed plaintext/runtime-admin access |

G4 may proceed in an isolated disposable environment after its scoped approvals
without deploying a real production root. G6/G7 cannot skip upstream evidence by
claiming that G1's offline tests passed. A declaration that a gate is required is
not evidence that it has been implemented or approved.

## Acceptance criteria and implementation sequence

1. Owner reviews A01/A04 profile, independence/custody and signed-body decisions;
   A02/A03/A05 stay pending except where explicitly approved. Retain the customer-
   authority/no-vendor-root constraint in every deployment.
2. Separately authorize G1's smallest frozen-purpose verifier, with no operational
   imports, synthetic promotion, keys/services/DB access or IAM behavior changes.
   Use only approved established cryptographic library APIs; never custom arithmetic. O cases and frozen independent vectors must pass.
3. Separately authorize S evidence: custody/device interoperability, protected pin/
   clock/journal/witness behavior and incident/restore simulations. Do not infer
   independent storage or people from identifiers/fingerprints alone.
4. After A03/A05 and relevant A01/A04 decisions, separately authorize isolated
   persistence/migration/roles and real D cases; preserve current rejecting adapter
   until its actual security properties are verified.
5. Only after G3/G4 evidence and separate IAM-04 authorization integrate production
   admission/current evidence/final gates and E cases. No external/async exception
   without explicit ordering/fencing design. Deployment has distinct G6/G7 approval.

All supported O cases must produce immutable evidence bound to exact bytes/context,
fixed sanitized diagnostic/rejection, bounded runtime and no authority mutation or
execution. Mandatory O/S/D/E cases remain unmet until actually evidenced. Partial
results, absence of failures, historical 98/2,034 results or successful structural
parsing are never production acceptance.

Future test reports must preserve existing IAM policy IDs, record/audit hashes,
API/OpenAPI/routes, tenant isolation and synthetic-only compatibility. A new approved
wire purpose does not permit changing TRUST02-JSON-1 under the same version.

## Checks performed now and recommendation

TRUST-03 performs only source/document consistency, existing-symbol/reference/link,
case/threat/gate traceability, approval-status, whitespace and preexisting file/index
preservation checks. No pytest/compilation/algorithm/library verification, key,
service, network, PostgreSQL, container or migration operation occurs. All K cases
remain SPECIFIED, NOT EXECUTED. No actual FIPS certificate/device status is verified.

Recommend TRUST-04 specification freeze and owner review of G1, followed only by
separately authorized offline verifier implementation. This plan authorizes neither
that implementation nor root establishment, IAM-03D, IAM-04 or deployment.

**A01: PRODUCTION APPROVAL PENDING**  
**A04: PRODUCTION APPROVAL PENDING**  
**A02/A03/A05: PENDING**  
**CRYPTOGRAPHIC DESIGN: PROPOSED**  
**CRYPTOGRAPHIC IMPLEMENTATION: NO-GO**  
**DATABASE SCHEMA IMPLEMENTATION: NO-GO**  
**OPERATIONAL IAM: NO-GO**  
**PRODUCTION DEPLOYMENT: NO-GO**  
**NEXT STEP: Recommendation only**
