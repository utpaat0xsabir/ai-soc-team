# IAM-03C D01–D04 decision package

Prepared 2026-11-14. **Recommendations only; no architecture approval or implementation.**
All four decisions are **PROPOSED**. The project owner's authorization to prepare
this package is not approval of its recommendations. Schema implementation and
operational IAM remain NO-GO. Companion: [minimum schema review](iam03c-minimum-authority-schema-review.md).

## 1. Executive summary

Recommend: two-of-three independently held offline root signatures; a protected
local checkpoint journal outside the authority DB; local OIDC/WebAuthn operator
authentication with durable application sessions; a completely separate disposable
PostgreSQL instance; and explicit production provenance/identity contracts that
reuse the pure IAM validators without enabling synthetic providers.

The initial authority profile should be deliberately narrow: explicit API-key
service assignments for teamless evidence metadata reads only, provisioned through
root-approved control-plane intent. Recommend a **16-table authority core**, merging
one redundant key-binding relation and deferring six tables under explicit feature
restrictions. This does not approve the earlier 23-table design or implement a
reduced schema. Human session/IdP storage is a separate prerequisite, not hidden
inside that table count. No online IAM administration, team access, raw/export,
approval-dependent action or external execution is permitted by the initial profile.

Complete-state verification and an off-DB checkpoint address an important gap:
a signed row alone cannot prove that PostgreSQL returned every revocation. A DB
commit and a filesystem checkpoint are not one atomic transaction; pending or
ambiguous publication **denies authority** until verified reconciliation. A final
same-database execution gate must still serialize with authority mutation. No
claim of instantaneous cancellation or atomic remote side effects is made.

## 2. Existing contract assessment and prerequisite review

All required documents were present. Read the instructions/handoff, current design,
threat/verification plans and audit limitations; reused unchanged earlier IAM/REF
findings only after comparing source/document hashes with the preceding design
review. Current Git has existing modified adapter/tests/SEC-02 work and untracked
design documents/artifacts; none is staged, removed, executed or altered here.

| Current file / symbol | Constraint on the decision |
| --- | --- |
| `services/api/app/iam/contracts.py:AuthenticationReference`, `PrincipalIdentity`, `Validity` | Kind/method mapping, tenant references and finite windows; API-key service identity does not imply a grant; no OIDC verifier or session store |
| `iam/contracts.py:RoleDefinition`, `role_catalog`, `PermissionScope`, `RoleAssignment` | Proposed canonical role names, exact scope/actions and issuer!=subject; no arbitrary new role/permission vocabulary |
| `iam/contracts.py:IssuanceEvidence`, `validate_snapshot`, `validate_approval` | Separate record digests/provenance; complete current graph; approver/operation equality; none authenticates its own source |
| `iam/policy.py:AuthorizationPolicy`, `TrustedVerification`, `evaluate` | Explicit policy/digest and trusted verifier inputs; exact role/action/resource/team/classification/approval; no fallback policy; ALLOW remains non-executable |
| `iam/admission.py:AuthoritySnapshot`, `SyntheticAuthority`, `admit` | Exact synthetic origin and authenticated-object registration; <=60-second snapshot, <=15-second revocation age, <=300-second receipts/anchors; only API_KEY_SERVICE actor admission |
| `iam/authority_provider.py:AuthorityProvider`, `ProviderSnapshot`, `ProtectedAuthorityBridge.authorize` | Protocol returns a synthetic-only type; ten equal component epochs; exact SyntheticProvider type check; pre/post currency checks are not execution fencing |
| `iam/postgres_authority.py:read`, `is_current`, `InjectedReadSession` | Dedicated read rollback/caller close; exact tenant/key/request/observation/mapping checks; no operational snapshot; currency always false |
| `iam/auth.py:get_current_principal`, `get_current_tenant`; `iam/api_keys.py` | Existing key hashing/unrevoked lookup binds tenant/key IDs, not HUMAN identity, MFA or privileges |
| `database/models.py:TenantAPIKey`, `AuditLog`; `database/roles.py:RolePlan` | Eight current tables; no IAM graph/revision/session model; audit actor_type only api_key/service/system; role-plan database whitelist excludes a new disposable name |
| `app/db.py`; `migrations/env.py` | Ordinary eager configured engine/settings paths cannot be imported by an isolated harness expecting no default connection |
| `audit/integrity.py:record_audit_event`, `verify_audit_chain` | Existing tenant lock, same-transaction staging and SHA-256 chain; no commit and no independent proof against tail deletion/whole-chain rewrite |

Abbreviated paths in this table are under `services/api/app/`; these are actual
canonical symbols. Flat IAM/models modules remain compatibility exports.

Source/tests reviewed include current adapter fake-session/lifecycle/provenance
cases, provider origin/epoch race cases, admission issuer/receipt/approval checks,
and policy role/duplicate/scope checks. Migration sources retain tenant-qualified
lineage/Wazuh FKs, key/audit storage and audit triggers/hash backfill; the proposed
IAM tables do not exist. No migrations or tests were executed for this document task.

Conflicts explicitly carried forward:

- Early IAM docs use former flat paths; REF-01 canonical paths supersede navigation.
- Older 1,892/358 counts predate 1,936/402; no current failure is inferred from that.
- The handoff/database-role document's live-role/revision observations are historical.
- General repository tests require ai_soc_test, but this decision task protects both
  ai_soc and ai_soc_test. D03 recommends a new guarded harness and a specific owner
  exception before future execution, not removal of existing protections.
- Prior design statuses are BLOCKED. Here they become PROPOSED recommendations
  awaiting approval, not APPROVED decisions. Prior design files remain unchanged.

## 3. D01 — independent root and restore trust

### Options

| Approach | Security properties | Dependencies / failure modes | Recovery complexity and local-first fit |
| --- | --- | --- | --- |
| Single offline administrator root | Simple offline pin; DB cannot manufacture its signature | One stolen/lost key or compromised custodian controls/blocks everything; no separation of duties | Low setup, brittle recovery; suitable only with an explicitly accepted single-person trust model, not recommended |
| Two-of-three independent offline signatures | Any two distinct custodians authorize root manifests/recovery; one lost key tolerable; no custom threshold cryptography | Need three real custodians, two available; quorum compromise defeats trust; identity of custodians must be established out of band | Moderate ceremony/escrow burden; recommended local-first governance without a network service |
| Hardware-backed root/admin keys | Reduces private-key extraction; user presence/PIN can strengthen ceremonies | Hardware loss, firmware/vendor/host risks, supply/budget and backup needs; hardware alone provides neither independent people nor DB rollback detection | Good optional custody mechanism for the quorum; not an alternative to recovery/audit policy |

### Recommendation and trust material

Choose **two-of-three independent Ed25519 signatures** over one canonical root
manifest/ceremony intent, not a new cryptographic threshold scheme. Each key belongs
to a distinct named custodian. Three devices owned by one person are not dual
control. Hardware-backed custody is preferred where supported; otherwise protected
encrypted offline media plus physically separate recovery custody. Do not invent
available custodians or silently downgrade when a quorum is unavailable.

Root private keys, their recovery material, root public-key pins, current signed
manifest/version pin, and the off-DB checkpoint/pending journal must remain outside
the authority database, outside Git and outside DB backup/restore control. Pin
verification code/configuration is operator protected. Root private keys do not
sign routine snapshots online. Distinct root-authorized issuer and checkpoint/
verifier keys perform bounded routine functions; no requester controls those keys.
A DB key/status row is accepted only under that independent pin and scope.

Bootstrap order: project owner approves custodians/verification procedure; a future
explicitly authorized offline ceremony records public fingerprints and signs the
initial tenant/source/incarnation, verifier/issuer scopes, policy/profile and
identity-enrollment manifests. Only then may separately approved bootstrap code
create suspended records and explicitly enrolled authority. No migration root,
self-signed DB issuer, default administrator or initial API-key role is created.
This package generates no key, fingerprint, certificate or credential.

Root custody bootstrap uses physical/out-of-band custodian identification; it
cannot depend on an IdP or IAM role that the root has not yet authorized. Later
OIDC administrator login does not make its subject a root custodian. Root operations
remain a distinct, independently approved control plane, not an IAM global-admin
role or a new permission added to IAM-02.

### Restoration, rollback and journal publication

Compare: (a) accept a trusted DBA and manual restore quarantine; (b) protected local
signed checkpoint/pending journal plus complete-state digest; (c) an independent
online witness/hardware monotonic service. Option (a) is simpler but cannot detect
malicious rollback on its own. Option (c) adds deployment/protocol dependencies and
still needs crash/partition semantics. Recommend **(b)** for the initial single
control-plane-host deployment, with host/custodian compromise explicitly outside
its guarantee. Do not claim a local file or a hardware key is immutable WORM storage.

The proposed checkpoint binds tenant, source, incarnation, profile/schema version,
root-manifest version/digest, monotonic revision, epoch, authority-state digest,
revision-event digest and audit anchor sequence/hash. The state digest covers the
complete canonical tenant authority state including revocations, not just returned
request rows. See D04 for the no-cycle definition. The checkpoint signs an audit
prefix; it does not prove that every later non-IAM audit tail entry was preserved.

A single authorized mutation coordinator per deployment takes a protected per-tenant
writer mutex and the established DB tenant/head locks. Read gates never wait on
that writer mutex; they atomically read journal state and deny if pending.
The future crash-tested publication protocol must be:

1. Verify current DB head/state against the independent checkpoint and approved
   root pin. Authenticate the exact operator/issuer intent; choose immutable intent
   ID and next revision. Persist/fsync a signed **pending intent** outside the DB
   before the first authority DML. Pending means unavailable authority, not an
   incremented committed revision.
2. Commit authority changes, revision/event/state digest and existing audit in one
   DB transaction. Every writer, including key/issuer revocation, must use this path.
3. After verified commit, atomically publish/fsync the next signed checkpoint,
   then clear/fsync pending state. Refuse another mutation or successful gate until
   head/checkpoint/source/profile agree and pending is clear.

DB and journal are **not atomically committed together**. Authority availability
is deliberately lost during the publication gap. The DB transaction's grant/revision/
audit atomicity remains intact; failed transactions do not advance the committed
checkpoint. An external online witness is not silently assumed.

| Observed recovery state | Required result |
| --- | --- |
| Clear journal; exact DB/checkpoint/root/state equality | Eligible for full provenance/policy verification, never an ALLOW by itself |
| Pending; DB has exact signed next event/state/audit | A fenced recovery coordinator can verify all proofs and finalize that checkpoint; no authority before completion |
| Pending; DB appears at old revision or operation is missing | Ambiguous failure versus restored DB: deny/quarantine. Do not infer rollback from missing rows; independent recovery quorum must resolve or keep tenant disabled |
| DB behind checkpoint, ahead without matching pending, different digest/source/incarnation, invalid signature, missing journal/root pin | Deny and open recovery incident; no cached-allow or automatic counter reset |
| Commit acknowledgement lost | Reconcile under tenant lock and coordinator fencing against immutable operation ID and journal; no blind retry |

Backups must label DB data **nonoperational until restored-state verification**.
Never restore the current checkpoint/pin alongside an old DB and thereby erase
rollback evidence. Keep independent custody copies and authenticated version history.
If both DB and independent journal/pins are rolled back by a compromised host/root,
this architecture cannot detect it without a genuinely separate witness; that is
an explicit residual risk requiring owner acceptance or a stronger deployment.

Emergency recovery freezes new authority, fences old coordinator/signers, preserves
DB/journal/audit evidence and verifies independent checkpoint copies. A quorum
approves a precise recovery bundle. Restore original missing audit/evidence rather
than rewrite/re-hash it; if completeness cannot be established, the affected tenant
stays disabled. A new incarnation is not permission to reset revisions, resurrect
revoked grants or discard history. Unrecoverable loss needs a separate migration/
incident decision, not a fabricated trusted state.

Compromised issuer: mark it revoked in the quorum-approved manifest and tenant
revision protocol, invalidate its dependent receipts/authority and checkpoint the
change before release. No waiting for its token TTL. Root rotation: old quorum
signs the new root-set/version/activation intent; new quorum acknowledges; freeze
publication during transition; independently reverify/re-attest current state under
the new pin, retain old proof history and retire old acceptance. A compromised root
quorum cannot repair itself cryptographically; independently controlled custody/
recovery approval and manual re-anchoring are required, or remain NO-GO.

Record root/recovery/rotation intents and signatures in the outside journal and
append sanitized matching events through the existing DB audit writer when DB
integrity permits. Neither log is evidence of the other's completeness without
verification. Signing keys, recovery codes and raw ceremony secrets are never audit
fields. Custodian availability and operational ceremony time are real costs.

### Decision matrix

| Field | D01 recommendation |
| --- | --- |
| Decision ID | D01 |
| Problem | No independent production root, issuer enrollment or restore/rollback verifier exists |
| Options | Single offline root; two-of-three offline quorum; hardware-backed custody, with the restore options compared above |
| Recommendation | Quorum root plus separate issuer/checkpoint keys, protected off-DB pending/checkpoint journal and full state commitment |
| Rationale | Local-first, no external service; avoids DB self-trust and row-omission blind spot; availability sacrificed on ambiguity |
| Dependencies | D02 attribution; D03 independent storage/roles; D04 canonical state and envelope; tests C01/C02/C06 |
| Risks | Host/quorum compromise, shared backup control, journal loss, signing-service compromise, publication gaps and full-state capacity |
| Approval required | Named three custodians/two-person quorum; key custody/recovery policy; independent storage/control; trust boundary excluding simultaneous host/journal compromise; publication/recovery state machine |
| Acceptance criteria | Independent pins; distinct signers; no bootstrap circularity; rollback/omission/crash tests fail closed; no root private key in runtime/DB/Git; ambiguous restores stay disabled |
| Status | PROPOSED |

## 4. D02 — human/operator authentication

### Options

| Approach | Benefits | Risks/dependencies and recovery |
| --- | --- | --- |
| Local OIDC identity provider with phishing-resistant MFA | Local-first, established login/MFA/session mechanisms; no cloud dependency | Protected IdP deployment/signing keys/backups and local operations required; IdP outage denies; MFA recovery must be separately controlled |
| External OIDC provider | Established administration, MFA and lifecycle integrations | Network/provider dependency, sovereign availability and tenant mapping risks; cannot meet disconnected privileged login needs without an independently designed local path |
| Direct hardware-backed administrator authentication | Local user presence, minimal identity service for very small installations | App would need secure enrollment/challenge/session/recovery implementation; hardware authenticates a key, not tenant membership or permission; custom-auth burden |

Recommend a **locally deployed OIDC provider with WebAuthn-based MFA**, integrating
an established provider rather than inventing an identity service in IAM. No
vendor/package is selected or installed here; exact provider/version, local origin,
TLS trust, signing-key lifecycle and deployment need owner approval. External OIDC
is a later explicit deployment option; direct hardware authentication is suitable
for offline root ceremonies but not a shortcut around application sessions.

Enrollment binds exact trusted OIDC issuer and immutable subject identifier to a
HUMAN principal UUID and explicitly approved tenant enrollment. Email/display name,
IdP groups, tenant URL parameters and role claims do not grant IAM authority.
Enrollment is root-approved until an authorized control-plane workflow exists;
self-registration produces no active tenant membership or administrator role.
Separate authenticated service/workload identities use their own credential/source
proof, never a claimed HUMAN kind or a browser session generated from an API key.

Validate exact issuer/audience, signature/algorithm/key pin, nonce/state/PKCE,
expiry/not-before and required authentication assurance. Do not accept bearer tokens
from arbitrary issuers/discovery URLs or a token's key URL. Browser sessions should
be opaque, server-revocable, securely transported, HttpOnly and CSRF protected.
Proposed baseline: 15-minute idle timeout, eight-hour absolute lifetime; fresh
WebAuthn step-up within five minutes for privileged operations, with a single-use
exact-operation challenge expiring in 60 seconds. These are approval proposals,
not changes to existing IAM validity limits or guarantees from timestamps alone.

Session issuance/liveness/revocation needs a **durable session record** managed by
the identity boundary, including principal/issuer/subject, internal session UUID,
authentication time/assurance, expiry, revocation generation and enrollment binding.
IdP/session storage is outside the proposed authority-table count. Its schema,
protected access and precise OIDC adapter are a separate implementation prerequisite;
no missing sessions table is assumed to exist. Never use process memory alone or
an unexpired self-contained JWT as proof that the session has not been revoked.

For privileged gates require a fresh authenticated session-state attestation and
current tenant/principal authority. Logout/session/subject compromise first denies
new identity attestations, then serializes relevant authority invalidation with
all affected tenant gates before acknowledging **completed** revocation. Existing
gates are ordered before completed revocation; no promise of interrupting earlier
work. Partial propagation or unavailable session-state verification denies new
gates. IdP back-channel logout is authenticated input to this protocol, not a
magically atomic transaction with PostgreSQL; delayed/missing notification means
no unconditional immediate IdP-revocation guarantee. Initial profile has no online
human protected operations. Human operational rollout requires fault/concurrency
tests of this acknowledgement boundary, including multi-tenant session invalidation.

### Required binding and audit attribution

| Binding | Protected source and checks |
| --- | --- |
| Tenant | Explicit rooted enrollment plus current active tenant/principal; never inferred from successful IdP login |
| Principal | Stable issuer/subject mapping, approved kind and current state; transient browser session UUID is distinct from enrollment identity |
| Issuer | Separate current D01 manifest authorization for source/record purpose/role ceiling; authenticated human is not automatically a trusted issuer |
| Requested operation | Session/step-up proof binds exact canonical operation/request/resource/parameters digests, tenant, requester and executor, nonce and expiry |
| Approval | Independently authenticated HUMAN distinct from requester/executor, exact operation/resource and current approval authority; single-use workflow proof supplements existing non-executable ApprovalRecord |
| Audit actor | Existing service/system emitter identity; bounded verified human/session/issuer/intent references and assurance metadata in details; no tokens, passwords or recovery material |

`AuthenticationReference(method='SESSION')` can represent a session UUID but lacks
OIDC issuer/subject, assurance and session-generation evidence. Do not repurpose a
stored enrollment reference or random UUID as a live session. D04 proposes an
internal verified identity sidecar and explicit projection, leaving IAM-01 pure
semantics intact. Human issuer authentication at issuance is different from the
requester's session being live now; logout alone does not retrospectively forge or
reissue signed grants. Revoking the issuer principal/key invalidates its authority.

Break glass is a quorum-approved, local, bounded recovery ceremony with strong
custodian authentication, exact tenant/action and preserved audit. It may freeze
or recover the identity/control plane; it is not an all-powerful unaudited browser
login, offline password fallback, MFA bypass or automatic grant. If quorum cannot
be met, remain unavailable. Account/MFA recovery requires independently verified
enrollment and dual control; revoke old sessions/authenticators, re-enroll explicitly
and audit before new privileges become usable. IdP administrators cannot thereby
replace the root set. Hardware loss does not justify weaker automatic fallback.

| Field | D02 recommendation |
| --- | --- |
| Decision ID | D02 |
| Problem | Existing authentication supports API keys, not verified human enrollment/MFA/session/recovery |
| Options | Local OIDC/WebAuthn; external OIDC; direct hardware-backed app authentication |
| Recommendation | Local OIDC/WebAuthn with durable revocable app-session verification, explicit tenant enrollment and exact-operation step-up |
| Rationale | Reuses identity mechanisms while preserving deterministic IAM grants; supports disconnected local operation |
| Dependencies | D01 root enrollment/recovery; D04 identity sidecar/admission extension; session storage and revocation protocol; C03/C04/C07 |
| Risks | IdP/host/key compromise, session theft, revocation propagation gaps, custom adapter errors and quorum availability |
| Approval required | Provider/deployment/origin/key trust; MFA/recovery policy; timeout/step-up proposals; durable session boundary; human-emitter attribution; completed-revocation semantics |
| Acceptance criteria | Login alone grants nothing; wrong tenant/kind/assurance denies; stolen/revoked sessions fail gates; exact approval separation; no root authority from IdP admin status |
| Status | PROPOSED |

## 5. D03 — isolated PostgreSQL verification and privileges

### Options

| Approach | Benefits | Risks / suitability |
| --- | --- | --- |
| Rootless disposable container/cluster, private Unix socket | Small local-first lab; no published network; separate empty data volume and generated test-only identities | Container/runtime availability and exact mount/socket attestation needed; host administrator remains trusted |
| Dedicated disposable VM/OS namespace/host | Stronger separation of volumes/processes and service reachability | More resources/setup/recovery; appropriate if container isolation cannot be convincingly attested |
| New schema/database in an existing operational cluster | Cheap setup | Rejected: shared roles/server/volumes and risk of either protected database being reached; not adequate isolation |

Recommend **a rootless disposable PostgreSQL 16 instance**, using an already
available approved image/binary, network disabled and a private Unix socket mounted
only into the approved test harness. No image pull, installation, container creation
or PostgreSQL command is authorized here. A separate VM is the fallback if these
properties cannot be enforced, not an automatic downgrade to an existing cluster.

Use one exact owner-approved name under `ai_soc_iam03d_disposable_<run_id>`; prefix
matching alone is insufficient. Protect ai_soc and ai_soc_test from even connection
attempts. Use a fresh lab-only volume, socket directory, credentials and independent
run manifest; no production mounts/backups/.env/.pgpass/service files, default DSNs,
Wazuh/Ollama/IdP endpoints or production signing keys. Synthetic identity/signing
fixtures exercise algorithms without pretending to be operational authority.

### Preflight before migrations/tests

1. Require exact run manifest and explicit opt-in, approved cluster/container ID,
   isolated data-volume/socket paths/ownership, non-production database name and
   allowed credential sources. Reject symlink/path escapes, existing volume reuse,
   published TCP, unexpected mounts/network and protected names before connection.
2. The trusted lab launcher independently attests that the private socket belongs
   to the approved new server process/instance and empty lab volume. A marker row
   supplied by the target DB cannot attest its own isolation. If host/process/socket
   identity cannot be established, stop without probing another server.
3. Parse only injected lab connection data; clear/deny fallback PostgreSQL environment
   and user service/password files; never import app.db/settings/.env to obtain it.
   Do not echo DSNs or credential values. No connection is attempted until 1–2 pass.
4. Connect only through that socket, then compare actual database, login, version
   and launcher/server identity with the pinned manifest before DDL/DML. Report
   comparisons, not secrets. Missing/mismatched identity stops; no retry elsewhere.
5. Separately authenticate each real nonowner role. Test owner/migrator privilege
   only in the authorized lab; administrator SET ROLE is not proof of runtime-login
   authentication or isolation. Record schema revision/constraints/RLS before cases.

The current RolePlan and database tests accept existing protected database names;
AGENTS.md generally requires ai_soc_test. Owner must approve a **specific future
lab-harness/guard exception**, preserving all existing guards. Do not change their
whitelists globally, disable checks, or run their DB suites against a renamed URL.
Current migrations/env.py settings wiring also needs an approved injected-connection
path. That is future implementation, not an instruction to run Alembic now.

### Proposed role matrix

| Role | Allowed | Explicitly denied |
| --- | --- | --- |
| Lab migration owner | NOLOGIN schema/table/function ownership; trusted migration capability reached only by dedicated deployment login | Serving app/reader requests; automatic runtime inheritance |
| Lab migration login | Explicit bounded SET access to lab owner and DDL for approved synthetic schema | Operational clusters/credentials; membership administration outside lab |
| Runtime application/executor | Tenant-specific existing business privileges and exact final-gate reads; narrowly reviewed tenant lock/audit staging access | Authority DML, owner/BYPASSRLS/SUPERUSER, arbitrary SET ROLE, root command EXECUTE |
| Read-only authority provider | Tenant-specific projected authority reads; forced RLS; dedicated read-only transactions | DML, raw key hashes, schema creation, writer functions, lock-column UPDATE |
| Authority mutation coordinator | Tenant-bound restricted command EXECUTE plus required existing audit writer access; signed intent validation | Arbitrary authority DML, role ownership, other-tenant/root commands without exact root capability |
| Test harness | Read metadata/fixtures via dedicated capability; run application cases using their real logins | Automatic superuser app login, operational targets, broad privilege grants to make tests pass |
| Lab bootstrap administrator | Only separately approved initialization/role provisioning in the attested fresh instance | Application use; persistence or permissions outside disposable run |

All runtime logins lack SUPERUSER, BYPASSRLS, ownership, role administration and
cross-tenant memberships. FORCE RLS policies and tenant composite FKs both apply;
fixed tenant role bindings cannot be replaced by attacker-set GUCs. SECURITY DEFINER
commands, if approved, use fixed search_path/schema references and authenticated
session_user binding, not the owner current_user. No PUBLIC/default privilege leak.
PostgreSQL row-lock SELECT requires UPDATE privilege: existing created_at locking
grants permit actual timestamp changes and must be narrowly assessed for the final
gate, never casually granted to the read-only provider. No DB permissions are changed.

Future teardown first fences clients/stops the lab, records synthetic results and
verifies exact instance/run/volume identity. Deleting volumes/roles/data requires
explicit destructive-cleanup approval; otherwise leave an isolated stopped lab.
Never run broad cleanup commands or assume rollback authorizes object destruction.
Lost test credentials mean discard/recreate only after approval, not reuse production
credentials. Preserve real project/Git work and any audit evidence required for review.

| Field | D03 recommendation |
| --- | --- |
| Decision ID | D03 |
| Problem | No approved disposable target/privileges; existing guards name protected databases |
| Options | Rootless private-socket cluster; dedicated VM/namespace; reject reuse of an existing cluster |
| Recommendation | Exact attested rootless instance/database/volume plus split real-login roles; VM if isolation cannot be attested |
| Rationale | Prevents default/incorrect target use and verifies effective least privilege without broad application superuser rights |
| Dependencies | Owner lab exception/setup authorization; D01 test trust material; D04 reader/gate protocol; C05/C08 |
| Risks | Host/bootstrap privilege, false launcher attestation, socket/mount reuse, overly broad owner/definer access |
| Approval required | Exact target/runtime/image availability, naming/guard exception, socket/volume/network boundary, role/function plan and separate setup/cleanup operations |
| Acceptance criteria | Protected names rejected before connection; independently attested target; actual nonowner logins prove RLS/FKs/forbidden DML; no service/production credential dependency |
| Status | PROPOSED |

## 6. D04 — production provenance and admission contract

### Options and recommendation

| Approach | Benefit | Defect / trade-off |
| --- | --- | --- |
| Broaden existing synthetic type gate or relabel for_tests objects | Small diff | Rejected: converts a fixture/identity registry into supposed real provenance; violates existing security semantics |
| New explicit production proof/result contracts inside canonical IAM, reusing pure validation/evaluation | Keeps source authenticity distinct from parsing; synthetic and production remain separate | Requires reviewed versioned contracts, source/verifier implementation and parity/negative tests |
| Independent authorization service returning signed bearer decisions | Process separation possible | Extra infrastructure and replay/TOCTOU surface; can duplicate IAM-02; not justified for initial local-first profile |

Choose **explicit production proof contracts** within existing canonical modules,
not another IAM package or permission evaluator. Preserve IAM-01/02 catalogs,
fail-closed graph validation and policy semantics; leave current IAM-03A/B types,
synthetic constructors and exact synthetic gate unchanged. A separately reviewed
production admission entry point may share extracted pure checks while requiring
real protected identity/source proof. Implementation requires its own authorization
and tests; it is not a switch that makes current PostgresAuthorityProvider trusted.

### Intended flow and trust ownership

```text
Protected authentication (key or approved human session)
 -> independently pinned issuer/source/profile
 -> tenant-scoped persisted records
 -> dedicated consistent primary read
 -> complete-state + issuance provenance verification
 -> fresh revision/checkpoint/revocation/session verification
 -> non-executable production snapshot and protected admission
 -> unchanged IAM-02 evaluation
 -> separate fresh execution-time gate
 -> DENY, or exact authorized operation inside the approved boundary
```

The request supplies operation/action/resource/parameter digests, never provider,
keyset, source connection, verifier, tenant ownership, epoch or trusted flags.
Authenticated principal and source registration come from protected composition.
A production API-key proof cannot rely only on the two UUIDs returned by today's
authenticator: a DB administrator could replace its stored key_hash. At explicit
root-approved key enrollment, bind tenant/key ID to a credential_binding_digest
of the existing key verifier using a versioned domain-separated encoding. The
protected authentication boundary checks the presented key using the existing
hash utility against that independently signed binding, as well as current key
ownership/revocation. Raw key/verifier values stay in the authentication boundary,
never in snapshot projections, logs or authority responses. Merely double-hashing
an unapproved DB value does not establish a binding. This proposed production
attestation/check and persisted digest require A04/A05 review; existing auth code
and endpoint dependencies are unchanged and not claimed DBA-resistant today.
The source connection must be independently authenticated/pinned, tenant-bound,
read-only and least privilege. Observer labels, row presence and coherent SQL are
not proof of issuer authenticity. Current PostgreSQL reader still returns no snapshot.

### Proposed evidence formats and future changes

These are non-executable protocol specifications, not implemented Python types:

| Proposed proof | Required bindings and validation |
| --- | --- |
| RootManifest/v1 | Root version/digest, tenant/source/incarnation, profile and approved policy digest, custodian/issuer/verifier/checkpoint public keys and scope; two distinct authorized custodian signatures; authenticated protected pin, no row-provided root |
| IssuanceRecord/v1 | Tenant, source, record purpose, subject/issuer IDs, canonical IAM issued-record digest, finite source validity, issuer authentication/authorization evidence at issuance, role ceiling, root/key version and signature domain |
| AuthorityState/v1 | Tenant/source/provider/incarnation, schema/profile/canonicalization versions, exact monotonic BIGINT revision, persisted epoch UUID, policy/root digests and complete-state digest; signed revision-event/audit-prefix linkage |
| Checkpoint/v1 | Exact AuthorityState and event/audit anchor, pending/committed journal state and checkpoint signer identity authorized by independent root; no fallback to an old checkpoint on failure |
| VerifiedIdentityContext/v1 | Key UUID/ownership plus independently approved credential-binding proof, or stable human issuer/subject enrollment + transient internal session UUID/generation/current-state proof, principal kind/tenant, trusted evaluation time, assurance/step-up and exact request/operation bindings |
| VerifiedAuthorityRead/v1 | Protected provider/source registration; identity-context digest; immutable checked IAM graph, request/operation/policy/state digests; verified issuance/root/checkpoint references; transaction observation and freshness result; no client-set authoritative booleans |

Canonicalization uses versioned, domain-separated canonical bytes; existing IAM
issued-record bytes/digests retain IAM-01 canonical_bytes/contract_digest exactly.
New state encoding sorts table groups and full tenant-qualified PKs, encodes types,
NULL and UTC times unambiguously, uses bounded lengths and no floats/unknown fields.
The **complete-state digest** covers head identity/profile/policy pins and normalized
current/historical authority records, object registry and tombstones, including
signed source receipts and approved credential-binding digests, plus projected
existing tenant/key/backing-resource identity and key revocation fields needed by
the profile (never raw key_hash). Exclude revision ledger signatures/event/state-digest fields,
audit rows and external checkpoint/pending records from that digest to avoid cycles;
the signed outer event binds their revision/audit linkage separately. Receipt
content cannot include a signature over itself. No second audit hash algorithm.

Future schema review must specify state_digest fields on head/revision and exact
row serialization. They are additions to the proposed schema, not existing columns
or approvals of that earlier design. An initial verifier must read/hash the **whole
tenant authority state** under one consistent view before deriving the requested
graph; request-subset hashes cannot prove absence of a revocation. Proposed initial
state-byte ceiling is 262,144 bytes, checked incrementally with bounded fields and
query deadlines; overflow denies. This reuses the existing evaluator's aggregate
budget magnitude but is a separate approved profile limit, not a silent contract
change. Preserve existing snapshot caps as well. Hashing cost/tombstone growth may
require later approved authenticated state proofs; no automatic truncation or
unreviewed Merkle-proof implementation is proposed.

Signatures require exact authorized key ID/algorithm/tenant/source/purpose, current
root/issuer scope and role ceiling, exact canonical digest and validity; verify with
independently pinned distribution. Public keys in rows must match root-authorized
keys. Reject unknown versions/algorithms, duplicate signers, invalid signatures,
contradictory proofs and fabricated flags. Key rotation/revocation requires explicit
D01 transition and revision invalidation, not automatic acceptance of old material.

### Validity, identity and admission compatibility

Long-lived source issuance evidence must not be relabeled as a fresh signed IAM-01
receipt by editing timestamps. Recommend that protected production verification
produce a new short-lived **verification attestation** after checking the original
immutable signed record and current root/issuer/revocation/state. It may then
construct existing runtime IssuanceEvidence/IssuerAuthority inputs with a window
contained in all source/actor limits and no longer than 300 seconds; the new proof
binds that exact projected contract digest. The original source signature remains
associated with the original bytes, not falsely claimed to sign the projection.
If source proof or current issuer authority expired/revoked, deny; do not refresh it.

Keep snapshot window <=60 seconds, exact evaluation-time binding, revocation
observation age <=15 seconds, and <=300-second verifier/anchor/receipt bounds.
Expiration is the minimum of these ceilings and all relevant principal/key/session/
issuer/receipt/approval/source lifetimes. Age limits supplement durable current
state; they never replace it. Validation uses protected aware time; future/stale
observation or unavailable clock proof denies. Decisions remain executable=False.

Stable human enrollment and transient session proof are distinct. Future human
snapshot projection must bind the acting principal's AuthenticationReference to
the independently verified current session, without changing stable principal ID
or manufacturing another issuer's live session. Historical issuer authentication
is verified at issuance with current issuer-principal/key revocation checked now;
requester session liveness is checked now. Existing ApprovalRecord requires the
exact trusted approver/operation representation: changed approver grant references,
authentication binding or resource metadata requires denial/new approval, not a
rewritten original approval. OIDC/assurance/session-generation sidecars and their
persistent identity binding need explicit new contracts/storage before human rollout.

Required future interface changes: production equivalents of ProviderSnapshot,
AuthoritySnapshot, admitted/outcome classification and protected identity/source
registration; explicit persisted revision/state/checkpoint proof; real session/
transaction observer; trusted verifier-to-admission handoff; short-lived projection
attestation; and a separate execution-gate transaction contract. Do not widen the
current Literal classifications, accept a Protocol-shaped arbitrary object, reuse
SyntheticOriginRegistry operationally, or add a human bypass to current key-only
admit. Extracted shared validation must preserve tenant/issuer/grant/approval failure
precedence and exact IAM-02 behavior. Pure IAMSnapshot/policy contracts remain 1.0;
new source/proof envelopes carry their own version. Owner must approve any later
necessary contract/schema change explicitly; none occurs here. In particular,
production human admission consumes principal_id plus verified session reference;
it must not fabricate an api_key_id to satisfy the current key-only admit/read
interface. The existing API-key identity mapping and endpoints stay unchanged.

### Revision, revocation and execution race

Read-only REPEATABLE READ gives coherence, not current authority. Observe actual
transaction/read-only/isolation/source through a protected dedicated wrapper, read
complete state and verify signatures/checkpoint. Current cleanup rolls back that
read transaction; caller closes. A separate fresh committed primary read checks
that tenant/source/incarnation/root/profile/revision/epoch/checkpoint remain equal
and no publication/session invalidation is pending. Unknown epoch denies. UUID is
an opaque persisted lookup handle, not a monotonic counter or provenance proof.

An ALLOW at that point is provisional and non-executable. Final same-DB action:
start a distinct READ COMMITTED write transaction, take existing tenant FOR NO KEY
UPDATE lock then head lock, obtain fresh identity/session/checkpoint/provenance and
exact resource/approval state, re-evaluate IAM-02, lock/version-check affected domain
rows, perform exact business action and existing audit, and hold tenant lock through
commit. All authority/resource/key/session invalidation writers must use the same
ordering/protocol; old direct writers invalidate the guarantee. Never call the
current rollback-owning reader inside that business transaction.

| Race | Required result |
| --- | --- |
| Revocation commits/publishes before final gate acquires lock | Fresh state rejects revoked authority; old ALLOW discarded |
| Gate owns lock first | Gate completes/aborts before revocation can commit; no promise to undo earlier work |
| Revision/root/profile changes during read/admission | Discard snapshot and fully reauthorize or deny; never reuse old permissions |
| DB commit succeeded but checkpoint/session revocation publication is pending | Deny new gates until verified reconciliation; do not claim distributed atomicity |
| Gate crashes, times out or loses commit acknowledgement | Rollback or reconcile UNKNOWN outcome by immutable operation ID; no blind duplicate action |
| Queue/other process/external service | No bearer ALLOW; revalidate at dispatch plus explicit resource-side fencing/idempotency. External actions remain disabled until an approved IAM-04 protocol exists |

The guarantee is ordering against **completed protocol revocation**, not cancellation
of running work, an IdP notification before propagation, arbitrary DBA writes, or
atomicity with a remote system. Different processes must share the same database
locks and authenticated identity/publication state; process-local mutexes alone
are insufficient. The initial single-host coordinator restriction must be enforced,
not silently extended to distributed writers/failover. Validity is checked at final
gate/start; a transaction is not magically rolled back by wall-clock expiry.

Map invalid origin to existing admission UNVERIFIED_ORIGIN, stale/current-state
failure to REVOCATION_UNVERIFIED or STALE_SNAPSHOT as appropriate, malformed graph
to RECORDS_INVALID and evaluator errors to POLICY_FAILURE. Adapter input/read/
cleanup categories remain stable. Any new public reason requires explicit contract
review. Errors/audit contain only established IDs/digests/reason codes; no SQL rows,
driver text, keys, tokens or proof payloads. Missing audit capability denies mutation;
failed-attempt logging cannot be promised during complete DB failure.

| Field | D04 recommendation |
| --- | --- |
| Decision ID | D04 |
| Problem | Current provider/admission are synthetic-only, missing authenticated source/state/session proof and execution-time coordination |
| Options | Reject relabeling fixtures; explicit production proof contracts/reused pure validators; independent authorization service deferred |
| Recommendation | Versioned production envelopes, complete-state checkpoint verification, protected identity sidecar and separate final DB execution gate |
| Rationale | Preserves deterministic IAM-01/02 semantics and synthetic denial barriers; closes omission/TOCTOU gaps within an explicit trust boundary |
| Dependencies | D01 rooted keys/journal; D02 identity/session protocol; D03 real read/write isolation; initial profile/revised schema; C01–C09 |
| Risks | Serialization/projection bugs, full-state growth, skipped writers, identity propagation, trusted-host compromise and external effects |
| Approval required | Exact production type/handoff/version and canonicalization; runtime-attestation projection; state fields/budget; profile/resolver restrictions; final-gate and completed-revocation semantics |
| Acceptance criteria | No synthetic operational acceptance; complete authenticated state; old/mixed/missing proof denies; genuine nonowner isolation; admission/policy parity; revocation-race/rollback/audit tests passed before activation |
| Status | PROPOSED |

## 7. Cross-decision dependencies and circularity checks

| Relationship | Required consistency / rejected circle |
| --- | --- |
| D01 -> D02 | Root custodian enrollment is independently witnessed before IdP bootstrap; IdP administrators cannot mint root trust |
| D02 -> D01 | Later ceremonies carry independently authenticated operator intent, but changing IdP/session DB rows cannot replace the root quorum |
| D01 -> D04 | Root pins authorize exact signer/verifier scopes; keys returned by PostgreSQL cannot certify themselves |
| D04 -> D01 | State/event canonicalization and pending/reconciliation semantics make checkpoints meaningful; audit details contain mutation digest, not a circular event hash |
| D03 -> D04 | Real nonowner roles/primary reads/tenant locks prove DB boundaries; observer labels and SET ROLE fixtures are insufficient |
| D04 -> D02 | Identity generation/liveness and exact operation proofs need durable source verification; fresh snapshot timestamps alone cannot revoke sessions |
| Minimum profile -> all | Explicit metadata-only/teamless/no-online-admin restrictions must be pinned by root/schema/policy versions, not inferred when tables are missing |

Bootstrap does not require a pre-existing IAM administrator grant: the independently
approved root ceremony is a distinct trust-establishment action with explicit scope,
not a new global-admin role. Once root-controlled initialization ends, ordinary
online role administration requires verified human roles.assign authorization and
independent approval. The minimum profile deliberately does not enable that path.

The earlier schema calls deferred relations optional at some points while leaving
FKs to them in its table specification. The companion review makes the required
restricted-schema/FK changes explicit; none is silently edited in the old design.
No decision is accepted merely because another unapproved decision assumes it.

## 8. Threat/failure analysis and future verification

These are proposed tests, **not run**. Existing denying-adapter tests are not proof
of the new protocols. Case IDs are shared by the approval and sequencing sections.

| Case / threat | Preconditions and impact | Required controls | Residual risk / future verification |
| --- | --- | --- | --- |
| C01 — Compromised root / unauthorized issuer | Stolen custodian quorum or mutable root pin could authorize arbitrary trust | Distinct offline custodians, protected pins, exact quorum/signature scope, root rotation freeze and recovery evidence | Quorum/host compromise remains critical; test missing/duplicate/old root signatures, unauthorized issuer/key/scope, and rotation continuity |
| C02 — DB rollback / missing audit / omission | DBA/restore replays old graph or removes tombstones/tail while preserving plausible counters | Off-DB latest checkpoint, complete-state digest, pending quarantine, audit-prefix verification and independent restore custody | Co-rollback of host/journal not detectable locally; test every crash state, missing revocation, old full image and lost audit; never accept internally consistent old chain alone |
| C03 — Forged admin / cross-tenant privilege | Valid IdP token or group claim misbound to victim tenant/root | Exact issuer/sub/audience/MFA, rooted enrollment, no login-to-role inference, independent approvals | IdP/adapter compromise; test fake issuer, same email, wrong tenant, service-as-human and root/admin confusion |
| C04 — Stolen session / recovery abuse | Copied active session or weak reset bypasses assurance | Durable revocation generation, operation-bound step-up/nonce, dual-control recovery and completed-revocation acknowledgement | In-flight work/notification delay; test revoked/expired/replayed sessions, lost factors, partial multi-tenant revocation and inability to obtain quorum |
| C05 — Incorrect DB target | Default URL, stale volume/socket or spoofed marker hits protected cluster | Independent launcher attestation plus exact pre/post-connect checks, no app/env fallback, protected-name rejection | Trusted-host compromise; test wrong name/server/mount/socket/symlink/env and ensure no connection attempt to either protected database |
| C06 — Concurrent revocation / stale replay | Grant/root/session changes between verified read and action | Shared tenant lock through same-DB commit, fresh full proof, pending journal denial, no bearer allowance | External effects unsupported; barrier-test both lock orderings, issuer/key/profile replacement and publication gaps |
| C07 — Missing audit / inconsistent transaction | Exception or disconnected commit leaves uncertain authority | Same DB mutation/revision/audit transaction, deferred links, immutable operation ID, explicit UNKNOWN recovery | DB-wide outage prevents audit-only failure writes; inject failure at every stage and reject omitted/mismatched audit or partial head |
| C08 — Excessive privileges / tenant injection | Runtime owner/bypass rights or client GUC escapes tenant | Forced RLS, tenant composite FKs, real split logins, restricted function EXECUTE, safe definer/session_user and no PUBLIC leak | Owner can disable DB controls; root/state proofs limit authority forgery but not availability; test real-login forbidden DML/role switch/query leakage |
| C09 — Fabricated/mixed source / semantic drift | Malformed rows or changed projection accepted as verified production input | Exact types/versions/bounds, source proofs, complete-state hash, exact IAM-01/02 validation parity and synthetic separation | Trusted verifier bug/process compromise; mutate every proof field, timestamp, graph component, stored key verifier versus independent credential binding, and approval digest; exceed bounds and assert no ALLOW |
| C10 — Deferred feature escalation | Reduced schema omits teams/approvals but accepts related authority anyway | Pinned initial profile, explicit disabled features, supported catalog/action intersection, dependency-closed reduced DDL | Future profile expansion needs full review; test team/raw/export/admin/approval-dependent/unknown-resource requests deny even with plausible records |

## 9. Human approval checklist — nothing approved here

| ID | Explicit owner decision to record before implementation |
| --- | --- |
| A01 / D01 | Approve two-of-three named distinct custodians, key custody/signature profile, quorum loss/root compromise response, independent journal/pin storage and crash/restore protocol; accept the stated host-compromise limitation or choose an independent witness instead |
| A02 / D02 | Approve local IdP/provider deployment and trust, WebAuthn/MFA/recovery, explicit tenant enrollment, durable session/identity sidecar, proposed timeouts and completed-revocation/audit-attribution semantics |
| A03 / D03 | Approve exact new disposable run identity, independent instance/socket/volume/network proof, dedicated test credentials and split privileges, specific AGENTS test-target exception and future injected-connection harness plan |
| A04 / D04 | Approve new production proof/admission/gate contracts, canonicalization and state commitment, bounded runtime attestations, signature distribution and state verification budget; preserve existing pure semantics and reject synthetic conversion |
| A05 / profile | Approve the companion 16-table restricted initial authority profile and explicit future replacement/deferral of the specified relations/FKs; accept that this is not general-purpose or operational IAM |
| A06 / execution | Separately authorize each implementation phase, environment setup/migration/role operation and any destructive teardown; architecture approval alone does not authorize credentials, migrations, IAM-04, commits, pushes or deployment |

Approval record should identify exact document revision/content digests, selected
options and exceptions, owner identity/date, action scope and remaining conditions.
No ambiguous conversation, historic broad project approval or proposed status is
sufficient. Record rejection/alternative selection just as explicitly. This package
does not create that approval record or name custodians on the owner's behalf.

## 10. Implementation acceptance criteria

Before any implementation milestone: authoritative owner acceptance of the relevant
A items, exact changed-file scope and recovery plan; all required identity/trust
sources and proof formats specified; reduced-schema dependencies reviewed; no
unknown security field defaulted. Key generation, IdP deployment and DB setup each
retain separate explicit authorization. Production IAM remains disabled throughout
foundation/prototype phases.

Before any source becomes operational: D01 journal/restore/omission tests, D02
identity/session/recovery tests, D03 actual isolation/privilege tests, D04 snapshot/
projection/gate parity and race tests, audit atomicity and C01–C10 feature-negative
tests must pass with no hidden exclusions. Current false currency and synthetic
provider gate cannot be changed as a side effect of installing tables.

## 11. Recommended sequence after approval — not started

| Phase | Scope and dependency | Stop condition |
| --- | --- | --- |
| P0 — owner decision record | A01–A05 selected explicitly; review exact protocol/schema/profile amendments | Missing/ambiguous approval, unavailable independent custodians/storage or unacceptable residual risk |
| P1 — trust/proof offline foundations | Implement canonical envelopes/journal state machine with synthetic test keys only after code authorization; no operational bootstrap | Self-trust, rollback/omission acceptance, signature cycle, ambiguous recovery returning ALLOW |
| P2 — human identity boundary | Approve provider/session storage/mapping first; implement offline adapter tests and only separately authorized local IdP/enrollment/custody setup | Login implies permission, service claims HUMAN, missing revocation/step-up/recovery attribution |
| P3 — minimum schema specification/implementation | Approve revised 16-table profile and FK/field changes; create reviewed future migrations only under separate scope | Dangling deferred references, default grants, fabricated enrollment, authority/audit integrity gap |
| P4 — provenance verification | D01 source/issuance/state/checkpoint verification and restricted source composition; D03 harness ready | Missing/unknown proof or DB-only anchor, unbounded/partial-state acceptance |
| P5 — snapshot/admission contract | Approved new production types and exact short-lived projection, reusable pure checks/IAM-02 parity; keep existing synthetic path separate | Semantic drift, silent timestamp re-signing, unsupported feature/identity or fixture activation |
| P6 — revision/revocation/gate implementation | Common writer/coordinator/lock/audit/UNKNOWN protocol; initially fake/offline tests, no external effects | Any alternate writer, mixed transaction, stale allowance or unacknowledged identity/publication state |
| P7 — IAM-03D isolated verification | Exact approved target/setup/roles/migrations; real restricted identities and all applicable C and existing V cases | Wrong target, privilege workaround, skipped integrity/concurrency case or unsafe recovery |
| P8 — IAM-04 operational integration | Separate approval after complete provenance/identity/DB evidence; exact API/business/gateway boundaries | No final gate, unsupported external fencing/cancellation, incomplete audit or scope expansion |

Root and identity bootstrap are separate ceremonies from code implementation. A
successful isolated test fixture is never an operational root or production identity.
General teams, approval workflows and broad role administration need the deferred
schema/identity features enabled and verified before that expansion, not after it.

## 12. Offline verification and operational decision

Only two documentation files are added. Source, tests, models, migrations, security
configuration, prior documents, unusual artifacts and Git index remain unchanged.
Checks: required prerequisite inventory, code/symbol/reference inspection, all
23-table classification/16-table dependency accounting, D/A/C/P identifier/link
consistency, no unfinished markers, new-file whitespace and git diff --check,
plus entry-hash/index preservation. No executable SQL, migration or approval record.

Validation performed: `python3 /tmp/iam03c-decisions/validate.py` passed all
23-table/16-retained accounting, four complete PROPOSED matrices, ten future threat
cases, six approval items, nine implementation phases, local links, canonical
symbol existence, unfinished-marker/whitespace and two-file scope checks.
`git diff --check` passed; because additions are untracked, their whitespace/final
newlines were also checked explicitly. Every pre-existing tracked/untracked input
hash and the index bytes match the entry manifest. These are static checks, not
SQL/FK execution, protocol model checking, crypto verification or evidence that
the proposed race/recovery guarantees have been implemented.

No tests rerun for documentation-only changes; this phase contains no implemented
Python behavior. Historical results remain 402 focused IAM, 1,936 selected offline
and 164 compiled files from preceding milestones. No new PostgreSQL, isolation,
concurrency, cryptographic, IdP or recovery verification is claimed. The 214 excluded
cases and unrestricted pytest remain unexecuted. No external service/tooling or
credential generation is needed to prepare this package.

**IAM-03C-D01-D04: COMPLETE — decision-package preparation only.**  
**D01: PROPOSED**  
**D02: PROPOSED**  
**D03: PROPOSED**  
**D04: PROPOSED**  
**SCHEMA IMPLEMENTATION: NO-GO**  
**OPERATIONAL IAM: NO-GO**  
**NEXT STEP: Recommendation only — owner review of A01–A05, then a separately scoped implementation authorization.**
