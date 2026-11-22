# B4 Gate 1 provisioning runbook

**Blocked on trusted provisioning and independent approval.** This runbook
does not authorize commands that open a database connection, provision
infrastructure, change PostgreSQL or Docker, or execute a migration.

## Prerequisites and custody

Assign an independent artifact and PostgreSQL security reviewer, an operator
who can issue Gate 1, a platform custodian for the protected launcher,
approval channel and stores, and database, PKI and credential custodians.
Use the [unsigned sign-off](b4-gate1-signoff.md) to record their independent
decisions. The [existing authorization package](b4-rehearsal-authorization-package.md)
defines the approval scope and separates Gate 2. Use the last observed Docker
tuple in the [review packet](b4-gate1-independent-review.md#proposed-exact-target-pin)
only as comparison evidence. Approval requires a fresh independent observation.

## Implementation and provisioning status

For every row, **independent approval is pending** and **production
provisioning is unverified**. The mocks used below provide no execution
authority.

| Dependency | Implementation and offline verification | Custodian action and configuration location |
|---|---|---|
| Protected approval record | `ProtectedInputs.load` and typed `Approval`. Scope, expiry and substitution cases are tested. | Platform custodian provisions a reviewed record service behind the protected bootstrap. No repository URL, service config or trust anchor is shipped. |
| Independent digest | `approval_pin` is a separate lookup. The caller compares the complete packet digest. | Independent reviewer deposits the approved digest in a separately protected and authenticated channel. Bind the record and pin to the same decision ID. Keep the trust anchor outside the working tree. |
| Durable replay | `reserve_once` uses exclusive creation, writes the run tag and fsyncs the marker and directory. Concurrent and replay cases are tested. | Platform custodian supplies the authoritative `replay_directory` path to the bootstrap. It must be supervisor-owned, mode 0700, durable, and under protected ancestors. No default path exists. |
| Frozen bootstrap | `execution_is_frozen` is mandatory and fails closed. Synthetic denial tested. | Platform custodian pins launcher, worker, interpreter, dependencies, Git and Docker binaries. Authenticate the immutable build before import. The bootstrap and executable deployment paths are external. |
| Process containment | `hold_freeze`, `start_worker`, `close_worker_scope` and the launcher deadline cover partial startup and timeout. | Register a durable, closed-by-default run scope before process creation. Bound startup and I/O, revoke admission, stop all descendants and prove the scope empty even without a process handle. Implement outside the repository. |
| PostgreSQL TLS | Worker supplies `verify-full`, exact `hostaddr`, approved IP identity and required SCRAM channel binding. Downgrade and identity failures are mocked. | PKI and database custodians provide a valid server certificate with IP SAN `127.0.0.1`, the reviewed CA bundle and compatible libpq settings. Provision only under separate approval. |
| CA validation | `Record.ca` and `Approval.tls_ca_sha256` bind exact bytes. The worker rejects mismatches and invalid CA syntax before connecting. | Put approved public CA bytes in the protected record and deliver the pin in the independently approved packet. Use no ambient roots or platform trust fallback. |
| Change freeze | `Record.freeze` digest is bound to the packet. The launcher requires a durable hold and gates release. Unresolved cleanup is tested. | Database custodian provides authenticated freeze evidence and an enforcing provider. Bind exact target, window and decision. Freeze administrative changes across both sessions and reconciliation. Hold on crash or uncertainty. |
| Backend monitor and recovery | `recovery_authorized`, `backends_gone` and `target_matches` are mandatory. Unresolved or late teardown prevents success in tests. | Separately approve an independent, read-only monitor against the exact pinned server. Reconcile both approved logins and run tag, plus PIDs and backend start times when available. Permit bounded post-expiry recovery separately. No privileged backend termination. |
| Restricted credentials | Worker accepts a process-local credentials map keyed by the two references in `Approval`. Exact target, login and no password-file fallback are tested. | Credential custodian injects existing scoped secrets through the isolated worker's protected transport only after verified admission. No .env, files, command arguments, logs, or chat. Never substitute administrator credentials. |
| Evidence storage | `evidence_ready` gates reservation. `store_evidence` accepts only the launcher-generated sanitized record and must return its exact SHA-256. Absent sink, bad receipt, late receipt and failed cleanup cases are tested. | Platform custodian provisions approved durable, append-only storage, access control and authenticated receipt transport. No sink path or URL is shipped. |
| Resource budgets | Typed `Budgets`, effective SQL timeouts, row/session checks and capped supervisor wait are tested. | Operator and reviewer approve exact limits and provider deadlines. The bootstrap must independently enforce process, result transport and recovery limits. |

## Provision the trust boundary

**Operator work after separate provisioning approval. Do not execute during
offline readiness.**

1. Establish independent reviewer identity and the reviewer-controlled
   approval channel in the organization's approved trust system. Pin its
   trust anchor in the protected deployment, independently from any packet
   or untrusted request. Configure revocation, expiry, access auditing and
   bounded lookups. Test with a separately authorized non-production
   fixture. Require rejection of an untrusted, mismatched, expired or
   revoked decision. Never derive a trusted pin from the submitted packet.
2. Bind the frozen build to the [current candidate](source-registry-execution-manifest.gate1-provisioning.candidate.json).
   Have the reviewer reproduce the inventory and verify exact interpreter,
   dependency artifacts and executable paths. The deployed bootstrap
   must expose only a decision ID. Provider instance, protected replay
   path, trust credentials, worker transport, monitor and evidence sink
   come from deployment authority. Reject arbitrary module or path input.
3. Establish the durable replay location and prove it survives restart and
   restore without losing consumed decisions. Use one authoritative
   namespace with protected ancestors. Treat any incomplete marker as
   consumed. Reconcile its run tag before issuing a new decision.
4. Configure the evidence sink for one immutable canonical observation
   per decision and run, with idempotent receipt for identical bytes and
   rejection of conflicting bytes. Return SHA-256 only after durable
   append, on authenticated transport. A receipt confirms persistence
   of observation bytes. It grants no approval and proves no final
   decision after expiry. Bound the record and response transport.
   Preserve the final launcher outcome and receipt reference in the
   protected decision record. Store no raw diagnostic, credentials,
   DSN, raw evidence, audit payload, or unnecessary backend identifiers.
5. Approve and enforce database-change freeze, process scope, and the
   independent read-only backend monitor before supplying secrets.
   Scope closure must prove that no worker can start later. The monitor
   checks absence on the pinned server and both login identities. A
   successful worker exit alone is insufficient.

## Safe verification commands

Run from the frozen repository root, with the independently verified
interpreter and tool paths. These commands do not contact PostgreSQL.

```bash
sha256sum docs/security/source-registry-execution-manifest.gate1-provisioning.candidate.json \
  docs/security/source-registry-execution-manifest.json
env -i PATH="$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=services/api .venv/bin/python - <<'PY'
from pathlib import Path
from hashlib import sha256
from app.database.source_registry_artifact import manifest_bytes

p = Path("docs/security/source-registry-execution-manifest.gate1-provisioning.candidate.json")
generated = manifest_bytes(Path.cwd())
assert generated == p.read_bytes()
print(sha256(generated).hexdigest())
PY
git diff --check
```

Expect candidate SHA-256
`f363e8cd585411834bf66ac0fb3c00862947fbaa40a1082c919fdbfca9086fc7`
and preserved approved SHA-256
`d829b2916ab5b1fd54fe9113fa7ef3784744aff68675cdd7b29b2338de008de5`.
The generator requires all 49 inputs, the ten-revision chain and 67
rendered statements at
`0fc91f8d8b76cf7e978603c5b998682a27bd77f4127516d1d85971439e880bf4`.
Stop on any mismatch.

An independently authorized Docker reader may run the following projected
inspection. It contacts Docker only. The output must exactly match the
separately approved container, image, network, publication and address pair.

```bash
docker --host unix:///var/run/docker.sock inspect --type container \
  --format '{{.Id}}|{{.Name}}|{{.Config.Image}}|{{.Image}}|{{.State.Status}}|{{json .NetworkSettings.Ports}}|{{range $name, $net := .NetworkSettings.Networks}}{{$name}}:{{$net.NetworkID}}:{{$net.IPAddress}}:{{$net.Gateway}} {{end}}' \
  ai-soc-postgres
```

A PKI reviewer can verify the supplied **public** certificate files locally.
Use the reviewed OpenSSL executable and paths selected by the custodian.
These placeholders denote public certificate files only.

```bash
sha256sum "$B4_REVIEWED_CA_FILE"
openssl x509 -in "$B4_REVIEWED_SERVER_CERT" -noout -ext subjectAltName
openssl verify -no-CApath -no-CAstore -CAfile "$B4_REVIEWED_CA_FILE" \
  -purpose sslserver -verify_ip 127.0.0.1 "$B4_REVIEWED_SERVER_CERT"
```

Expect the independently pinned CA digest, an explicit `IP Address:127.0.0.1`
SAN, and certificate verification `OK`. Supply any required reviewed
intermediate chain through the PKI custodian. These checks cannot establish
which certificate a live server will present. No live TLS probe is authorized
by this runbook.

## Activation and failure handling

**NOT AUTHORIZED TO EXECUTE.** The supported entry is the Python API
`source_registry_preflight_launcher.launch(decision_id, provider=...,
replay_directory=...)` through the independently provisioned protected
bootstrap. No CLI, deployment config file, general approval loader, or
provider implementation is shipped. The exact verifiable record,
`ProtectedInputs`, and outcome types live in
[the launcher module](../../services/api/app/database/source_registry_preflight_launcher.py).
`Approval`, `DockerPin`, `Budgets`, the worker's process-local credential
interface and sanitized report are in
[the worker module](../../services/api/app/database/source_registry_preflight.py).
Do not invoke the worker directly, the guarded migration runner, or Alembic.

Before issuing any worker request, obtain the authenticated Gate 1 approval
reference with the exact candidate, target, query and isolation pins, TLS,
identities, freeze, monitor, storage and protected delivery references.
Bind the approved validity window and separately authorized recovery scope.
Proposal only: two sequential sessions, 5 s connection, 5 s statement and
idle, 1 s lock, 1,000 rows, 60 s overall capped by approval expiry, and 5 s
bounded recovery. See the [existing budget proposal](b4-readonly-preflight-approval-packet.md#proposed-resource-budgets).
Only a timely `VERIFIED` with a verified evidence receipt, confirmed
containment and teardown, matching target and released freeze is success.

On denial, missing input, target drift or expiry, stop admission. On failed
or ambiguous startup, terminate or reconcile the durable process scope,
verify backend teardown independently, and recheck Docker. If any is
uncertain, keep the freeze and escalate through the approved recovery
channel. A storage error or ambiguous receipt prevents success. Preserve
the original outcome and reconcile by run tag through authorized read-only
access to the evidence store. Never replay the consumed decision. Require
a fresh authorization for retry. No database mutation, migration, recovery
restore, or privileged backend termination belongs to Gate 1.

## Linux provisioning automation

This section supersedes the earlier candidate pin and file-provider
availability notes. The
[Linux provisioning candidate](source-registry-execution-manifest.linux-provisioning.candidate.json)
has 53 entries and SHA-256
`ef2a34a42cfc0c65c44e095e66400e753a871a93bfcbff7c46523324e736869c`.
The approved manifest and earlier candidates are preserved. The DDL pin
and statement count are unchanged.

The [local inputs implementation](../../services/api/app/database/source_registry_local_inputs.py)
opens independently protected directory descriptors. The bootstrap verifies
ancestry and opens these descriptors before constructing a concrete provider.

- `/var/lib/ai-soc-b4/records/<decision-id>/` contains root-owned
  `approval.json` in the worker's typed approval shape, and the exact
  `isolation`, `ca.pem`, and `freeze` artifacts. No login secrets belong here.
- `/var/lib/ai-soc-b4/pins/` contains the independently reviewed Ed25519
  public key as `reviewer.pem`, a lowercase 64-byte
  `<decision-id>.pin` with no trailing newline, and the binary
  `<decision-id>.sig`. The reviewer signs the exact ASCII bytes
  `ai-soc-b4-preflight-pin-v1\n<decision-id>\n<pin>\n`. The verifier checks
  the key algorithm and uses a fixed reviewed OpenSSL executable.
  The private key stays with the independent reviewer. The authority
  must control revocation and separate packet publication from reviewer
  signature issuance.
- `/var/lib/ai-soc-b4/evidence/` stores one bounded observation per decision
  and run. Exclusive creation, file and directory fsync, and exact-byte
  receipt are enforced. Identical bytes are idempotent. A different
  observation or a partial file prevents a receipt. The approved supervisor
  must isolate this directory from worker and requester access. It must
  provide retention, incident reconciliation and any required immutable
  archival controls outside the filesystem API.

The local inputs class is abstract. The production bootstrap must still
implement frozen-executable verification, recovery authority, durable freeze,
worker launch and result transport, process scope closure, freeze release,
backend monitoring, and final target verification. Do not instantiate a
test subclass for operations. The local provider and archive preparation
perform no database connections.

Run the [provisioning script](../../scripts/provision_b4.py) in read-only
mode to reproduce the exact plan.

```bash
.venv/bin/python -I scripts/provision_b4.py --dry-run \
  --candidate docs/security/source-registry-execution-manifest.linux-provisioning.candidate.json \
  --candidate-sha256 ef2a34a42cfc0c65c44e095e66400e753a871a93bfcbff7c46523324e736869c
```

The observed plan SHA-256 is
`532572bdc8a68f0f4c443a3cee754576db7f991bffa4ba572004c85ee01fee69`.
The current session printed the plan but could not complete protected host
verification. An independently authorized host context must confirm the
same plan and the existing service-account replay path.

**NOT AUTHORIZED TO EXECUTE.** Apply requires root, a verified frozen
source tree under protected ancestry, a reviewed interpreter, and explicit
operator approval of the exact plan. The supported arguments are the same
candidate options with `--apply --approve-plan-sha256 <approved-plan-digest>`
in place of `--dry-run`. The matching digest guards against plan drift.
It carries no independent authority by itself. The five operations are:

1. Create `/var/lib/ai-soc-b4/records` as root:147, mode 0750.
2. Create `/var/lib/ai-soc-b4/pins` as root:147, mode 0750.
3. Create `/var/lib/ai-soc-b4/evidence` as 136:147, mode 0700.
4. Install `/opt/ai-soc-b4/source-<candidate-sha256>.tar` as root:147,
   mode 0440, at archive SHA-256
   `ceabf9b440df13c928847ec2b15e503f9f42275ed659f5c2fa1aff83e60e939b`.
5. Install `/etc/systemd/system/ai-soc-b4-worker@.service` as root:root,
   mode 0644, at SHA-256
   `67308a9ed8a97ab552884c747860f1a263fa2a9057ff07296183c47fec3cc2f1`.

The archive is a deterministic, reviewed source input. The custodian still
needs a separately approved immutable runtime with matching Git metadata,
interpreter, dependency artifacts, and executable paths. The script does
not install that runtime, publish a trust anchor, reload systemd, enable
or start a unit, or change existing path metadata. It refuses conflicts.
After an interrupted apply, inspect the named output and reconcile the
exact approved plan. Never overwrite or delete a partial file automatically.

The [worker template](../../deploy/b4/ai-soc-b4-worker@.service) expects
independently provisioned `/opt/ai-soc-b4/bootstrap/worker` and a
restricted inspection broker socket at
`/run/ai-soc-b4/docker-inspect.sock`. Review the bootstrap's decision-ID
transport and sandbox, cgroup closure, worker/supervisor isolation, and
proposed systemd ceilings before approval. Do not give the worker direct
host Docker socket access or Docker group membership. A read-only socket
mount is not method authorization. The broker policy must permit only
the approved projected identity read. Runtime installation, candidate
approval, trust publication, any daemon reload or activation, and Gate 1
all require separate decisions.

## Gate 1 bootstrap integration update

The prior Linux candidate and installation plan are historical. The
[new 56-file candidate](source-registry-execution-manifest.gate1-bootstrap.candidate.json)
and [revised inert plan](b4-gate1-bootstrap-installation-plan.review.json)
are unapproved. Their SHA-256 digests are
`e8c0612a6f78698b1b1ad7cae5fbd4bb10d2b08bf3a274faed6571665824a3e6`
and `ab9c989304152de4862a9ecdf2a55dcd2ca7306d0a6e1bb5c67d9684cc12728a`.
Do not apply the historical plan.

The [bootstrap](../../scripts/b4_preflight_bootstrap.py) is invoked with a
reviewed interpreter in isolated, no-bytecode mode. Deployment selects a
fixed role and supplies only a validated decision ID. The supervisor role
requires UID 136/GID 147 and protected local directory descriptors. The
worker role rejects root, UID 136, and membership in GID 147. The updated
template expects a separate root-controlled runtime at
`/opt/ai-soc-b4-worker`. The five inert installation operations do not
install that runtime. It requires independently verified imports,
interpreter and dependencies, and matching reviewed Git metadata.

The [broker client](../../services/api/app/database/source_registry_b4_broker.py)
requires root-owned local sockets and checks the peer UID before sending.
The separate control and worker sockets use bounded newline-delimited JSON
with a request nonce and an exact nonce/result reply. Control requests bind
the decision ID and approval digest. Run-scoped operations also bind the
run ID. The worker socket must only admit the nominated dynamic worker from
the authorized process scope and deliver its one-use handoff privately.

The independently controlled authority must implement the server side of
this contract. It must authenticate and enforce recovery authority and the
durable freeze, record containment before startup, prove scope closure,
perform independent backend and Docker reconciliation, and withhold freeze
release until reconciliation succeeds. The root UID check authenticates
the local peer. It does not establish those operational facts. The worker
still needs the separate inspection-only Docker broker. No controller,
runtime, broker, secret, or live authority was installed in this phase.

### Broker server engineering handoff

The [broker server](../../services/api/app/database/source_registry_b4_broker_server.py)
implements both existing JSON sockets and a projected Docker HTTP endpoint.
The bootstrap and its wire format are unchanged. Use `Broker.serve` with
prebound root-owned listeners at `/run/ai-soc-b4/{control,worker,docker-inspect}.sock`.
Protect directory ancestry and socket access through independently reviewed
host configuration. Socket clients are authenticated using Linux peer
credentials. The infrastructure adapter must prove that the worker PID,
effective and supplementary IDs, and cgroup match the authorized scope.

Keep the reviewer anchors and grants on a broker-only root 0700 directory
descriptor. An execution grant signs the canonical bytes specified by
`SignedGrants.verify` with domain `ai-soc-b4-broker-v1`. It binds the protected
host/runtime identity, complete approval digest, candidate, scope, and expiry.
The existing wire protocol generates the run ID after review. The broker
binds it once to the signed decision in the durable journal. An independently
authorized custodian can invoke the separate `Broker.recover` interface with
a short-lived recovery signature bound to that exact run and approval digest.
Neither socket exposes this interface.

Use a different root 0700 descriptor on durable local storage for the
broker journal. Replay and evidence share the append-only, hash-linked
journal. Startup rejects partial records and locks the store against a
second broker. A journal with an unfinished operation blocks new runs.
Ambiguous release or recovery requires independent reconciliation. An
evidence custodian must arrange protected retention and independent receipt
archiving. A hash chain on the same host cannot detect privileged rollback
or truncation without an independently retained checkpoint.

The required `Infrastructure` adapter remains a deployment dependency.
It must supply immutable packet/credential custody, enforce an administrative
change freeze, arm the worker scope deadline independently of the broker
connection, and prove complete cgroup teardown. The monitor must deliver
complete active backend observations and a sticky indication of any
out-of-scope connection since freeze acquisition, including one that opens
and closes between polls. Polling by the broker alone cannot prove that
property. The Docker adapter must perform only a fixed inspection of the
approved target. No generic proxy or daemon descriptor belongs in the
worker scope. Verify the actual Docker CLI negotiation, OS sandbox,
credential custody, deadline and monitoring paths offline on the deployment
runtime before requesting live Gate 1 approval.

The 56-file bootstrap candidate and its installation plan are obsolete
for this source revision. The [58-file broker candidate](source-registry-execution-manifest.broker-server.candidate.json)
and [updated inert plan](b4-broker-server-installation-plan.review.json)
are unapproved. The existing five-operation plan format changes only the
archive destination and payload digest. It does not install a broker
launcher or provision its private directories, trust anchors, or listeners.

### Protected runtime integration

The isolated bootstrap accepts the root-only `broker` role and a separate
`recover <decision-id> <run-id> <expires-at>` role. The latter checks the
independent recovery signature and the journal before requesting any action.
Start neither role on an unapproved host. The broker verifies all files
listed by the configured deployed `B4-MANIFEST.json` digest. Provision the
interpreter, standard library, site-packages and startup configuration as
part of the independently frozen platform. Its private configuration is
`/etc/ai-soc-b4/broker/runtime.json` and contains only `host`,
`runtime_sha256`, `authority_uid`, `authority_gid`, and `worker_ipc_gid`.
The private `records` and `grants` directories live beneath it. The broker
journal resides in `/var/lib/ai-soc-b4/broker`. All four directories must
be root-owned mode 0700 under protected ancestry.

The three socket-activation descriptor names are `control`, `worker`,
and `docker`. Bind their existing paths with root ownership and mode
0660. The control socket group is GID 147. The other two use the dedicated
`ai-soc-b4-worker-ipc` group provisioned independently. The worker template
joins that group and hides the authority socket. The broker rejects extra
inherited descriptors and marks listeners close-on-exec. Verify that the
service manager supplies no other descriptors or supplementary groups.

The live independent authority provider is still required. It must serve
the fixed `/run/ai-soc-b4/authority.sock` through a protected root-owned
mode-0660 listener. The broker verifies the configured dedicated authority
UID/GID from the kernel credentials attached to its initial one-byte `B`
greeting before sending the request. This also works when the listener
creator is the root service manager and the serving process is unprivileged.
Authority requests are nonce-bound with absolute monotonic deadlines.
Provision its administrative freeze, credential and evidence custody, and
worker control separately. In particular:

- `hold` must establish a restart-safe exclusive freeze with an empty
  workload baseline, return its original event cursor and prove durability
  before the worker can start. `recover` must recover the original cursor
  from protected storage, never reset the observation baseline. `release`
  must check that ownership and the event barrier still match atomically.
- `start` must enforce the absolute `stop_by` ceiling even on broker
  crash. It must verify sandbox policy and arm the deadline before a worker
  can connect. `stop` must disable replacement and restart before local
  cgroup teardown. `scope_closed` must prove stopped state after the
  broker confirms recursive emptiness. Verify worker egress to the precise
  approved endpoint and restrict Unix sockets and filesystem visibility.
  The worker's loopback systemd allowance alone does not enforce a port
  restriction.
- `observe` must cover every successful backend connect and disconnect
  since the freeze watermark, including connections that open and close
  between requests. Return a contiguous event sequence, synchronized active
  snapshot and coverage watermark. The source must account for event
  producer failures, restarts, target changes and loss of visibility;
  snapshots or sequence numbers fabricated from polling do not qualify.
- Verify both initial and appended evidence checkpoints against independent
  durable storage. Deny conflicting receipts or lost journal history.
  Serve credentials solely through the admitted worker handoff. No
  credential storage is allowed in the runtime manifest or broker journal.

This integration changes the reviewed source and worker unit. The prior
58-file broker candidate and five-operation plan do not cover it.

### Independent authority isolated-host verification

The dormant authority units require a distinct primary service account,
the host IPC supplementary group, a frozen runtime at
`/opt/ai-soc-b4-authority`, and durable private service-owned state at
`/var/lib/ai-soc-b4-authority`. The root-managed configuration under
`/etc/ai-soc-b4/authority` must be readable only by approved identities.
Use root-owned group-readable approval packets and public verification
anchors. Keep private signing keys outside this deployment. The
`runtime.json` fields are `uid`, `gid`, `host_uid`, `host_gid`, `host`,
and `runtime_sha256`. The authority accepts root broker callers only
from the fixed broker and recovery service cgroups.

Verify service and socket syntax offline. On a separately authorized,
isolated Linux host, verify descriptor inheritance, filesystem visibility,
UID and cgroup membership, and effective egress with a disposable worker.
Then terminate the broker and the authority separately during a simulated
run. Confirm the independent controller still stops all descendants by
the original deadline, the freeze remains held, and invalid recovery
signatures cannot authorize release. Verify that event loss, a collector
restart, and a short-lived unapproved connection simulation each leave
the freeze held. Corrupt a copied checkpoint and confirm verification fails.

Provisioning remains blocked on the independently controlled
`host-control.sock` provider. It must enforce the administrative freeze
and egress constraints, arm worker deadlines outside both services, and
supply complete PostgreSQL connection events with producer loss and restart
detection. Its release operation must compare the durable original cursor,
current event head, target identity, zero active sessions, and freeze
ownership atomically. The authority validates the entire contiguous batch
from the original cursor and locally rechecks cgroup emptiness before
requesting release. No PostgreSQL event producer is installed by these
units. An active-session snapshot or an unqualified logging feed cannot
provide that coverage. External retention of the authority journal head
is needed to detect rollback of the authority's own storage.

### Host controller and isolated verification

The controller owns a root-private journal under
`/var/lib/ai-soc-b4-host-control`, separate from the authority and broker.
It accepts the dedicated authority account from its exact service cgroup.
Its root-managed configuration under `/etc/ai-soc-b4/host-control` contains
the authority UID/GID, host ID, and the approved runtime manifest digest.
The same directory contains the private `records` and `grants` inputs.
The controller can anchor authority checkpoints and arm the cgroup
watchdog after independent grant verification. It denies readiness and
does not launch a worker or release the administrative freeze.

The checkpoint protocol advances by one, retains the head across restart,
and checks the exact head before the authority can resume. A crash after
the authority's local synchronization and before the independent receipt
can leave the two heads different. Startup must stop in that case.
Keep an external copy of the controller head if rollback by a privileged
host administrator is within scope.

#### Session coverage decision

- TCP events can see short-lived transports if captured inside the target
  network namespace or on every relevant interface. They cannot establish
  authenticated PostgreSQL user/database identity or see Unix sockets.
- Unix socket events can detect local transports in the relevant namespace.
  They cannot identify successful PostgreSQL authentication or distinguish
  every request path from an established session by themselves.
- Backend process events can identify forks and exits if captured against
  the correct container cgroup, PID namespace, and instance epoch. Some
  processes are auxiliary or never authenticate. The observation must
  correlate authenticated sessions, including failures and abnormal exits.
- PostgreSQL 16 connection/disconnection logging catches activity between
  snapshots, but collector crash, power loss, and file-write failure can
  lose records. A kernel ring buffer can also overflow. Consumer-assigned
  sequence numbers cannot account for events that never reached it.

A sufficient producer needs an authenticated-session source inside the
server covering both transports, a stable instance epoch, a source-side
sequence or loss counter, and an active-session view from the same release
barrier. A privileged transport/fork tracer can cross-check those events.
Attest the exact binary/configuration and make overflow, rotation, loss of
instrumentation, or either restart invalidate the freeze window. Stock
logging and periodic activity queries alone do not establish the contract.
See [PostgreSQL 16 logging](https://www.postgresql.org/docs/16/runtime-config-logging.html)
and [Linux BPF ring buffers](https://docs.kernel.org/bpf/ringbuf.html).

#### Isolated-host acceptance sequence

1. Verify root ancestry, the protected runtime hashes, three service
   identities, descriptor inheritance and non-writable state boundaries.
   Verify that the controller can reach only its approved writable scope
   and never grants the worker a controller or Docker-daemon descriptor.
2. With a separately authorized disposable process tree, verify exact
   unified cgroup membership and cgroup v2 recursive teardown, including
   descendants and a failed-kill result. Kill the broker and authority
   separately before the deadline and verify that the controller still
   terminates the tree. Kill the controller and verify immediate cleanup
   on restart. Current code cannot enforce the original deadline if the
   controller is unavailable. A service-manager-armed deadline or separate
   watchdog must cover that interval before any worker can be admitted.
3. Verify mandatory containment at the kernel boundary. Use an independently
   installed worker cgroup egress filter for the single IPv4 TCP endpoint,
   including checks for namespace changes, unsupported address families,
   and local Unix sockets. Verify both mount namespace denial of the real
   Docker socket and protected paths and the worker's descriptor table.
4. On an independently approved disposable PostgreSQL instance, exercise
   successful and failed authentication on TCP and Unix sockets, rapid
   sessions, namespace/PID reuse, collector restart and overflow. Require
   the produced event sequence and synchronized snapshot to agree. A gap
   or restart must block freeze release. Test the administrative gate against
   each path capable of changing the target during the freeze.
5. Interrupt each durable checkpoint transition and compare both stores.
   Verify that a changed or rolled-back authority head fails at startup.
   Verify signed recovery and durable teardown before considering release.

The authority and controller deployment artifacts remain unapproved.

### Admission proof and service-manager deadline

The authority requests an admission proof over the existing authenticated
host-control channel after taking the freeze. It never accepts this proof
from the worker. The proof binds the approved target and TLS pins,
decision and run, both worker logins, exact worker TCP endpoint, denial of
Unix-socket and replication admission, empty initial workload baseline,
administrative freeze, policy digest and execution window. The instance
binding uses the PostgreSQL version, postmaster start timestamp and
database OID under the pinned container and TLS identity. Both authenticated
worker sessions corroborate it before the role and history queries. The
independent monitor's separately approved scope remains in force.

The authority commits the canonical proof digest to its existing journal,
checks continuity before launch, handoff and release, and retains the
freeze upon detected drift. The worker gets no credentials before the
controller verifies effective PID 1 unit properties for the exact cgroup
and run. The dormant unit budgets 30 seconds after activation and up to
5 seconds for stop escalation. Admission requires the combined bound to
fit the approved monotonic deadline. The controller watchdog remains a
secondary stop path. A timer or delivery receipt does not prove teardown.
Whole-cgroup closure, independent backend absence and the evidence
receipt still gate success. The existing complete-event monitor also
still gates release.

For isolated verification, allow one supervised fixture run and test
unexpected pre-existing sessions, alternate TCP endpoints, Unix sockets,
replication, and incorrect credentials. Change the policy or freeze in
a separate controlled fixture and verify that credentials or release are
denied. With a disposable process tree, kill the broker and controller
before expiry, then verify that PID 1 stops the entire scope by the bound
and that a stale or replaced scope cannot reopen admission. Reconcile
the independently observed backends, verify durable receipts, and confirm
that incomplete cleanup retains the freeze. Obtain separate authorization
for each live target and destructive process test.

Acceptance of preventive admission in place of the complete event stream
requires independent evidence that admission and administrative exclusion
cover the entire window, including initial sessions, alternate namespaces
and local paths, and remain effective across crashes and restarts. It also
requires independent teardown evidence. This change does not enact that
replacement. The host controller still denies readiness because the actual
admission and administrative freeze provider and authenticated event source
are unavailable.

### Ubuntu 22.04 worker deadline compatibility

Stock systemd 249 has no runtime jitter property. The portable worker unit
omits the v250-only directive. The controller queries the system manager
for its version and userspace monotonic timestamp, checks the effective
worker properties, and rechecks the manager identity. A missing jitter
property is allowed only on 249. Any exposed jitter value must be zero.
Require the same manager epoch and worker invocation on both deadline
checks. Verify a 5-second startup timeout, 30-second active runtime and
5-second stop grace, control-group kill, final SIGKILL, no restart and no
stop hooks that could extend the bound. Read both stop-hook arrays through
typed systemd D-Bus properties because systemctl 249 can omit empty arrays.

The unified hierarchy root is not expected to expose `cgroup.kill`.
Before credential handoff verify a writable kill control on the worker's
exact domain child cgroup. A configured timer is not evidence of closure.
On a separately approved disposable fixture, compare the actual PID 1
properties against the deadline, verify all descendants disappear by the
bound, and verify recursive emptiness plus independent backend teardown
before releasing the freeze.

### Frozen runtime deployment inventory

The candidate inventory supersedes the five-operation inert plans. It is
review evidence and has no apply path. Build the archive with the current
candidate and the separately pinned preserved manifest as inputs. The runtime
recomputes file hashes, the migration graph, DDL and interpreter/dependency
versions against the packaged manifest. The deployed archive needs no
`.git` metadata. The historical commit and dirty flag are pinned by the
approved manifest digest rather than rederived on the host. Provision root-
controlled interpreters and dependencies separately. Keep credentials and
approval material outside the archive.

The authority's root-managed, group-readable configuration is now under
`/etc/ai-soc-b4-authority`. Keeping it beneath the root-only
`/etc/ai-soc-b4` made it inaccessible to the authority identity. The host
controller socket already uses the authority's primary group, so the
authority unit does not require a supplementary host IPC group.

For first activation, verify source and unit hashes, root ancestry and
protected mounts. Verify socket ownership and systemd descriptor names,
then run a credential-free worker-tree fixture on the approved Ubuntu host.
Test exact manager properties, alternate endpoint and Unix-socket denial,
recursive cgroup teardown and timing, and protected-resource denial. Verify
that restarting the broker/controller does not enable replay or release a
held freeze. Stop the fixture and preserve the journals and independent
checkpoint on ambiguous cleanup. Do not use test or production credentials
in this fixture.

The current controller deliberately denies readiness. Deployment inventory
coverage does not supply the production admission/freeze service or
authenticated PostgreSQL event producer. Complete-event monitoring remains
mandatory pending an independent equivalence decision. Gate 1 requires
separate target, fixture, credential, monitor and read-only execution
authorizations. Gate 2 remains separately blocked on the unresolved
historical `0eafe3f3` DDL provenance and migration approval.

Reproduce the inventory without host access from a frozen checkout with:

```python
from pathlib import Path
import json
from scripts.provision_b4 import deployment_inventory

candidate = Path("docs/security/source-registry-execution-manifest.autonomous-b4.candidate.json")
inventory = deployment_inventory(candidate, "<independently reviewed candidate digest>",
                                 "<preserved approved manifest digest>")
print(json.dumps(inventory, sort_keys=True, indent=2))
```

For the credential-free deadline check, use a separately approved disposable
host and a test-only copy of the worker template with a fixture entry point.
The fixture must fork a child that ignores SIGTERM and stay alive until
systemd stops the scope. Use `systemctl --system show -p Version
-p UserspaceTimestampMonotonic` and the exact worker properties checked in
`manager_deadline`. Record the activation time, deadline, full worker cgroup,
and descendant PIDs. Confirm no descendants remain by active time plus 35
seconds after the broker and controller have been stopped. Confirm
`cgroup.events` reports `populated 0`, or reconcile an absent cgroup with
the stopped unit and the recorded PIDs. Treat a recreated worker scope,
missing manager property, or incomplete cleanup as a failed fixture. No
database, Docker daemon, credential handoff, or migration enters this test.

### Shared-host fixture review boundary

The fixture has no automatic stop or slice cleanup command. PID 1 is the
only planned termination path. Keep the empty residual slice and journal
evidence for separately authorized reconciliation. A lost start
acknowledgement, runner crash, unit or cgroup replacement, or ambiguous
deadline never authorizes teardown of an unproven scope.

Before a new execution decision, run the read-only fixture precheck in the
ordinary real-host shell. It queries PID 1's effective unit search paths,
rejects applicable exact, prefix and type-wide overrides and dependency
directories, and checks NSS reservation of the fixture user and group.
Post-start checks are additional evidence. They cannot prevent a startup
hook from running. The independent custodian must establish and maintain
exclusive control of unit changes, NSS, and slice admission for the entire
window. A protected window record at
`/run/b4-fixture-a649861e.window.json` binds the exact host, manager epoch,
runner digest, unit, slice, and short expiry to those assertions. It is a
custodian attestation, not a kernel lock. If that control cannot actually be
enforced and independently verified on the shared host, use a disposable VM.
Do not issue the record from the runner or use it as execution approval.

The runner fsyncs `START_ATTEMPTED` and its parent directory before the
privileged request. It will not reuse that evidence filename. After a
crash, use the unprivileged `--reconcile` mode from the real host.
Reconciliation compares available invocation and process evidence and
does not stop anything. Preserve incomplete evidence for separate recovery.
A polling interval spanning the deadline is inconclusive. A reported
success requires an unchanged manager, no scope or invocation replacement,
known descendant identities gone, and a confirmed empty or collected unit.

The stricter fixture socket policy prohibits socket creation. The worker
only probes metadata for PostgreSQL Unix sockets, Docker, B4 and Wazuh paths,
validates inherited descriptors and rejects an unexpected credential
directory or ambient credential variable. Absent and inaccessible paths
are reported separately. This fixture cannot verify production PostgreSQL
egress or Gate 1 readiness.

On systemd 249, the fixture's top-level slice can report `LoadState=loaded`
without a unit file. The precheck accepts only its pristine implicit form:
inactive, no configuration or aliases, no queued job or activation history,
only the built-in root-slice and shutdown dependencies, and no cgroup on
disk. The fixture service must still report `LoadState=not-found`. The
controlled-window prerequisite and prohibition on automatic stops still apply.
