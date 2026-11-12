# TG-04B development preparation — Gate 1

Prepared 2026-11-11. Offline specifications only. Nothing here authorizes or
performs provisioning, registry access, credentials, database work or live dispatch.
TG-04B remains BLOCKED. Existing assessment and development plan were supplied
in the conversation; this directory records their Gate 1 preparation only.

## Review artifacts and deliberate inactivity

- `compose.review.json`: JSON Compose draft with **empty `services`**. Proposed
  services/networks/volumes exist only in `x-` review fields. Do not run it or
  mechanically promote those fields. Image references and entrypoints are unset.
- `security-policy.review.json`: desired security policy, not installed rules,
  application settings, grants or a credential resolver.
- `evidence-templates.review.json`: nine receipt field inventories, common
  metadata and PRE2 contract field inventories. Nulls intentionally prevent valid
  authority objects. No template is independently verified evidence.
- `tests/test_gateway_development_spec.py` (repository root): tests parse local drafts
  and compare contract fields/limits, without Docker, settings, DB or network.

No existing Compose, application, migration, authentication, gateway, ingestion,
AGENTS.md or handoff file is changed. Recovery for Gate 1 is to retain or stop
using these review artifacts; no infrastructure rollback is needed.

## Dedicated topology

One dedicated non-production VM, proposed project `ai-soc-gateway-dev`, with its
own virtual disk, service identities and networks. No production routes, data,
volumes, host-directory mounts, container-engine socket or host namespaces.
Proposed initial capacity: 4 vCPU, 8 GiB RAM and a bounded 40 GiB development
disk; measured image/kernel/storage compatibility remains a provisioning blocker.
Set disk quotas and logging rotation before seeding data. No production backup
restore, snapshot clone or federation. Import only approved images and a tiny
synthetic dataset. No Wazuh manager, endpoint agents or dashboard is required.

PostgreSQL has its own cluster/volume and database `ai_soc_gateway_dev`, distinct
from both protected `ai_soc` and test-only `ai_soc_test`. No published DB port.
The Indexer has its own cluster/volume and dedicated synthetic source. The runner
joins separate `database` and `search` networks; services do not share identities.
There are no public service ports. Administrative access requires a separately
approved VM management channel, absent from runtime containers.

Dedicated network names and volumes are project-scoped, never external. Reserve
non-overlapping subnets after host route inventory; do not guess address ranges.
Record approved fixed endpoint addresses, preserve TLS hostname verification and
reject address changes pending review. Internal Docker networks are segmentation,
not proof of default-deny egress. Enforce host/VM input, forwarding and output
rules for IPv4/IPv6, including host gateways, metadata endpoints and Docker NAT
paths. Only runner-to-development-PostgreSQL:5432 and runner-to-Indexer:9200 are
proposed runtime flows, with established replies. Deny other new flows, general
DNS, proxies, redirects, Internet and production routes. Indexer/PostgreSQL have
no general outbound permission. Bound denial logs without packet payloads.

## Version and image promotion process

No versions or image digests have been verified. For each of PostgreSQL, Indexer
and runner, an authorized operator must independently review upstream identity,
license/support status, version compatibility, platform and immutable digest.
Record the fields listed in `image_lock_fields`, including provenance and dated
review. Use reviewed `repository@sha256:...` references, not tags alone. Verify
transferred image integrity in the isolated VM. Registry access/image import is a
future approval, never an action performed by these tests. Runner provenance must
identify the reviewed source artifact including currently untracked gateway code.
No automatic pulls, updates, restart loops or demo-security initialization.

## Accounts, ownership, credential and TLS boundaries

Provision fresh tenant slug `gateway-development`, integration name
`Gateway Development Indexer`, and API-key principal. Generate UUIDs only during
approved provisioning and independently attest their exact relationships. Principal
ID means authenticated API-key record UUID, never the API key value or model text.
Seed exactly `wazuh-alerts-gateway-dev-v1`; capture actual index UUID and cluster
identity. Use DEDICATED organization mode with null field/value/mapping and
`server_enforced=false` as required by PRE2; independent exclusive ownership proof
is mandatory. No aliases/rollover/shared-source shortcuts. Index replacement
invalidates grants/manifest evidence even if its name is unchanged.

Separate owner/provisioner/runtime DB identities; no superuser/owner runtime.
Review schema, existing role utility limitations, migration plan, atomicity and
recovery before any development initialization. Do not execute existing provisioning
helpers: the Wazuh provisioner targets protected `ai_soc`. Runtime cannot provision
tenants, keys or integrations. Separate Indexer provisioner, independent verifier
and exact-index reader. Determine minimum search/PIT permissions against the pinned
version; permission names are unresolved, not guessed broad grants. Inspect all
direct, inherited, backend and default roles. Verify through metadata/ACL review,
not attempted destructive operations or another customer's data.

The policy lists environment variable **names only**. A future approved launcher
may inject development secrets from a protected development source, never from
the repository, Compose literals, arguments or production secret stores. Only
the runner receives its runtime secrets; provisioning/verifier credentials stay
outside it. Environment delivery is not protection from privileged process/host
inspection: restrict runtime users, dumps, diagnostics and management access.
The existing resolver does not support the proposed new reference; that change
needs separate implementation approval. Do not reuse its production reference.

Development CA key remains offline/outside runner. Review issuer provenance,
chain, certificate validity and exact SAN `wazuh-indexer.gateway-dev.test`; record
CA/leaf fingerprints. Future CA public certificate mount is read-only. Server
private key stays with Indexer; neither key enters evidence. TLS verification is
mandatory. PostgreSQL should use a separately reviewed server certificate and
verified transport as part of the development DB connection plan.

## Runner, query and authority requirements

Future runner: reviewed non-root UID, read-only root filesystem, no capabilities,
no privilege escalation, bounded tmpfs, PID/memory/CPU limits and no engine socket.
Image-specific writable paths/user/kernel requirements need compatibility review;
do not add privileges to bypass failures. Scheduler and live registration remain
disabled. Proposed container resources are capacity limits, not per-operation
deadline/CPU enforcement; the latter remains unimplemented.

Only `wazuh.alerts.search@1.0`, operation `query`, exact integration and concrete
index UUID is eligible for future review. Compile an approved historical half-open
window no longer than 15 minutes, timestamp existence and exact source filters.
Use PRE2 canonical query helpers and pagination scope, not caller DSL. One page,
one returned hit and at most two fetched hits for lookahead. No retries, automatic
continuation, wildcard discovery or broad fallback. Reserve resources for PIT
cleanup within the 3-request/15-second aggregate limit; timeout/overflow is failure,
never a complete truncated success. Validate provenance and output before evidence
writes. Budget semantics and proposed numbers are in the policy draft; they are
not enforced in the existing live client.

Proposed trusted bridge: `AuthenticatedPrincipal.tenant_id` -> context tenant and
`AuthenticatedPrincipal.api_key_id` -> context principal. Trusted code must resolve
current grants, integration ownership/active state and revocation; repeat checks
immediately before dispatch, with no initial authorization cache. No request/model
may inject context, policy, receipt or consent. Revoke admission immediately and
cancel undispatched work on state changes; packets already sent cannot be recalled.

Mandatory TG-01 and TG-03B checks remain necessary. PRE2 PASS is offline-only,
`executable=false` and operational clearance UNVERIFIED. A real adapter must have
separate explicit non-synthetic eligibility and a truthful reviewed disclosure
contract; neither the fake allowance nor synthetic data category can authorize it.
Tenant-local classification requires actual tenant-controlled boundaries. External
cross-boundary disclosure requires exact trusted consent; no implied consent from
read-only labels. No response actions, orchestration or persistent sinks are added.

## Evidence admission and non-sensitive verification

Complete each receipt using common metadata plus its required fields. All times
are trusted UTC; query times align to milliseconds. Reject unknown versions,
duplicate JSON keys, contradictions, stale evidence and unapproved fields. Support
receipts expire within one hour and on any relevant change; the admitted verifier
receipt must be at most five minutes old and valid for at most five minutes.
Manifest TTL is at most one hour. No automatic freshness renewal from old claims.

Separate issuer from verifier. Authenticate their origins using an approved
signature envelope or independent authenticated review; pin the verifier trust
anchor outside the supplied bundle. Admission implementation is future work.
Verify integrity/provenance before constructing `VerificationAuthority` and
`IndependentVerification` from trusted code. Hashes and boolean claims alone do
not establish trust. Use existing PRE2 model serialization/digest helpers and
schema 1.0. Include exact canonical manifest and bundle digests in the receipt.
No secrets, customer alerts, private keys or raw authorization tokens in evidence.

After separate operational approval: inspect only development control-plane
records, exact-index metadata, effective ACLs, certificate chain and applied network
rules. Controlled synthetic endpoints/canary resources may test denial and budgets
after approval; never probe production addresses or real unrelated tenants. Capture
sanitized outcomes, reviewer, timestamp, artifact digest and expiry. No live check
is authorized now. Missing operational evidence remains BLOCKED/UNVERIFIED.

## Approval checklist and safe lifecycle

Gate 2 prerequisites, all separately explicit before execution:

- [ ] Approve exact VM host, capacity, management boundary and non-production route inventory.
- [ ] Approve reviewed source artifact, selected versions, immutable images and import method.
- [ ] Approve concrete non-overlapping addresses, effective default-deny rules and controlled verification targets.
- [ ] Approve promoted runnable configuration, image-specific UID/storage/TLS settings and disabled runner entrypoint.
- [ ] Approve development-only accounts, secret delivery, certificates and effective permission matrix.
- [ ] Approve exact DB initialization/migrations/seed records and recovery review; no protected DB access.
- [ ] Approve synthetic index creation/seed writes and independent metadata/ACL inspection.
- [ ] Approve issuer/verifier identities, external trust anchor and dated evidence-admission procedure.

Database-dependent automated tests still target `ai_soc_test` per AGENTS.md.
Operational initialization/verification of `ai_soc_gateway_dev` needs explicit
approval distinguishing it from tests; no silent test redirection.

After approval, install isolation controls first, then establish CA/accounts and
bring up only the development database/Indexer. Independently verify identity,
TLS, privileges and egress before admitting any runner connection. Keep runner
stopped until separate implementation and execution approval. Abort on any source,
TLS, privilege, destination or resource mismatch; never weaken a guard to proceed.

Live activation later requires fresh independent receipts for every prerequisite,
trusted bridge/revocation checks, implemented budgets, mandatory authorization and
disclosure gates, explicit non-synthetic registration, offline regression success
and separately approved minimum smoke test. No production rollout follows.
Outputs must say development Wazuh observations over synthetic seed data, not
verified conclusions or genuine customer intelligence.

Shutdown: deny new admission, stop runner, bounded PIT cleanup, stop only the
development services and preserve volumes/receipts. Revoke development access
through approved operators and retain evidence. Delete no volumes/accounts/index
or VM without separate destructive-action approval. If compromise is suspected,
isolate the VM first; avoid exporting secrets or payloads. Residual risks include
host-admin access, container escape, stale receipts, clock drift and incomplete
network enforcement; independent operational verification is still required.
