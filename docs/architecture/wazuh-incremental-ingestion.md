# Reliable incremental Wazuh ingestion — Phase 1.4.1

Status: architecture approved in conversation; cursor contract, checkpoint
storage, PIT client, and Phase 1.4.4 manual checkpoint-aware synchronization
implemented, followed by Phase 1.4.5 lease fencing/recovery and Phase 1.4.6
tenant-scoped status visibility. Phase 1.4.7 adds an optional foreground scheduler,
disabled by default; production scheduling is not activated. Python 3.10; no new
dependencies. Existing offset-based ingestion remains unchanged.

## Observed capabilities (2026-11-10)

TLS-verified probes used the configured ingestion identity. No credentials,
documents, index names, or PIT identifiers were printed or stored here.

| Probe | Observation |
| --- | --- |
| Root version metadata | HTTP 403 |
| Node version metadata | HTTP 403 |
| Field capabilities across alert indices | timestamp/@timestamp: date; id: keyword; searchable and aggregatable |
| timestamp ascending, _index ascending, id ascending | Two-hit search and subsequent search_after succeeded |
| PIT creation | HTTP 200; short-lived context released successfully |
| PIT timestamp/_shard_doc sort | HTTP 400, search_phase_execution_exception; context released |
| Documents without id | Exact current count: zero |
| PIT timestamp/_index/id without explicit sort format | First, repeat, and next searches succeeded; integer/string/string sort values |
| Explicit timestamp sort format | HTTP 400, x_content_parse_exception; omit the sort format option |
| Strict PIT creation and partial-result rejection | Supported; epoch-millisecond range filter also succeeded |
| Bounded index/id composite aggregation | 1,000 groups examined; zero duplicates; scan incomplete |
| Phase 1.4.4 index UUID metadata | HTTP 403; live incremental activation blocked |
| Phase 1.4.4 timestamp/id field mappings | HTTP 200; metadata for 15 indices returned |

The installed version remains unknown. A forbidden endpoint is not evidence of
feature absence. PIT lifecycle and candidate three-field pagination were verified
in Phase 1.4.3. Probes were separate from routine mocked automated tests.
The failed _shard_doc probe excludes that strategy for this installation unless
its cause is independently resolved without configuration changes.

## Ordering decision and activation gates

Use PIT plus search_after with (timestamp epoch milliseconds, concrete _index, id
keyword), ascending, and mandatory boundary collision detection as approved for
Phase 1.4.3. Do not use _id sorting, enable fielddata, or silently fall back to
offsets. The cursor module models this sort, not other sort modes.

Keyword mapping and successful sample pages do not prove that id is unique
within an index or immutable. The client therefore fetches one extra hit beyond
the page size and validates strict progression over ALL returned hits before
returning the page. Equal tuples within a page or across its boundary fail the
entire page. The extra hit is not emitted; the next search starts after the last
emitted hit, so the extra hit is fetched again. A colliding group can never be
silently skipped by search_after. This depends on the complete, immutable PIT
view and the Indexer's correct sort/search_after semantics; no offset fallback
is permitted. The PIT freezes sort keys for the snapshot lifetime.

Mappings across target indices and rollover templates still need service-level
validation before activation. The client rejects missing/multi-valued source
IDs/timestamps, source/sort inconsistencies, incompatible date precision, and
unexpected indices. Its query includes scoped documents with no indexed
timestamp as well as the requested time range, so missing timestamps are not
silently excluded before validation. A collision stops the scan for explicit
operator resolution or a separately approved unique-key strategy. A finite data
sample cannot prove future uniqueness. Date-nanos requires a new cursor version.

PIT search must be tested for complete shard coverage, repeatable pages, and
the exact sort values returned. Do not assume Elasticsearch-specific implicit
tie-breakers exist in OpenSearch. Source configuration/identity changes invalidate
active cursors and require explicit replay/reconciliation.

## Cursor contract

Version 1 is bounded JSON stored internally. Fields: tenant_id, integration_id,
query_fingerprint (lowercase SHA-256), generation, window_start_ms,
window_end_ms, snapshot_id (local UUID), sort_values, version. The time window
is half-open [start, end). No cursor exists before the first successful page;
the checkpoint represents that state separately.

Sort positions are exactly an integer epoch-millisecond timestamp and two
nonempty UTF-8 strings. Booleans, floats, missing values, duplicate JSON keys,
unknown fields, unsupported versions, invalid UUIDs, oversized encodings,
out-of-window positions, ties, and backwards movement are rejected. Errors use
a fixed safe code and do not echo input. Positions and cursors are immutable.

The query fingerprint binds canonical index identities, enforced tenant source
filter, sort specification, timestamp format, and configuration version. Window
bounds, generation, tenant, integration, and snapshot must also match the
authoritative checkpoint when deserializing. Page size is bounded independently.

The cursor is not signed and is NOT an authentication token. It must not be
accepted from a public API as authority. Authorization first loads the tenant's
integration and checkpoint from the database; those records supply context.
Changing a cursor's position cannot be detected cryptographically by this
module. Only the ingestion service may derive and persist its position from a
validated Indexer page. Any future external cursor API needs its own integrity
protection. Raw PIT IDs are held separately, never exposed in APIs/audit/logs.

## Checkpoint model — Phase 1.4.2

Add a unique (tenant_id, id) integration key, then a synchronization table with
integration_id as primary key and a composite (tenant_id, integration_id) foreign
key referencing the integration. Use RESTRICT deletion. This prevents wrong
tenant ownership and multiple checkpoints for one integration in the database.
Changing integration ownership is not a supported operation.

Separate completed_window_end from the active window and committed page cursor.
Include generation, last_attempt_at, last_success_at, safe_error_code,
imported/duplicate counts, query fingerprint, concrete index identity manifest,
and local snapshot identity. Require consistent nullable active-state fields,
nonnegative counters, valid bounds, and allowed states through DB constraints.
Raw PIT context, if persisted for resume, is internal short-lived state and must
never include credentials. An expired/lost context triggers replay, not reuse
of its position with a new PIT. Bound manifest storage and scan scope; fail
explicitly if those bounds would omit required indices.

Existing integrations begin uninitialized, with no inferred historical progress.
Do not infer a checkpoint from evidence's maximum event timestamp. Bootstrap
requires an explicit retained-history scope, not an arbitrary recent default.
Create checkpoint rows idempotently under unique constraints. Production migration
and any source permission/configuration changes require separate approval.

Implemented table: `wazuh_sync_checkpoints`, model `WazuhSyncCheckpoint`.
Migration `b71a4c2d9e10` follows `013505dd4ffd`; applied only to `ai_soc_test`.
Production application remains pending. The migration creates an empty table;
existing integrations have no checkpoint until explicitly initialized later.

The completed watermark and active bounds use integer epoch milliseconds to
match cursor version 1. Active window bounds, local snapshot UUID, and index
manifest are either all absent or all present. The fingerprint is required for
any active or completed progress. Cursor version defaults to 1, with an optional
three-element JSONB sort position; SQL NULL represents no committed page. Database
checks reject invalid sort types, out-of-window timestamps, control characters,
empty identifiers, and identifiers longer than 512 UTF-8 bytes. The manifest is
a nonempty JSONB object bounded to 64 KiB; detailed source identity validation
belongs to the future client/service. No raw PIT token is persisted: loss of the
in-memory PIT requires replay from the active window's beginning.

Status values are uninitialized, idle, syncing, error, and gap. Idle requires a
completed watermark and no active window; syncing requires an active window.
Uninitialized cannot claim progress, imported counts, or a successful attempt.
Error and gap can preserve an active window for recovery. Error codes have a
fixed database allowlist; no raw exception messages are stored. Counters and
generation are nonnegative big integers. Attempt/success timestamps are timezone
aware. Counts are cumulative, updated by the future service only on committed
pages. A tenant index supports scoped lookups; it is not row-level security.

The composite FK restricts parent deletion and ownership changes while referenced.
No public checkpoint read/write API exists. The database constrains ownership and
state shape, not temporal transitions: monotonic progress, generation fencing,
exclusive workers, detailed manifest semantics, and atomic evidence/audit updates
remain the responsibilities of later approved subphases.

Migration tests execute the real upgrade against a populated predecessor schema
inside a transaction-isolated schema in `ai_soc_test`; rollback removes test DDL
without DROP/DELETE/TRUNCATE cleanup. Application rollback leaves additive storage
unused. Automatic downgrade is explicitly refused because it would discard saved
progress; a data recovery plan and separate approval are required for removal.

## Processing and concurrency — Phases 1.4.3–1.4.5

The Phase 1.4.3 client exposes `alert_snapshot(...)` as an internal context
manager. It requires concrete alert index names (maximum 100), tenant/integration
UUIDs, a finite half-open time window, and an explicit trusted source filter.
The filter is frozen and included in the query fingerprint. It is not a public
authorization surface: callers must authorize integrations and enforce source
ownership. Explicit match_all is appropriate only for dedicated tenant sources.
Index discovery and index-UUID verification remain service responsibilities.

`page(size=..., cursor=..., generation=...)` returns normalized items, an internal
next cursor, and an exhausted flag. It emits at most 100 alerts (also respecting
the client's lower configured limit), fetching at most 101 hits for validation.
Only a validated empty page signals exhaustion. A first empty page has no cursor;
subsequent empty pages preserve the supplied cursor. Page calls do not implicitly
advance internal progress: a caller can retry a page until its DB commit succeeds.
When a later service increments checkpoint generation it must explicitly rebind
the committed cursor to that authoritative generation, never reuse stale context.

HTTP responses are capped at 8 MiB; duplicate JSON keys and nonstandard numeric
constants are rejected. Oversized alerts fail explicitly. PIT lifetime
is one minute, refreshed per search. Complete shard coverage is required at
creation and search. The client handles optional rotated PIT IDs and releases
only its own context on exit. Successful processing followed by failed cleanup
raises a safe error; cleanup failure during another exception preserves the
primary exception. In that case the short PIT lifetime bounds retained resources.
Cleanup never deletes documents. No automatic HTTP retries or DB writes occur.
Raw PIT IDs remain private and are absent from cursors, results, and object repr.
Upstream request errors are raised with safe codes and suppressed exception context.
HTTP 404 on PIT search signals expiry and requires a new snapshot/window replay.

The legacy `search_alerts` method and ingestion endpoint are unchanged. Production
incremental ingestion is not activated by adding these client methods.

### Phase 1.4.4 manual synchronization

This section records the Phase 1.4.4 baseline. The lease, retry, and rollover
behavior below supersedes its explicitly deferred items in Phase 1.4.5.

`POST /v1/integrations/wazuh/{integration_id}/sync?limit=50` authenticates the
existing tenant API key. Limit is 1–100. Responses contain only integration ID,
completed/not_due status, fetched/imported/duplicate counts, and page count.
There is no request body for source filters, cursors, credentials, or window
bounds. Cross-tenant integrations return the same 404 as missing integrations.

`WAZUH_SYNC_SCOPES` is an operator-owned JSON object keyed by integration UUID.
Default is empty: the new path is disabled until deliberately configured. Each
entry has tenant_id, bootstrap_start_ms, window_ms (default 300000), overlap_ms
(default 60000), safety_delay_ms (default 30000), and either source_field plus
source_value or dedicated_source=true. Unknown fields are rejected; all time
values are strict bounded integers, and overlap must be smaller than window_ms.
Do not put passwords or raw connection data in this setting. No deployed setting
or .env file was changed in this phase.

Shared sources require a common organization field and distinct values across
tenants. Dedicated-source assertions cannot coexist with other tenants' source
policies on the currently shared connection. The operator must establish that
the selected field comes from a trustworthy organization mapping, not an
attacker-controlled log string. The client verifies keyword mapping for the
organization field; each returned source is also checked locally against the
configured scalar value. Missing/ambiguous policies fail before any Indexer call.

The Indexer identity must permit index UUID and mapping reads as well as PIT
search. The service validates at most 100 concrete indices, UUIDs, date/keyword
sort mappings and doc values. Index metadata is checked before PIT creation,
after creation, and before each page commit. Metadata errors fail closed; the
current identity returns 403 for UUID metadata, so live activation remains
blocked. No permissions were changed and no fallback infers identity from names.
The query fingerprint binds manifest, policy, and connection identity. A changed
manifest, including normal rollover, conservatively stops for source-change
review; automatic rollover/reconciliation remains Phase 1.4.5 work.

One request drains one finite time window with bounded page memory. Initial
progress starts at the explicit bootstrap; subsequent windows overlap the
completed watermark and advance by at most window_ms, bounded by current time
minus the safety delay. An active window is replayed from its beginning with a
fresh PIT because raw PIT tokens are not persisted. No persisted sort position
is reused across PIT lifetimes. Only a validated empty page completes a window.
If not yet due, no checkpoint is created and no network request is made.

The service owns its request session transactions and rejects staged unrelated
writes. Authentication/read transactions are released before network calls.
Before writing each page, it rechecks API-key revocation, tenant ownership,
active integration, connection configuration, policy, and checkpoint generation.
Lock order is integration, checkpoint, then the existing tenant audit lock.
Evidence, audit event, counters, generation, and cursor are committed together.
The first checkpoint is created in the first successful page transaction.
Failed pages roll back entirely; previously committed pages remain durable.
Concurrent stale workers receive a conflict before writing. This is commit
protection, not the exclusive-worker lease planned for Phase 1.4.5.

Deduplication keeps the existing integration-prefixed reference and unique index.
On replay, stored evidence integrity is verified and canonical raw `_source` is
compared. Search transport metadata (sort, fields, score) may differ without
changing observed content. Existing evidence and its original hash are never
rewritten. Different source content, interpretations, and records from another
collector cause identity conflicts rather than silently substituting evidence.

Attempt time updates on successful page commits; success time updates only on
window completion. Failure-attempt/error recording is deferred to the status
phase and does not advance progress. Cleanup errors can occur after committed
pages or completed windows; an error response does not imply those commits were
undone. Clients must retry safely rather than reset checkpoints. No automatic
retry, scheduler, background worker, or production activation is included.
Requests are synchronous; large windows may exceed frontend timeouts. Exclusive
workers, ambiguous-commit recovery, polling, automatic rollover, and retention
reconciliation require their later subphases. Application rollback can disable
scope configuration and leave the additive checkpoint table unused.

### Phase 1.4.5 ownership and recovery

Migration `c82b5d3ea021` follows `b71a4c2d9e10` and was applied only to
`ai_soc_test`. It adds `wazuh_sync_leases` plus nullable checkpoint
`scope_fingerprint` and `source_manifest` fields. Existing progress and cursors
are preserved; no lease owners or source identities are guessed by the migration.
Lease rows use integration ID as primary key and the same composite tenant/
integration FK with RESTRICT ownership as checkpoints. Owner UUID and expiry are
both present or both absent. Fencing counters are positive and never reset when
an owner releases the lease. No secrets or raw PIT IDs are stored.

A synchronization authenticates and validates operator scope, then claims its
lease in a short transaction before Indexer access. A live competitor receives
`wazuh_sync_busy`. A locked integration also returns busy using NOWAIT rather than
waiting indefinitely. PostgreSQL `clock_timestamp()` governs acquisition, expiry,
renewal, and takeover; application wall-clock changes cannot extend ownership.
`WAZUH_SYNC_LEASE_SECONDS` defaults to 120, bounded to 30–900 seconds.

Workers renew before scan attempts and page reads. Write lock order is integration,
lease, checkpoint, then tenant audit lock. Owner UUID, fencing counter, and expiry
are checked with the lease row locked through the page transaction, then expiry
is checked and renewed before commit. A successor cannot take ownership while
that transaction holds the row lock. Expired or fenced workers fail before
committing; release predicates include tenant, integration, UUID, and fence, so an
old worker cannot release its successor. Normal exit releases ownership without
deleting the lease row. If cleanup fails or the process dies, expiry permits
takeover. Claim/renew/release never advance evidence checkpoints.

Retryable read failures (connection/timeout errors, HTTP 429/502/503/504, or lost
PIT searches) restart from freshly loaded durable state, at most three attempts
with 0.1/0.2-second backoff. New PITs replay active windows from their beginning,
never reusing prior snapshot positions. HTTP 403, malformed pages, identity
conflicts, and repeated/decreasing pages fail immediately. HTTP 500 is not assumed
transient. Permission checks, metadata validation, scope validation, and lease
ownership are repeated rather than bypassed by retry. The legacy offset client
does not gain automatic retries.

DBAPI errors explicitly marked connection-invalidated can also restart after
rollback and lease revalidation. There is no blind resubmission of COMMIT. A
new attempt rereads committed checkpoint state. Response counts are computed
from durable checkpoint counter/generation deltas, including commits whose
acknowledgement was lost. If the database cannot be reached or ownership has
changed, the request fails safely; a later owner resumes committed progress.
An uncertain lease-claim acknowledgement may leave an owner until expiry.

The stable scope fingerprint binds policy and connection, independent of the
snapshot's concrete index set. Durable source manifests preserve previously
observed UUIDs after window completion. Newly discovered indices can join later
windows; additions during a PIT scan are deferred until its successor. Missing
protected indices return `wazuh_sync_retention_gap`; UUID replacement returns
`wazuh_sync_source_changed`. Neither resets or advances progress. Index counts
remain bounded to 100. This detects observable identity loss, not history that
was already removed before the first bootstrap; full historical reconciliation
and upstream backups remain separate operational requirements.

Old checkpoints adopt stable identity only after recomputing and matching the
original snapshot fingerprint with current verified policy/connection and the
old manifest when available. An old idle checkpoint with no stored manifest
cannot safely adopt a changed index set; it stops for explicit review. Migration
tests cover both populated idle and active checkpoints without losing cursors.

Concurrency testing also reproduced an existing audit deadlock: two evidence
transactions held tenant FK KEY SHARE locks and each requested FOR UPDATE in
`record_audit_event`. The audit lock now uses PostgreSQL FOR NO KEY UPDATE,
which still serializes audit writers while allowing FK key-share locks. A barrier
test fails with the old lock and passes after the fix; hash chaining and
append-only protections are unchanged.

No scheduler or production activation was added. All workers must use this lease
protocol before synchronization is enabled; mixed versions that bypass leases
are unsupported. Rollback disables synchronization scopes and leaves additive
storage intact. Synchronous requests can still outlast frontend timeouts; expired
leases fail safe rather than guarantee uninterrupted processing under arbitrary
database/network stalls. Production metadata permission remains separately blocked.

### Phase 1.4.6 synchronization status

`GET /v1/integrations/wazuh/{integration_id}/sync/status` is authenticated and
tenant scoped. It is a database-only read: no Indexer calls, scope configuration
requirements, locks, renewals, or state updates. Owned inactive integrations are
visible. Missing and foreign integrations both return the same 404. Invalid
UUIDs are rejected by FastAPI; missing/revoked API keys use existing authentication.

The allowlisted response contains integration_id, integration_active,
checkpoint_status, completed_window_end_ms, generation, imported_count,
duplicate_count, has_committed_cursor, last_success_at, last_attempt_at,
last_finished_at, last_attempt_outcome, safe_error_code, and sync_lock_active.
No tenant IDs, connection details, credentials, raw cursors, fingerprints, index
manifests, owner tokens, PIT IDs, source filters, or raw exception messages are
selected as response data. The response model forbids extra fields and restricts
status/error strings to explicit literals. Each joined table has a tenant
predicate; a single SQL projection gives one coherent database snapshot.

No checkpoint means uninitialized progress and zero committed counts. It does
not imply no synchronization was attempted. A leased attempt can fail before any
checkpoint exists. Checkpoint fields continue to describe committed progress;
attempt fields independently describe the latest leased run. Last success is
updated only by successful window completion, so a later failure cannot erase
or advance it. Legacy checkpoint attempt times are shown as a fallback when no
new lease attempt time exists, but historical outcomes/finish times are not
inferred. An unavailable status database returns a fixed safe 503 error.

Migration `d93c6e4fb132`, following `c82b5d3ea021`, adds nullable last_attempt_at,
last_finished_at, last_outcome, and safe_error_code to `wazuh_sync_leases`.
It was applied only to `ai_soc_test`, preserving all ownership, fencing, expiry,
and checkpoint progress. Existing lease outcomes remain unknown. Database
constraints enforce allowed error codes, consistent running/terminal fields,
and nondecreasing attempt timestamps. Production migration remains pending.

Claiming a lease records PostgreSQL start time, running outcome, and no error.
Retries within the same lease belong to that one attempt. Finalization records
PostgreSQL finish time and succeeded, failed, not_due, or interrupted while
releasing ownership in the same short transaction. Both owner UUID and fence
must match. A late worker cannot overwrite a successor's attempt metadata.
Unknown exceptions map to processing_failed; exact internal codes map to the
fixed public allowlist without copying arbitrary text. A new attempt clears the
previous attempt's error. Success clears its own error; not_due is not a completed
synchronization. Normal helper release without an explicit outcome records an
interrupted attempt with lease_lost.

An expired lease whose persisted outcome is still running is reported as
interrupted/lease_lost, using PostgreSQL statement time. GET does not repair that
row or guess the actual stop time, so last_finished_at remains unknown. The
sync_lock_active flag reports unexpired ownership, not proof of worker health.
Rejected authentication, missing/inactive integrations, unavailable scope, and
busy competitors do not acquire a lease and do not replace the latest leased
attempt. The endpoint does not claim those rejections were synchronization runs.

If attempt finalization cannot reach the database, the primary synchronization
outcome is preserved and the lease expires normally. Status may temporarily
remain running, then interrupted; it cannot promise an accurate finish time
through a database outage. Attempt metadata never changes checkpoint generation,
cursor, evidence, audit events, counters, or the completed watermark. Application
rollback can stop using the endpoint/metadata while leaving additive columns
intact. Scheduling and live Indexer permission changes remain unapproved.

### Phase 1.4.7 optional scheduled ingestion

`scripts/run_wazuh_scheduler.py` is an explicit foreground entry point. Nothing
starts at API import/startup. No cron entry, service unit, container, dependency,
or production worker was installed. No database migration is required.

`WAZUH_SCHEDULER_ENABLED` defaults to false. `WAZUH_SCHEDULER_JOBS` defaults to an
empty JSON object and is bounded to 100 integrations. Each key is an integration
UUID; its value contains tenant_id, api_key_env, optional interval_seconds
(default 60, range 5–86400), and page_size (default 50, range 1–100). Unknown fields,
duplicate normalized UUIDs, invalid references, and non-integer limits are
rejected. API-key references must match `AI_SOC_WORKER_<NAME>_API_KEY`; raw keys
are never stored in job configuration. Referenced keys must be provided through
the worker process environment, not as CLI arguments. No existing .env file or
deployed configuration was changed.

Every execution opens a fresh database session and invokes the existing API-key
authentication function with the referenced secret. It verifies the configured
tenant matches the authenticated principal, then calls `sync_wazuh`. Integration
ownership, key revocation, source policy, metadata permissions, and lease fencing
remain enforced by the same synchronization path used for manual requests.
Authentication failures cannot fall back to another key or tenant. Logs include
only integration IDs and fixed safe codes; they never include key values,
exception reprs, or tracebacks. Audit events retain the authenticated API-key
identity rather than fabricating a system actor.

One job runs at a time per process. PostgreSQL leases prevent competing processes
or manual requests from synchronizing the same integration concurrently. Polling
uses monotonic time and schedules the next run after completion, so missed periods
do not create a catch-up queue. Busy leases defer for the normal interval. Failures
back off exponentially, starting with the normal interval, capped at the greater
of that interval or one hour. Success resets backoff. One job's failure does not
prevent other due jobs from running. Only configured jobs, next-run times, and
capped failure counters are retained; there is no growing history or task queue.
Large synchronous windows can delay other jobs in this intentionally serial
first worker; no cross-integration latency guarantee is made.

SIGINT/SIGTERM set a cooperative stop event. Idle scheduling waits and retry
backoff waits are interruptible. Synchronization checks before claiming a lease,
before new read phases, and between pages. If shutdown arrives during a page fetch,
the current validated page and its audit/checkpoint transaction finish together;
the next page is not fetched. The PIT is released and the worker's lease finalized
as interrupted. The existing safe status contract uses processing_failed as the
generic interruption code; no new database error enum was introduced. If the
current page exhausts the window, its successful completion remains successful.
A later run creates a fresh PIT and safely replays the active window. No thread
or transaction is force-killed. Shutdown may wait for in-flight HTTP requests and
database operations; it is not an instant cancellation guarantee.

The CLI supports `--once` for one due pass. Disabled/invalid configuration returns
exit code 2; a one-pass job failure returns 1. Both a production app environment
and the live `ai_soc` database name require the additional explicit
`--allow-production` flag. This flag is an activation capability, not approval:
using it requires the user's separate production authorization. It was not used.
The worker also remains disabled unless its enable setting is explicitly true.
All execution tests used mocked Indexer responses and `ai_soc_test`.

For future non-production operation after configuring scoped jobs and process
environment keys, run `python3 scripts/run_wazuh_scheduler.py --once` for a single
pass, or omit `--once` for the foreground loop. Run from the repository root.
Stop with SIGINT/SIGTERM and disable the enable setting for rollback. Committed
evidence, audit chains, counters, and checkpoints remain intact. Live activation
is still blocked by the previously observed Indexer UUID metadata permission.

### Transaction sequence

1. Authenticate and load the tenant-owned active integration. Dedicated source
   ownership or a trustworthy enforced organization filter is mandatory; the
   existing local tenant predicate does not isolate a shared upstream Indexer.
2. Establish a finite window and PIT, and record an active generation. Use one
   bounded page (maximum 100) at a time and finite request/PIT timeouts.
3. Fetch outside the database write transaction. Reject malformed hits/sort
   values, missing keys, oversize pages, timed_out responses, partial shards,
   expired PITs, and non-increasing positions. Empty validated pages exhaust
   the window; total-hit counts and short pages alone do not prove exhaustion.
4. Begin a short transaction; lock the tenant-scoped integration then checkpoint
   in consistent order. Revalidate active status, source fingerprint, snapshot,
   prior cursor, and generation. Stale workers must discard fetched results.
5. Preserve original hit documents and existing evidence hashes/source identities.
   Reuse integration-prefixed references and tenant-scoped ON CONFLICT dedup.
   A replay with a changed payload for the same identity must surface an identity
   conflict rather than silently treating changed content as a harmless duplicate.
6. Write evidence, hash-chained audit event, counts, page cursor, and generation
   in the same transaction. Acquire the existing tenant audit lock after the
   integration/checkpoint locks. Never commit the checkpoint independently.
7. Advance completed_window_end only upon verified exhaustion. Failure leaves
   prior committed page progress intact; roll back the entire failed page.
   Persist safe attempt/error status separately without advancing progress or
   overwriting a newer generation's status.

Generation checks and the Phase 1.4.5 lease jointly prevent stale commits and
concurrent active ownership. A resumed or expired worker cannot commit after a
successor takes ownership. Keep lease and audit lock order consistent.

On process crash, PostgreSQL rolls back the open transaction. Resume from committed
state if its PIT is still usable; otherwise replay the active window from its
beginning using a new snapshot identity and deduplication. Never reuse an old
PIT-specific position in a new snapshot. A lost commit acknowledgement is handled
by rereading checkpoint state and replaying safely. Bound retries with backoff.

## Late arrivals, retention, and index rollover

Use a configurable safety delay and overlap before the completed watermark.
Deduplication makes replay safe. Event time is not ingestion time: finite overlap
cannot guarantee arbitrarily late arrivals. The observed @timestamp date mapping
does not establish ingestion-time semantics. Verify a trustworthy ingestion-time
field before using it as such.

Periodic bounded reconciliation of retained indices is required for alerts
outside the overlap. Reconciliation has separate progress from normal windows.
Capture concrete names and index UUIDs; verify identity before resuming. New
rollover indices join subsequent scans. Missing/recreated indices and retention
that overtakes unprocessed history produce an explicit incomplete/gap state,
never silent success or automatic checkpoint reset. Monitor capacity so scanning
keeps ahead of retention. Data already removed upstream cannot be recovered by
this platform; report that limitation explicitly.

## Tests and acceptance by subphase

| Subphase | Required tests |
| --- | --- |
| 1.4.1 | Cursor round trips; strict invalid-input rejection; duplicate JSON keys; immutable values; equal timestamps across IDs/indices; repeated/backwards positions; context/ownership binding |
| 1.4.2 | PostgreSQL composite ownership FK; unique integration; state checks; existing integration compatibility; upgrade on ai_soc_test; populated migration behavior |
| 1.4.3 | Mocked first/next/empty pages; exact PIT/search_after request contract; 100-item bounds; shard failures/timeouts; missing/multi-valued keys; malformed JSON/sort; expired PIT; preserved raw hits |
| 1.4.4 | Atomic success; duplicate and changed-content replay; empty batch; evidence/audit/checkpoint failures; cross-tenant denial; no watermark advance on failure |
| 1.4.5 | Crash/restart; ambiguous commit; snapshot expiry; stale generation and lease fencing; concurrent workers; audit integrity; retention/rollover/recreated-index gaps |
| 1.4.6 | Authenticated status; cross-tenant/missing integration; safe schema; no credentials/PIT IDs/raw errors; invalid input |
| 1.4.7 | Poll interval; exclusive worker; bounded memory; shutdown; retry; checkpoint continuity; production remains disabled |

No routine test contacts the live Indexer. Database tests must explicitly target
ai_soc_test. The existing suite contains three mutation-protection tests that
attempt UPDATE/DELETE/TRUNCATE; these are excluded under the current prohibition
on destructive database operations. This is a reported verification limitation,
not a passing full-suite claim. The existing concurrency test commits test rows.

For 1.4.1, no runtime endpoint or schema changes exist. Rollback removes only
the cursor module, its tests, and this document; preserve all pre-existing work.
Each subsequent subphase requires approval before implementation.

## References

- https://docs.opensearch.org/latest/search-plugins/searching-data/paginate/
- https://docs.opensearch.org/latest/search-plugins/searching-data/point-in-time/
- https://docs.opensearch.org/latest/api-reference/search-apis/point-in-time-api/
- https://www.postgresql.org/docs/current/explicit-locking.html

Documentation describes possible features; installed behavior and existing
permissions must be verified independently as recorded above.
