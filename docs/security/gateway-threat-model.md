# Security Tool Gateway threat model and permission design

TG-02, version 1.0, 2026-11-11. Status: design and offline verification only.

This document and [permission matrix](gateway-permission-matrix.v1.json) specify
future acceptance requirements. They are not runtime configuration, grants,
installation permission or activation approval. Runtime code does not load them.
TG-01 remains the only implemented gateway: one synthetic IP reputation lookup.
Master milestone 3.5 is evidence-to-case relationships; internal 3.5.1 is TG-01.
Neither identifier is renamed by this work.

## Scope and security objectives

Protect tenant isolation, principal authority, customer assets, evidence integrity,
audit completeness, disclosure choices, credentials and host availability. A model
may propose work; trusted deterministic code must decide whether any operation
can run. No analyst tier, model output, tool description or provider result grants
authority. All real integrations, credentials, egress, persistent approvals,
storage, agents and response execution require later separate authorization.

The JSON matrix defines 16 operation profiles and candidate mappings for TC-01
through TC-47. A candidate's presence does not establish installation, licensing,
supported versions, callability, customer consent or a grant. Even where an
existing Wazuh client exists, adoption by this gateway is not authorized.

## Current TG-01 implementation and limitations

Sources: `services/api/app/tool_gateway.py`, `tests/test_tool_gateway.py`.

- Strict frozen schema-1.0 contracts: TrustedContext, ToolCapability,
  ToolRequest, ToolGrant, ToolObservation, ToolResult and GatewayAudit.
- Exact registry: mock.ip_reputation version 1.0, lookup, risk `passive`,
  read_only=True, external_disclosure=False, synthetic=True. R0 below is a design
  classification; it does not replace the runtime's `passive` value.
- Context/grants are trusted caller inputs, not authenticated by this module.
  Request tenant/principal claims are checked against that context. Python type
  validation cannot establish who created a context or grant.
- Canonical IP and flat immutable key/value parameters. Only
  `(("dataset", "synthetic-v1"),)` is dispatchable. IP validation is not a
  public-IOC disclosure classifier; private IPs in a synthetic lookup never leave
  the process. Other target types require a separately approved contract version.
- Duplicate/conflicting grants, unknown capabilities/versions, identity mismatch,
  changed inputs, oversized requests/results and unsafe responses fail closed.
- Response is always `unknown`, labeled SYNTHETIC / TEST ONLY. A mock result must
  never become a live reputation assertion, incident fact or response trigger.
- Request/result SHA-256 values verify internal content, not source authenticity
  or confidentiality. Hashes of guessable indicators can permit inference.
- Caller-owned list sinks are test-only, bounded and serial. Replay detection
  depends on retaining these lists. No durable replay protection, transaction,
  concurrent reservation, audit chain, wall-clock deadline, CPU/memory enforcement,
  tenant rate limit, consent lifecycle or human approval system is implemented.
- Frozen models can be bypassed by malicious Python in the same process. Input
  reconstruction catches tested forgeries, but this is not process isolation.
  An attacker controlling gateway code/host can defeat these checks.
- Output checks happen after adapter invocation and before successful sink
  append. They cannot prevent effects already performed by a future adapter.
  Pre-dispatch authorization and independent runner/egress controls are required.

Current numeric limits are recorded under `tg01_implemented_limits` in the JSON.
All other matrix ceilings and controls below are proposed, not newly enforced.

## Assets, actors and trust boundaries

| Asset | Security need |
| --- | --- |
| Tenant evidence, cases, lineage, artifacts and results | Correct ownership, confidentiality, immutable provenance and content hashes |
| Identity, grants, registry, policy and approval/consent state | Authentic source, version binding, freshness, revocation and least privilege |
| Endpoints, fleets, indexed logs and customer networks | Lawful scope, source mapping, bounded access and no unintended effects |
| Provider credentials, keys and service identities | Gateway-only resolution, least privilege, no model/output/log disclosure |
| Audit events, request identity and quotas | Durable integrity, consistent reservations and trustworthy retry state |
| Gateway/runner host and tenant capacity | Isolation, resource ceilings, cancellation and fair admission |
| Tool binaries, rule packs, templates and provider data | Pinned provenance, validation and separation from authority |

Attackers include unauthenticated callers, another tenant's authenticated user,
an overprivileged or compromised principal, a prompt-injected model, a malicious
log/artifact author, a compromised intelligence provider, a hostile binary/plugin,
and an operator making a scope/configuration error. A database/host administrator
is privileged: application checks alone do not prevent administrator tampering.
Independent audit anchoring and operational separation remain future controls.

| Boundary | Trusted side and required enforcement |
| --- | --- |
| B1: caller/model/log to authentication | Authentication middleware verifies identity using trusted credentials; request text cannot select tenant/principal. No external LLM is assumed. |
| B2: authentication to authorization | Trusted principal state, tenant ownership, grants and policy are resolved server-side; validate revocation and exact scope. Never deserialize a model-supplied TrustedContext/ToolGrant. |
| B3: policy/registry to adapter dispatch | Operator-controlled explicit registry pins capability, operation, adapter/schema/version and effects. Missing policy or version denies. |
| B4: gateway to tenant source | Enforce actual source ownership and trustworthy source-to-tenant mapping in the query; do not fetch a shared source then distribute by untrusted payload labels. |
| B5: gateway to external provider | Consent, minimization, provider terms and exact allowlisted egress checked before transmitting bytes; no model-controlled URL or credentials. |
| B6: gateway to binary/remote asset | Approved runner or asset operation only, explicit artifact/asset identity, enforced ceilings and no ambient privileges. |
| B7: adapter output to evidence/model | Validate source, type, bounds, tenant and request correlation; quarantine untrusted text and keep interpretations distinct from observations. |
| B8: gateway to audit/evidence/quotas | Atomic tenant-scoped state and durable retry identity before production use; no success or checkpoint advancement after failed processing. |
| B9: human approval to executor | Independently authenticated approver and immutable decision binding; expiry/revocation/use checked immediately before effects. |

Future trusted authentication derives tenant and principal from the authenticated
session/API key. A delegated agent identity must also bind to its initiating
principal and delegation scope; a service account is not a tenant wildcard.
Application tenant checks remain required even with shared database roles.

## Versioning and exact authorization binding

Matrix version 1.0 is a design namespace, not a TG-01 runtime version upgrade.
Policy decisions must pin a matrix/policy version and registry digest. A changed
permission, risk, target type, parameter schema or adapter version requires a new
reviewed version and reauthorization; never interpret an unknown version as the
nearest compatible one. An adapter version includes pinned binary/image and
backend/rule-pack digests where applicable. No actual binary versions are asserted
here; adoption must verify them first.

Bind a future authorization decision to all of:

1. Trusted tenant, principal, active delegation and request/retry identity.
2. Exact capability identifier/version, operation and policy/registry version.
3. Typed canonical target, materialized asset/source selector and customer scope.
4. Canonical typed parameters, query template/rule version, result/disclosure
   limits, and immutable artifact identifier/version/content digest where used.
5. Applicable consent scope and approval scope, including recipient and purpose.
6. Execution identity, runner image and effective resource ceilings.

Absent artifact/consent/approval fields must have a validated explicit
`not_applicable` representation when the operation requires none, never a
wildcard. Exact matching and uniqueness apply to identity and authorization
records; conflicting records deny rather than selecting the broadest grant.

Canonicalization occurs before comparison/hash/approval: IP normalization;
provider-specific domain/URL rules; typed asset IDs; allowlisted query templates
and bounded time/index selectors; sorted duplicate-free parameter keys. Reject
ambiguous encodings, duplicate serialized keys, Unicode/control ambiguities,
wildcards, arbitrary SQL/shell, recursive structures and parser limits exceeded.
The future ingress parser must reject duplicate JSON keys; TG-01 takes validated
Python models and does not implement that ingress boundary.

No raw filesystem path, arbitrary URL or fleet expression is authority. Artifacts
are immutable tenant-owned references with verified content hashes; defend against
symlinks, path traversal, archive expansion and object replacement. Targets such
as asset groups must be resolved to a bounded exact set before approval; changes
require a new decision. IP reassignment and source-index rollover require trusted
identity checks, not string equality alone.

Authorization is the intersection of authenticated identity, explicit grant,
registered operation, tenant/source ownership, asset scope, current policy,
consent/approval where required, available quota and healthy enforcement. Any
failed or unknown predicate denies. A matching tier or earlier successful request
does not repair a failed predicate.

## Operation permission matrix

The JSON is the authoritative design table. Profiles are operation-specific
minimum gates, not permission bundles. Entries named `not_authorized` remain
unavailable regardless of suggested tier. Later adapters need independent approval
and exact grants. Unlisted operations deny.

| Profile | Risk | Scope/effect | Consent minimum | Human approval minimum |
| --- | --- | --- | --- | --- |
| mock_lookup | R0 | Synthetic, in-process unknown verdict | No disclosure permitted | None for mock |
| local_query | R1 | Existing tenant-owned records only | None if within tenant-controlled boundary | Not ordinarily; sensitive-data policy may require it |
| local_transform | R1 | Offline bounded decode/transform | No egress | Not ordinarily |
| offline_analysis | R2 | Parse untrusted evidence in isolated runner | No egress | Additional approval for particularly sensitive artifacts |
| external_lookup | R2 | Existing provider report/indicator lookup; disclosure occurs | Exact third-party disclosure consent | Required if tenant policy raises risk |
| hunt | R1 | Bounded searches over existing tenant telemetry | None if tenant-local | Not ordinarily; expensive/sensitive hunts may require it |
| rule_draft | R1 | Offline draft/translation/validation only | No egress | No activation authority |
| export | R3 | Separately controlled evidence/PCAP export | Add consent if recipient is external | Required |
| active_scan | R3 | Active interaction with exact authorized assets | Add consent for any external recipient | Required |
| remote_collect | R3 | New endpoint data acquisition, including live read-only queries | Add consent for any external recipient | Required |
| submission | R3 | URL/file/report submission; may trigger scanning | Required | Required |
| publish | R3 | Share/publish intelligence or evidence | Required | Required |
| modify | R3 | Change configuration or remote state | Add consent for any external recipient | Required |
| rule_activate | R4 | Deploy/enable a detection or enforcement rule | Add consent for any external recipient | Required |
| response | R4 | Containment/remediation/playbook effects | Add consent for any external recipient | Required |
| detonate | R4 | Execute suspect artifact in dedicated isolated environment | Egress denied; any disclosure separately reviewed | Required |

Risk is multi-dimensional: source mutability, endpoint interaction, disclosure,
artifact execution, operational impact and resource consumption. A read-only API
can still disclose sensitive data. A tool name does not determine risk. Risk may
be raised by target/data/operation; it must never be lowered by an analyst tier.

Examples in the JSON separate existing osquery/Velociraptor results from new
endpoint collection; URLscan existing results from new scan submission; Sigma
drafting from rule activation; Cortex local analysis from provider lookup and
response; and Shuffle discovery from execution. Arbitrary analyzers/recipes,
packet capture, fleet SQL, response, reporting and uploads cannot hide under
`query`, `lookup` or `analyze`. An operation's combined effects require every
applicable gate. A lookup API that implicitly scans/submits must be denied under
external_lookup and separately classified before any use.

Public feeds may later be ingested without sending customer indicators, but need
a distinct approved acquisition capability; they do not inherit blanket lookup
permission. Internal MISP/OpenCTI means tenant-controlled deployment with proven
tenant isolation. A managed/external deployment instead requires external_lookup
and disclosure review. Cross-tenant sharing is disclosure even on a local server.

## L1, L2 and L3 advisory routing

L1 normally proposes triage, decoding and passive existing-report checks. L2
normally proposes host/network/artifact/timeline investigation. L3 normally
proposes bounded hunts, malware analysis, ATT&CK mapping and rule drafts. These
labels guide task routing and visible suggestions only. They do not authenticate
an actor, create grants, waive consent, enlarge a target or approve execution.

An L1 principal with an explicit valid grant may be authorized for its exact
operation; an L3 principal without that grant must be denied. HUMAN also does not
mean administrator or automatic approver. Response candidates are routed for
human review, not directly callable by AI. A formal handoff transfers task intent,
evidence IDs/hashes, provenance and uncertainty; the receiving actor needs its own
authenticated authority and must reauthorize every operation. Approval and quota
state cannot be copied as free-form handoff text.

## External disclosure consent and privacy

For any customer data crossing its authorized boundary, require an authenticated
tenant data-authority decision covering recipient/provider/account, operation,
purpose, exact canonical indicators or batch digest, data fields, visibility,
retention/jurisdiction terms, validity interval and revocation/version. A cached
consent must still be current at dispatch. A boolean True in a request is never
consent evidence. TG-01's False only declares that its mock permits no disclosure.

Public-IOC classification and redaction are future TG-03 acceptance requirements:
deny private/internal/reserved/link-local/loopback identifiers, credentials,
customer names, internal domains, secret-bearing URLs and unclassified data by
default. Public reachability alone does not establish permission or anonymization.
Provider SDK telemetry and redirects are disclosure surfaces too. Minimize data,
never attach unrelated log context, and record only sanitized policy outcomes and
appropriately protected hashes. Hashing is not encryption or a privacy guarantee.

Verify provider license/commercial terms, quotas, redistribution, scan visibility
and privacy conditions at adoption. No current provider terms are asserted or
verified by TG-02. A free API or catalog entry is not commercial-use authorization.
Local result caches are tenant-scoped and keyed by provider/account, operation,
indicator, versions and consent scope; a cache hit never bypasses authorization.
No cache or consent storage is implemented here.

## Human approval and execution lifecycle

Sensitive operations require an independently authenticated authorized human
approver distinct from the delegated requester. The LLM cannot approve itself.
Bind approval to tenant, requester/delegation, approver, exact operation/version,
target set, parameters/artifact hashes, risk, purpose, visibility, policy version,
maximum uses, time window, cancellation and recovery plan. Expired, revoked,
reused, self-approved or differently scoped approvals deny. Consent and approval
are separate; neither substitutes for an operation grant or lawful asset scope.

Future lifecycle: validate -> authenticate -> canonicalize -> resolve exact scope
-> authorize -> reserve quota/retry identity -> verify consent/approval -> record
intent -> recheck revocation/version/kill switch -> dispatch -> validate output
-> atomically record completion/evidence/audit and release capacity. Recheck before
every effectful step. Production admission must fail closed if audit, authorization,
reservation or enforcement state cannot be established.

Consume approval uses and quota atomically to defeat concurrent replay. Cancellation
must fence pending work; already transmitted requests/effects may be irreversible.
Do not promise rollback of disclosure or packet transmission. Ambiguous outcomes
require reconciliation against provider/action identity, never blind resubmission.
Maximum attempts starts at one: no automatic retry of scans, submissions, collection
or response. Later read-only retry policies need explicit bounded budgets and
must count additional disclosures. Preserve evidence/audit/checkpoint consistency;
failure must not appear as successful processing.

## Quotas, ceilings and fail-closed conditions

The JSON contains explicit proposed ceilings for wall/CPU time, memory, control
input/output bytes, artifact bytes, targets, records, processes, attempts,
tenant concurrency, per-principal/per-tenant rates and daily disclosures. Values
are initial design maxima, not measured performance or configured enforcement.
TG-01 only enforces its separately recorded four existing numeric limits.

Effective ceilings are the minimum of reviewed profile, tenant policy, grant,
provider allowance, consent, approval and runner capacity. Zero means prohibited,
not unlimited; absent/unknown/invalid values deny. Control input excludes artifact
content; artifacts have their own verified size ceiling. Large memory/disk images
exceeding the proposed 64 MiB artifact ceiling deny until separately reviewed and
versioned; do not silently truncate or raise limits to accommodate a tool.

Reserve tenant/provider quotas atomically before dispatch, include all attempted
disclosures, bound pagination/aggregate results and prevent one tenant exhausting
shared capacity. Use a trusted clock, handle clock rollback/expiry conservatively,
and do not reset budgets on retry or worker restart. Never return truncated results
as complete. Isolated runners need enforced deadlines/cancellation, read-only
evidence mounts, bounded scratch, no secrets/host mounts, nonprivileged identities,
process limits, and no ambient network. Active operations need a different reviewed
egress policy restricted to approved assets; model-controlled networking is absent.

Deny on missing/ambiguous auth, grant, registry, version, target ownership, source
mapping, parameters, consent, approval, adoption/terms verification, budget, retry
state, audit readiness or runner enforcement. Deny duplicate/conflicting identities,
stale snapshots, redirects/DNS rebinding, altered artifacts/parameters, output
identity mismatch, unbounded decompression and unknown response schemas. No default
adapter, fallback provider, wildcard role or exception-to-allow behavior is permitted.

## Threat register and adversarial acceptance scenarios

Existing coverage names refer to `tests/test_tool_gateway.py`. Future scenario
IDs are specifications, not claims of implemented defenses. For pre-dispatch
denials assert zero adapter/runner/network calls, no evidence or progress writes,
and a bounded sanitized denial event where the audit boundary is available.

| ID / attacker scenario | Mitigation and required acceptance test | Coverage / later gate |
| --- | --- | --- |
| A01: model claims tenant/principal/admin/L3 authority | Trusted auth context; reject request authority fields; no tier override | TG-01 untrusted-request/modified-request tests; real B1/B2 integration later |
| A02: valid user targets another tenant/source | Exact ownership and enforced source mapping; mixed-tenant denial | TG-01 mixed-policy tests; TG-04 actual query/source tests |
| A03: grant or registry version drift | Pin exact operation/version/registry/policy; deny stale/unknown | TG-01 grant/registry tests; TG-04 drift tests |
| A04: duplicate/conflicting IDs or approvals | Reject ambiguity; atomic single-use execution identity | TG-01 duplicate/replay tests; TG-07/09 concurrency tests |
| A05: parameters, target, asset group or artifact replaced after approval | Snapshot/hash exact scope; revalidate at effects; no mutable reference authority | TG-01 modified-input tests; TG-06/09 race tests |
| A06: leaked credentials in exception/output/log | Sanitize errors; isolated secret resolver; redact logs and outputs | TG-01 unsafe-output/sanitized-denial tests; TG-03/10 canary-secret tests |
| A07: injected URL reaches metadata/local service; redirects or DNS rebinding | Provider-owned routes, pinned destinations, address classification and independent egress enforcement | TG-03/05; zero sockets for denied cases |
| A08: public-looking IOC contains private hostname or URL token | Typed classification/minimization and exact consent before encoding/transmission | TG-03; no outbound bytes for private/ambiguous/secret values |
| A09: consent absent, expired, wrong provider/account/purpose or revoked midflight | Recheck scope/current state; deny before transmission; never infer consent from tier | TG-03/05 race/expiry tests |
| A10: lookup endpoint implicitly uploads/scans | Separate operation IDs and all effect gates; no fallback or hidden SDK telemetry | TG-05/09 request-contract tests |
| A11: missing/self/expired/revoked/used human approval | Independent human and exact immutable binding; atomic use and cancellation fencing | TG-09 adversarial approval tests |
| A12: prompt/tool-output injection tells model to change policy or execute shell | Treat text as untrusted data; no grant parser or execution from tool text | TG-01 forged-field tests; TG-08/10 multi-step injection tests |
| A13: arbitrary plugin, query, recipe, path or binary | Explicit pinned registry and typed templates; no discovery, expression evaluator or arbitrary shell | TG-01 registry/forbidden-I/O tests; TG-04/06 template/path tests |
| A14: malicious artifact exploits parser or archive expansion | Isolated nonprivileged runner; artifact hash/size, extraction/process/resource limits; no egress | TG-06 exploit/canary/timeout tests |
| A15: provider lies or sends wrong tenant/target, huge output or instructions | Schema/provenance/identity limits; quarantine untrusted text; no evidence promotion | TG-01 output/digest tests; TG-05/10 spoof/streaming-size tests |
| A16: mock output is presented as observed threat truth | Immutable synthetic/source label; evidence type remains synthetic interpretation | TG-01 success/output tests; TG-07/08 synthetic propagation tests |
| A17: concurrent calls bypass quota or consume approval twice | Atomic reservation and unique execution identity; deterministic saturation denial | TG-07/09 parallel-worker tests; not covered by list sinks |
| A18: crash after effect, before receipt; replay after restart | Durable intent/outcome/reconciliation; no blind repeat or false success | TG-07/09 crash/ambiguous-commit tests |
| A19: audit/evidence failure produces partial success | Atomic tenant storage; rollback and no checkpoint advance; preflight audit availability | TG-01 preserves existing sink records on failure; TG-07 rollback/fault tests |
| A20: shared cache leaks another tenant's data or consent | Tenant/account/version/consent-scoped cache and authenticated reads | TG-05/07 cache isolation tests |
| A21: privileged operator tampers with policy/audit | Separated administration, reviewed artifacts, append-only records and independent anchoring | TG-07 and master 11.7; privileged host compromise remains residual risk |
| A22: noisy tenant, output bomb, slow provider or killed runner | Atomic quotas, bounded streaming, deadlines and cancellation; no unbounded retries | TG-01 limit tests; TG-05/06/10 saturation tests |
| A23: analysis discovers malware and automatically responds | Analysis has no response grant; new independently approved response decision | TG-08/09 escalation/no-dispatch tests |
| A24: downgrade design or broaden candidate routing to imply grants | Pin matrix version/digest; advisory tier cannot satisfy any missing authorization predicate | TG-02 decision-table tests; later trusted policy-version integration |

## Later milestone release criteria

| Milestone | Required evidence before claiming runtime readiness |
| --- | --- |
| TG-03 | Public/private/ambiguous IOC classification, redaction, recipient/purpose consent, commercial-terms adoption records and independent egress denial tests; no live calls without approval |
| TG-04 | Exact typed local read-only operations, pinned adapter versions, enforced source ownership, safe templates, tenant/principal/version/target negatives and no-dispatch assertions |
| TG-05 | Provider-specific existing-report contracts, consent/terms/quotas/cache isolation, bounded timeout/streaming behavior, SSRF/redirect/secret tests; no submission under lookup |
| TG-06 | Verified image/artifact provenance, offline isolation, CPU/memory/wall/output/disk/process ceilings, malicious-file tests and host/network canaries |
| TG-07 | Durable tenant ownership, append-only audit integrity, provenance/result hashes, unique retry identities, concurrent admission, atomic evidence/audit/intent and rollback/ambiguous-commit tests on ai_soc_test |
| TG-08 | Scoped capabilities and formal L1/L2/L3 handoffs; independent recipient authorization; prompt/tool-output injection cannot grant authority or cause dispatch |
| TG-09 | Independent human approval binding, expiry/revocation/use, kill switch, concurrency, cancellation, reconciliation and action-specific recovery; separate authorization for every effectful operation |
| TG-10 | Combined A01-A24 adversarial/regression evidence, measured resource bounds, actual enforcement failure tests and explicit residual-risk sign-off |

TG-02 completion requires versioned documented profiles, full candidate coverage,
explicit bindings and gates, current-vs-proposed distinction, adversarial scenarios,
passing design consistency checks and unchanged TG-01 behavior. Decision-table
checks are abstract specification checks; they do not verify authentication,
network isolation, consent storage, approval enforcement, quotas or production
atomicity. See [verification report](gateway-tg02-verification.md).
