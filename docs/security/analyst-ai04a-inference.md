# AI-04A — offline inference foundation

Schema 1.0; implemented 2026-11-12. Backend-only, synthetic fake execution.
No model installation, Ollama/vLLM client, endpoint probe, HTTP route, database,
environment lookup, background worker, gateway tool or orchestration exists.
TG-04B live Wazuh remains paused/blocked. Existing analyst/gateway contracts and
operational Settings are unchanged. Only trusted application code supplies model
configuration, context, authoritative evidence, clock, cancellation and admission.

## Configuration and approval

ModelDescriptor records model ID, family, runtime, endpoint reference, artifact
identity/optional SHA-256, local/self-hosted classification, CHAT/JSON_SCHEMA/
STREAMING capabilities, context/output maxima, memory/CPU requirements, approval,
evaluation and accounting mode. Production approval is explicitly false. Model IDs
are configuration data: `qwen2.5:1.5b` could be a future reviewed assignment, but no
family/model name appears in analyst logic or is installed/verified here. Test
fixtures register only synthetic model identities, never claim to run Qwen.

ModelRegistry has at most 16 unique model entries and 16 endpoint identities.
Duplicate IDs/artifact aliases, unapproved/unevaluated models, missing required
capabilities and mismatched runtime/endpoint references deny. Registry/profile
ordering is canonical. Unknown schema versions and unknown fields deny. Approval
flags must originate from trusted configuration admission, never model text;
contracts cannot authenticate who created Python objects or verify an artifact.

Three independent AnalystModelProfiles bind L1/L2/L3 to exact registered model
IDs, model schema 1.0 and configuration versions. Each specifies context/output
units, temperature, timeout, overall deadline, concurrency, streaming, byte/chunk
limits and JSON_SCHEMA mode. No implicit profile, auto-selection, download,
fallback, dynamic import or plugin lookup. Profiles cannot exceed descriptor
capabilities/maxima. Model selection never creates gateway grants or analyst
escalation/response authority. Changing an assignment/version changes request
identity; it does not constitute production adoption approval.

## Endpoint policy: contract versus enforcement

EndpointPolicy is a no-network contract. IN_PROCESS is available only for runtime
`fake`, with no host, port or protocol. Proposed LOOPBACK policies permit only
literal 127.0.0.1/::1, an exact approved port and http/https. No arbitrary URLs,
userinfo, credentials, DNS hostnames, redirects, ambient proxies or substitutions
are representable. An initial future Ollama proposal is loopback:11434, separately
reviewed by an operator; it is not active or probed. Activation remains
PROPOSED_ONLY. A future local runtime still requires independent endpoint identity,
access-control/TLS review as applicable, and default-deny egress evidence.

`run_inference` refuses every selected runtime except fake/IN_PROCESS and every
provider implementation except the exact closed FakeModelProvider type. Even an
approved LOOPBACK registry entry or object implementing the provider protocol
cannot run. These restrictions, rather than network configuration claims, establish
the current no-network boundary. No cloud/remote destination or fallback path exists.

## Request and result binding

`prepare_request` validates typed, bounded authoritative inputs before serialization
and invokes AI-03 rendering against AI-02 assembly. Only SYNTHETIC / TEST ONLY
tasks are admitted. InferenceRequest embeds the validated prompt, selected model,
profile, endpoint, tenant/principal/task/tier, snapshot, registry/configuration
digests, creation/timeout/deadline and synthetic label. A namespace UUID derived
from canonical request content is deterministic for identical inputs; a separate
SHA-256 binds that UUID and all fields. Time, registry, profile version and artifact
changes affect identity. No random IDs, wall-clock defaults or hidden settings.
Hashes bind content, not authenticity, confidentiality or durable replay protection.

The existing prompt/proposal/parser/evaluation models remain authoritative.
LocalInferenceProvider defines `generate(InferenceRequest) -> Iterator[ProviderFrame]`;
provider metadata is untrusted and grants no tenant or evidence authority. Each
frame must echo the exact request ID/digest, snapshot digest, selected runtime/model,
sequence and chunk/stream hashes. These are checked against trusted request state,
not used to derive identity or select a different model. Stream hashes detect
inconsistency, not a malicious runtime that knows the request. Final source
validation always uses original application inputs, never echoed model authority.

Only after a complete stream does AI-03 parse the bytes and AI-02 evaluate all
findings. A malformed/rejected model response returns a denial; accepted insufficient
or human-review findings remain such inside a COMPLETED inference proposal.
COMPLETED does not mean semantically correct, authentic or incident-confirmed.

InferenceResult is strict, immutable, synthetic-labeled, FAKE_MODEL / TEST ONLY
and executable=false. Status/reason combinations are checked. Errors contain no
raw response/exception text; rejected streams return no partial output. The full
result envelope is bounded by task/profile output bytes. If even fixed denial
metadata cannot fit, raise only `invalid_inference_result_budget`. Request assembly
errors are sanitized as `invalid_inference_request`; do not log underlying
Pydantic input diagnostics. Existing secret-marker/canary checks remain necessary
but are not comprehensive DLP or proof of model safety.
Malformed task budgets never control serialization; without a valid budget,
return only the fixed bounded INVALID_INPUT denial, without candidate content.

## Fake provider and budgets

FakeModelProvider contains an immutable, bounded script of at most 64 FakeSteps,
each at most 32 KiB, plus a closed fault selector and test invocation counter.
It snapshots/revalidates the script before generation. Steps simulate normal or
partial output, failure, cancellation and elapsed time without sleeping. Faults
simulate wrong request/snapshot, unauthorized model fallback, bad checksums,
sequence and malformed frames. Invalid JSON, forged task/citations, contradictions,
escalation and other analyst attacks are supplied as synthetic response bytes.
No source, prompt or model output can choose another provider or configure a fault.

Per-operation enforcement:

- Complete serialized request/prompt bytes cannot exceed task/profile input limits
  (at most 64 KiB). Context reserves the configured maximum output allowance.
- SYNTHETIC_UTF8_BYTES_V1 counts canonical UTF-8 prompt bytes and raw output bytes
  as synthetic token units. It is explicitly not a tokenizer for any real model.
  UNVERIFIED accounting denies; real token accounting requires later adoption.
- Output buffer is checked before append against task bytes, profile bytes and
  synthetic output-token allowance (profile maximum 8192 units). At most 64 chunks,
  with any tighter profile limit applied. Nonstreaming profiles require one final
  frame. Bad sequence/hash, overflow, incomplete output or data after final deny.
- Injected trusted time/cancellation are checked before generation, around every
  frame, at provider completion, before parsing and after parsing. Clock rollback,
  invalid controls and cancelled work cannot be accepted. Provider timeout covers
  generation; overall deadline includes validation and is capped by task deadline.
  Simulated elapsed time can only tighten deadline checks, never extend them.
  A final cancellation/deadline check also precedes result delivery after cleanup.
- No automatic retry, queue, worker, model loading or fallback. Admission slots
  release in finally on success, denial, overflow, timeout, cancellation and failure.

AdmissionController uses a lock and shared process-local state: global capacity
1–4, per-model artifact capacity from active/requested profiles, and duplicate
in-flight request-ID denial. A permissive new profile cannot override an active
lower limit. Release checks the original request digest. The application must
reuse the same controller across calls; fresh controllers/processes do not share
quotas. This is not durable replay prevention or multi-process admission.

Memory/CPU descriptor values are reviewed resource requirements, not installed
OS/process quotas. Fake scripts/loops/buffers are bounded by these explicit
structural limits; no model process is created. Cooperative checks cannot preempt
blocking arbitrary Python, callbacks or a future live transport. Trusted callbacks
must remain bounded. Hard termination, native tokenizers, model residency/loading
limits and OS-enforced resources remain future live-runtime requirements.

## Verification and exact AI-04B prerequisites

Synthetic tests cover all tiers and independent family assignments; immutable
registry/profile/request identity; invalid approvals/capabilities/endpoints;
fake model injection; malformed/contradictory output; frame integrity/completion;
input/output/context limits; clocks/cancellation; admission/release; secret-safe
errors; and forbidden filesystem/network/DB/model imports/subprocess/gateway use.
Existing AI-01/02/03 and gateway/PRE2/event/detection/correlation regressions apply.
No operational database or real runtime tests are authorized/performed.

Before any separately approved AI-04B live implementation/activation:

1. Explicitly approve the exact local engine, API/version, artifact digest/license,
   model roles and reviewed source/configuration artifact; no implicit Qwen adoption.
2. Verify isolated host/process, exact loopback peer/port and access controls,
   protocol/TLS decision, no proxy/redirect/DNS/cloud fallback and enforced egress.
3. Provide pinned tokenizer/chat-template/context accounting, structured-output
   compatibility and measured profile memory/CPU/VRAM/residency limits.
4. Design bounded live streaming, strict response/request metadata, hard timeout,
   cancellation/termination, cleanup and safe handling of ambiguous completion;
   use mocked transport tests before permitting live requests.
5. Establish shared admission across actual workers/processes, model-loading
   serialization, current trusted identity/configuration approval and secret/data
   minimization. Do not reuse test counters as operational controls.
6. Preserve mandatory AI-01/02/03 validation and exact request isolation; authorize
   any change to the current fake-only dispatch eligibility separately.
7. Approve a minimum synthetic smoke test with exact model/profile/limits and
   stop conditions. Passing offline tests alone never authorizes a real request.

AI-04B implementation, model installation/execution and live activation remain
separate approvals. No tools, Wazuh, persistence, orchestration or deployment is
implied. Stop after AI-04A.
