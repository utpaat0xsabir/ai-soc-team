# AI-04B-2A.1 — prompt projection and disabled live transport

Implemented 2026-11-12, exclusively offline. No HTTP request to Ollama, real model,
privileged host inspection, service/configuration modification, database, Wazuh,
tool dispatch, orchestration or deployment. AI-04B-2A readiness remains BLOCKED;
TG-04B live Wazuh remains paused/blocked. No operational capability is issued.

## Unchanged authority and optimized projection

AI-01/02 contracts and AI-03 parser/system instructions are unchanged. The complete
authoritative prompt, tenant/principal/task/snapshot/registry/profile bindings,
evidence and provenance remain in the existing InferenceRequest and digests.
Internal repetition is retained where it binds independent validation boundaries;
it is not removed or treated as model input simply because it is stored internally.

`ollama_prompt.py` adds an immutable schema-1.0 OllamaPromptPlan with projection
version `title-only-v1` and accounting version
`OPTIMIZED_BYTES_PER4_OVERHEAD128_V1`. This is a wire/budget record, not another
analyst or evidence schema. It strips only JSON Schema title annotation keywords
from the outgoing format. It preserves properties/definition names, required,
additionalProperties, types, constraints, references and actual const/enum/default
data, including properties named title. No descriptions, defaults, evidence,
provenance, task objectives, system instructions or refusal/uncertainty requirements
are removed. All messages are byte-identical to the original wire projection.

The full original schema stays in the AI-03 prompt and Pydantic parser. Expected
wire content is rebuilt from the authoritative request; `validate_plan` rejects
tampered projections even after an attacker recomputes all local hashes/metrics.
Unknown versions, changed constraints, source omissions, system-role substitution
or scope/digest changes deny. No truncation or automatic limit increase.

The existing AI-04B-1 accounting mode and baseline behavior are preserved. The
new mode is selected only through trusted configuration and changes the bound
request/configuration digest. No existing operational profile, approval flag,
context limit or output limit is edited. Tests use synthetic-only configurations.

## Measured fixture and accounting policy

| Measurement | Original | Optimized |
| --- | ---: | ---: |
| Outgoing HTTP chat JSON bytes | 6275 | 5455 |
| bytes/4 rounded up | 1569 | 1364 |
| Explicit additional chat-overhead reserve | legacy mode: 0 | 128 |
| Output reserve | 512 | 512 |
| Estimated total under respective modes | 2081 | 2004 |
| Authoritative internal AI-03 envelope bytes | 7541 | 7541, retained |

Wire reduction is 820 bytes; with the same 128-unit reserve the original would
estimate 2209 versus optimized 2004. The old internal-envelope heuristic was 2398,
but that includes metadata not transmitted to the model. The new compact plan is
7001 serialized bytes for this fixture; it is a diagnostic/binding envelope and
is not added to model-context usage. Native tokenizer usage is UNVERIFIED.

New offline admission calculation is deterministic:

`ceil(actual complete outbound JSON UTF-8 bytes / 4) + 128 + configured output reserve`

Counting the entire outbound body includes all system/user messages, schema,
model/options and serialization overhead. The extra reserve represents estimated
chat-template overhead. It is not an independently established upper bound for
the installed tokenizer/template, and bytes/4 is not a native token count. Thus
2004 fits the proposed 2048 only as an **offline estimate**, leaving 44 estimated
units; this is not evidence of safe real-model fit. No output/context ceiling was
raised and no evidence was dropped. Larger inputs or reserves fail closed.

Internal-envelope and complete-request byte limits remain enforced separately
(at most 64 KiB with tighter trusted profile/task limits). Context admission uses
the exact outgoing projection, not internal bookkeeping. Output byte/token policy
and returned counter checks remain in the existing adapter/pipeline. No claim of
tokenizer accuracy, semantic correctness or host resource enforcement is made.

Operational admission is a separate mandatory gate. Plans always declare
`native_tokenizer_verified=false`, `operational_admission=BLOCKED`, executable=false.
Those fields cannot be relabeled through a plan/model claim. Until independently
approved tokenizer/template bounds and all host evidence exist, no real request
is admitted even if the estimate fits. Existing default/legacy 2048 rejection is
unchanged; only mock verification may exercise the new estimated mode.

## Live-capable mechanics, unreachable operational authority

`GatedOllamaTransport` implements HTTPX BaseTransport, and
`GatedLiveOllamaProvider` implements the existing generate-to-ProviderFrame interface.
Both reuse the AI-04B-1 chat-generation implementation and validators. The ordinary
`run_inference` eligibility still admits only FakeModelProvider and exact
MockedOllamaProvider; the gated provider is not registered, even in offline mode.

There is no issuer, verifier, positive sentinel, environment switch or boolean
authorization implementation. `_require_operational_clearance` always raises
`live_ollama_transport_disabled` for every supplied object. It runs before real
HTTPTransport construction/socket use. The default provider validates exact policy
and then denies at this gate. A future operational activation requires reviewed
code implementing trusted verification and separately changing provider admission;
ordinary configuration, task parameters, model output or caller flags cannot do it.

The currently unreachable live branch specifies HTTPTransport retries=0,
trust_env=false, one connection and no keepalive pool. It permits only exact POST
`http://127.0.0.1:11434/api/chat`, no credentials/query/fragment, hostname alias,
IPv6 alternative, different scheme/port/path, cookie or authorization headers.
All timeout phases must be finite, positive and at most 60 seconds; the shared
adapter sets tighter remaining request/overall deadlines and disables redirects
and ambient proxies. Gated provider policy requires concurrency one.

The independent `offline(MockTransport)` factory exercises the same constrained
exchange/stream cleanup mechanics without issuing a capability. It accepts only
the exact in-memory transport type, never a default transport, live transport or
subclass. It cannot be promoted into an operational path by an env/model flag.
Tests bridge it through the existing exact MockedOllamaProvider to verify normal
AI-03 parsing/AI-02 evaluation, rather than adding another inference pipeline.
Direct offline gated-provider frames are untrusted until those validators run.

Requests and headers are bounded before exchange. Responses reject redirects and
oversized headers; a managed stream bounds aggregate bytes at 64 KiB and closes
its underlying stream/transport on close or overflow. Shared adapter validation
still rejects unsafe content/transfer encoding, length mismatch, unexpected status,
bad JSON, tool calls, partial generation, model mismatch and unsupported metadata.
Response headers cannot replace the body model identity or authoritative request.
No retries, tool definitions, provider fallback or external API paths exist.

## Cancellation, resources and assurance limits

Existing trusted clock/cancellation checks surround reads, completion, parsing and
delivery. Shared admission slots release on every failure; response context and
managed stream clean up HTTP resources. Mock tests demonstrate cleanup on timeout,
cancellation and overflow and rejection of incomplete responses. They do not prove
GPU generation stops on disconnect or that a blocked live call is preemptible.
HTTP timeouts remain cooperative/transport-phase controls, not hard OS deadlines.

One-request transport/profile policy does not coordinate other clients/processes.
Application checks do not establish CPU/RAM/VRAM quotas or adequate memory/swap
headroom. Host-admin/compromised Python code can patch private functions or bypass
these boundaries; this is not an execution sandbox or cryptographic issuer.
No operational capability was constructed, including in tests.

The previous readiness review verified local blob integrity but not publisher
authenticity, exact active-server artifact binding, release version, socket/PID
ownership, service proxies or firewall enforcement. It observed nearly full swap
and unlimited service resource ceilings. Those observations are historical and
were not re-inspected in this offline milestone. A model tag or matching local
SHA-256 is never promoted to publisher authenticity or operational approval.

## Verification and next separately approved milestone

Tests reproduce the baseline, measure optimized bytes/reserves, preserve evidence
and semantic schema constraints, reject rehashed mutations, prove deterministic
serialization, deny missing/forged capabilities and unsafe destinations, and block
real sockets/HTTPTransport construction. They cover redirect/proxy behavior,
headers/model mismatch, failure/retry counts, output overflow, cancellation/cleanup,
admission release and unchanged analyst/gateway regressions. All responses are
injected synthetic mocks; no endpoint is contacted.

Next: separately approve completion of the read-only readiness evidence and native
tokenizer/template accounting review. Resolve server version, exact process/store/
artifact binding, egress/proxy controls, memory/swap/VRAM and enforceable resource/
cancellation controls. Only then propose a capability issuer/verifier and activation
review. No live request, service change, model installation, Wazuh, IAM migration,
orchestration, persistence or deployment follows from this milestone.
