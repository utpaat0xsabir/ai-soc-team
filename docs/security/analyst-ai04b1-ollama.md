# AI-04B-1 — mocked Ollama chat adapter

Implemented 2026-11-12. Backend-only offline verification. No Ollama contact,
model execution/download, service activation, database, Wazuh, tool dispatch or
deployment. TG-04B live Wazuh remains paused/blocked. AI-04B-2 is not authorized.

## Integration and scope

`MockedOllamaProvider` implements existing AI-04A `generate(InferenceRequest)` and
emits one existing ProviderFrame. It does not assemble tasks, select models,
authorize tenants, retrieve evidence, parse analyst proposals or route agents.
The existing `run_inference` owns those boundaries, admission, cancellation and
result validation. It now admits exactly two code-owned implementations: the
existing FakeModelProvider or this mock-HTTP provider. One fixed local import
resolves the adapter; no plugin discovery, dynamic model-selected imports or
alternate inference pipeline exists.

Construction requires the exact `httpx.MockTransport` type, never None, a live
HTTPTransport, a supplied Client or a transport subclass. There is no default
transport or live activation flag. Control must be the same trusted object used
by the existing inference pipeline. Mock handlers are trusted test/application
code; do not admit arbitrary handlers from user/model input. Privileged Python
could itself perform I/O or bypass checks; this is not a process sandbox.

Existing immutable registry/profile/request bindings remain intact. Selecting
runtime ollama requires approved literal-loopback EndpointPolicy, explicit
artifact SHA-256, DEVELOPMENT_APPROVED/OFFLINE_SYNTHETIC descriptor, synthetic
task, non-streaming profile and ESTIMATED_BYTES_PER4_V1 accounting. A tag alone
is insufficient even for mock eligibility. A supplied digest/approval flag is a
trusted configuration assertion, not independent verification of installed bytes.
No actual runtime or artifact identity was inspected. Production approval stays
false. Different approved model IDs may be assigned independently per tier.

## Wire operation and destination controls

Only POST to a constructed `http(s)://literal-loopback:approved-port/api/chat`.
Endpoint host must be exactly 127.0.0.1 or ::1, with no hostname, credentials,
query, fragment or caller URL. Policy rejects cloud/private-LAN destinations and
other loopback aliases. IPv6 brackets are constructed by code. Redirects and
ambient environment proxies are disabled; no alternate provider, retry, discovery,
pull/show/list or browsing operation is available. An injected mock supplies every
response. Nothing here demonstrates ownership of a future process listening there.

Request shape is model, messages, format, stream=false and fixed allowlisted
options temperature/num_ctx/num_predict. AI-03 messages are translated exactly;
the code-owned output JSON schema is supplied as format. No tools or tool choice
objects are sent. No model family, quantization or specific tag appears in analyst
logic. The adapter does not log prompts, response text or exception messages;
HTTP client event hooks are empty. Normal HTTPX metadata logging may report the
fixed method/destination/status, never application-added body logs. Future runtime
and deployment logging policy still requires independent review.

## Bounds, completion and strict parsing

HTTP input bytes and estimated context are checked before the request. Wire
response headers are capped at 8 KiB and aggregate body at 64 KiB, read in bounded
chunks. Content-Type must be application/json; compression is rejected. Declared
length must be a bounded decimal, agree with actual bytes and not conflict with
Transfer-Encoding. Non-200 status never redirects/retries. HTTP timeout failures
map to TIMED_OUT; connection failures to sanitized FAILED. HTTP connect/read/write/
pool timeouts use remaining request/overall time. Trusted cancellation, deadline
and clock rollback are checked before HTTP, around reads, after response validation
and through final delivery in the existing pipeline. All paths release admission.

Non-streaming generation was deliberately selected. HTTP transfer may arrive in
chunks, but there is one completed JSON provider envelope, never accepted NDJSON
or partial generation. No output frame is emitted before full validation. Exact
wire fields: model, aware created_at, assistant message/content, done=true,
done_reason=stop, bounded prompt_eval_count/eval_count, and optional nonnegative
duration counters. Unknown fields, tool-call fields (even empty), injected schema
versions, missing completion, length-stop/truncation, mismatched model and malformed
or oversized envelopes deny. Duplicate JSON keys, non-finite values, Unicode and
depth/collection limits reuse AI-03 strict decoding. Its new provider-only arguments
permit bounded longer text and JSON whitespace inside the outer content string;
the default analyst response parsing policy remains unchanged.

Model content then passes the original strict AI-03 parser and AI-02 evaluator,
including exact task/citation hashes, scope, synthetic labels and narrow claims.
No echoed model identity can override request bindings. Existing chunk/frame
hashes bind the output to the original inference request. These hashes are not
runtime/artifact attestation. Invalid proposals deny; for this adapter, AI-02
INSUFFICIENT_EVIDENCE also denies with MISSING_EVIDENCE and no candidate attached.
Reviewable interpretations remain proposals requiring human review. Structural
acceptance never establishes semantic truth or source authenticity.

Raw content bytes are bounded separately from token counts. `num_predict` is
explicitly sent; returned token counters must also fit configured context/output
ceilings, but those counters are untrusted provider metadata. The context preflight
uses ceil(canonical UTF-8 bytes / 4) plus the output reserve. This is an estimate,
not a tokenizer-verified guarantee and not an OS/runtime resource boundary.
The existing fake provider retains its synthetic-byte accounting unchanged.

## Proposed development settings — not activated or independently verified

| Setting | Candidate |
| --- | --- |
| Runtime/model | Ollama / qwen2.5:1.5b |
| Quantization | Q4_K_M, owner-reported; not verified here |
| Endpoint | http://127.0.0.1:11434 |
| Context / output tokens | 2048 / 512 |
| Temperature / concurrency | 0.1 / 1 |
| Fallback / tools | Disabled |

No default approved operational configuration is installed. Test configurations
use dummy synthetic artifact digests and larger context allowances solely to test
wire behavior. The representative synthetic chat body measured 6275 bytes, giving
2081 estimated context units including a 512-unit output reserve. The 2048 proposal
therefore fails closed in the fixture; tests prove it is never silently increased
or evidence truncated. This is not a real token measurement or recommendation to
raise production limits. Native tokenizer/chat-template and hardware measurements
must resolve the actual fit before any later activation.

## Required AI-04B-2 readiness evidence

All following operational checks remain UNVERIFIED and separately authorized:

1. Installed Ollama version and compatibility with this exact strict chat wire
   contract, schema format and completion metadata; no assumptions from mocks.
2. Independently obtained artifact digest, quantization, license/provenance and
   exact tag-to-artifact mapping, including protection against replacement.
3. Approved capabilities, tokenizer/chat template, true context/output accounting
   and synthetic task/prompt fit. Installed/listed does not mean approved.
4. Exact bound loopback address/port, owning process/user and access controls;
   trusted TLS policy if selected; no exposed interfaces or hostname substitution.
5. Effective network/proxy/redirect/no-cloud-fallback policy and runtime egress.
6. Physical RAM, swap, free VRAM and measured safe concurrency/model residency;
   native process CPU/GPU/memory ceilings and model-loading serialization.
7. Controlled timeout, disconnect/cancellation and resource cleanup evidence.
   Closing a request does not prove remote generation stopped; cooperative checks
   cannot preempt a blocked mock handler or live process. OS enforcement is future.
8. Actual cross-process admission/quota policy if multiple workers exist; current
   lock/controller remains process-local and must be shared across calls.
9. Synthetic-only smoke-test inputs, secret-free logs and mandatory AI-01/02/03
   validation of every output; no tools, Wazuh, orchestration or real response.
10. Separate reviewed live transport implementation/eligibility approval and exact
    smoke-test limits/stop conditions. Removing MockTransport is not authorized.

HTTPX timeout configuration and offline tests do not establish OS CPU/GPU/memory
isolation, true token accounting or actual runtime cancellation. No models ran.
