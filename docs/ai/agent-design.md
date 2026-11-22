# Local analyst agent design

[Existing contracts](../../services/api/app/analysts/contracts.py) define task, snapshot and result shapes. The [inference implementation](../../services/api/app/analysts/inference.py) includes model/profile policy, bounded requests, admission controls and deterministic fake providers. [Ollama provider work](../../services/api/app/analysts/providers) includes mocked and gated transport paths. Existing offline L1 orchestration stays synthetic and proposed-only.

A production provider adapter should advertise structured output, streaming, context and cancellation capabilities. Pin the endpoint class, local model/artifact digest, prompt revision, schema, generation settings and tier profile. Validate output independently of provider claims. A configurable tier profile can select a small quantized L1 model and larger L2/L3 analysis where measured benefit justifies cost. Use local time, token, memory, concurrency and per-tenant budgets. No cloud fallback.

Compose prompts using immutable policy context separated from labeled untrusted evidence. Return JSON with cited observations, hypotheses and alternatives, confidence rationale, information gaps, proposed severity and proposed tool requests. Reject unknown fields, unrelated citations, expired evidence, forbidden disclosure, malformed streams and unauthorized stage changes. Persist safe model metadata and inference receipts, with controlled access to sensitive traces.

An agent may request an approved evidence-gathering tool by typed ID and scope. Gateway policy decides disclosure and authorization and applies budgets and audit. A model cannot invoke arbitrary shell, network, adapters or SQL. Preserve idempotency and require independently approved human decisions before executing any high-impact action. [Orchestration](../architecture/agent-orchestration.md) · [Gateway threat model](../security/gateway-threat-model.md)

On unavailable or invalid inference, retain deterministic alerts and evidence views, emit a structured unavailable or abstained result, and route to human triage. Separate model research from integration authorization.
