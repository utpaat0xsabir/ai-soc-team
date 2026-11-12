# AI-03 — offline prompt, response and replay protocol

Schema/template version 1.0, implemented 2026-11-12. Model-independent only.
No Ollama/other model, client, database, file loading, evidence retrieval, tools,
HTTP endpoint, worker, routing, persistence or orchestration. TG-04B remains
paused and blocked. Existing AI-01/AI-02, detection and gateway interfaces remain
unchanged. This protocol produces proposals, never execution permission.

## Trusted application boundary and rendering

`render_prompt(context, task, snapshot, package, at=trusted_time)` requires the
authoritative application context/task/snapshot alongside the existing AI-02
AnalystInput. It reconstructs and revalidates these contracts, rejects forged
unknown model attributes before serialization, and compares the entire package
against fresh AI-02 assembly at its recorded evaluation time. Current task
validity is checked separately; future-dated packages deny. A self-consistent
replacement package is insufficient without the authoritative caller inputs.
Authentication and evidence-store admission remain the application's duties.

PromptEnvelope binds task digest, package digest, snapshot ID/digest, tier,
classification and instruction/schema versions. Digests identify bytes, not
authentic issuers. The two immutable message roles are fixed:

- system: a code-owned static common boundary plus an allowlisted L1 triage,
  L2 investigation or L3 hunting instruction. No variable source text or objective
  is inserted here; there is no developer message role.
- user: canonical ASCII-escaped JSON containing the application-selected task
  objective, task type, snapshot identity, evidence provenance/IDs/hashes and
  explicitly marked untrusted excerpts. Source metadata is data too. Tenant and
  principal authority fields and the policy reference are omitted from this
  projection; strings in evidence can still contain forged identity assertions.

Original source references, hashes, timestamps and synthetic classification are
preserved. No evidence is omitted, truncated, repaired or fetched. Embedded roles,
JSON, shell commands, delimiters and bidirectional controls in evidence remain
quoted data. They cannot choose message roles, templates, schema or grants.
They may still influence a future model: delimiters/roles and these tests do not
prove model resistance to prompt injection. Future renderers must preserve this
separation rather than concatenating data into system instructions.

The output schema is derived directly from existing AI-02 AnalystProposal, stored
as immutable canonical JSON in the envelope with ID `ai02.AnalystProposal@1.0`.
No competing result/evidence model or externally loaded template is introduced.
Schema content and system instructions are checked against code-owned values.
Only template 1.0 is accepted. Any future template/schema change requires review
and versioning; dependency/source artifacts must be pinned before model adoption.

The complete serialized envelope, including messages, schema and metadata, must
fit the smaller of the trusted task input budget and caller prompt ceiling,
never above 64 KiB. Message lengths and schema size are bounded. AI-01's
conservative traversal limits may reject otherwise byte-small packages. Canonical
ASCII escaping avoids encoding/serialization ambiguity; no tokenizer budget or
model-specific chat transformation is claimed. Known-secret exclusions and AI-02
credential-marker checks run again during authoritative assembly. Unknown/encoded
secrets are not comprehensively detectable: admit only minimized secret-free data.

## Wire response and parsing

`parse_response(context, task, snapshot, response, at=trusted_time)` accepts bytes
or text for exactly the existing AnalystProposal JSON document. The top-level
proposal and result must explicitly declare schema_version 1.0. The model cannot
supply context, task type, snapshot authority, tenant/principal identity, grants,
approval state or execution flags. These are unknown fields and deny, including
false-valued execution flags. Task ID/tier/escalation still undergo existing
contract and AI-02 evidence validation against the original caller context.

Before decoding, enforce strict UTF-8 and the smaller of the trusted task output
ceiling and 16 KiB. A lexical scan bounds nesting (16) and collection openings
(256), ignoring delimiters inside strings. Decode one complete JSON document:
no fences, prose, concatenated documents, BOM repair or best-effort extraction.
Ordinary surrounding JSON whitespace is allowed. Duplicate keys, including nested
and escape-equivalent keys, non-finite constants/overflowing floats and integers
outside the bounded representation deny. No retries or automatic corrections.

Decoded traversal permits at most 4096 nodes, 64 list members, 32 object members,
64-character keys and 1024-character strings, subject also to the existing schema's
tighter limits. Cc/Cf/Cs Unicode categories (controls, format controls and
surrogates) deny in decoded model strings/keys. This intentionally restricts
multiline/control-bearing model output; source evidence is still preserved as
untrusted data during rendering. Valid printable Unicode is not normalized.

The duplicate-free, bounded decoded tree is canonically serialized for existing
Pydantic JSON-mode UUID/tuple validation. This typed-validation pass is not a
retry of malformed wire output. Every structurally valid proposal then passes
through AI-02 `evaluate_result`, preserving all evidence checks and narrow IP,
rule-ID and event-time comparisons. No cited field is promoted to source truth.

ParseResult separates:

- MALFORMED: invalid wire encoding/JSON/limits or unsupported/invalid response
  schema. Contains only a fixed reason and no candidate/evaluation content.
- REJECTED: invalid trusted caller inputs or AI-02 INVALID. Evidence rejection
  retains only the sanitized INVALID evaluation, never candidate text.
- ACCEPTED: AI-02 VALID, INSUFFICIENT_EVIDENCE or REQUIRES_HUMAN_REVIEW. Acceptance
  means an admissible proposal, not semantic correctness, source authenticity,
  approval or execution. Uncertainty and missing-information fields are preserved.

The complete parser result is output-budgeted. If an accepted wrapper would
overflow, return a sanitized rejection. If even a rejection cannot fit a valid
task's budget, raise only `invalid_analyst_parser_budget`. When trusted inputs
cannot establish a valid task/budget, return a fixed bounded control-plane
TRUSTED_INPUT_INVALID rejection, without treating untrusted claims as a budget.
Never log underlying Pydantic/JSON exception inputs. All outcomes are non-executable.
Contract construction alone is not admission: use the public boundary functions.

## Replay and adversarial corpus

`replay` takes 1–32 unique immutable ReplayCase objects in memory. Each contains
a bounded raw response (at most 32 KiB, including deliberate invalid UTF-8), fixed
expected status/reason/outcome and a restricted case ID. No fixture file loading
or model invocation occurs. It renders one authoritative prompt and replays every
response at the supplied deterministic time. ReplayRecord contains only case ID,
prompt digest, actual categories, expectation match and executable=false. It
contains no response body, candidate text, credentials or exception details.
Mismatch is recorded, not silently converted into a passing expectation. Digests
are not privacy protection for guessable input data.

The synthetic test corpus includes 28 replay cases: valid output, duplicate and
escape-equivalent keys, fences/prose/multiple documents, depth/size/UTF-8 attacks,
NaN, unknown versions, identity/grant/approval/execution injection, task/tier/
escalation bypass, synthetic-to-live substitution, fabricated citations/hashes,
contradictory IP, invented TI/ATT&CK prose, credential leakage and bidi controls.
Additional tests cover all tiers, source prompt injection, exact schema/role
preservation, wrong authoritative bindings, malformed numbers, collection/string
limits, strict Unicode, source-field checks, insufficient evidence, immutability,
budget errors, replay mismatch/reproducibility and forbidden I/O/model/dispatch.

No natural-language truth engine, generic contradiction detector, LLM injection
certification, durable audit/replay protection or host/process sandbox exists.
Privileged Python/host code can bypass these contracts. Semantic review, real
authentication and operational enforcement remain separate requirements.

## Next separately approvable milestone

AI-04 recommendation: offline, injected fake-model transport contracts for
bounded response streaming, cancellation/deadline handling and exact request/
response binding. No real model, network, tools, persistence or orchestration
without fresh authorization. Stop after AI-03 verification.
