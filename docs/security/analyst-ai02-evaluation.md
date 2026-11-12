# AI-02 — offline evidence assembly and source-support evaluation

Schema 1.0; implemented 2026-11-11. No LLM, I/O, retrieval, dispatch, database,
authorization grants, persistence, routing or orchestration. TG-04B remains paused
and blocked. Only trusted application code may supply AI-01 task, context,
authoritative snapshot, evaluation time and known-secret exclusions.

## Input assembly

`assemble_input` reuses AI-01 `validate_inputs`: exact tenant/principal, task,
original references, snapshot identity/digest, event/capture/task/deadline times,
classification and budgets are checked after bounded reconstruction. AI-01
envelope hashing remains unchanged. No extra evidence can be fetched or supplied
through model parameters. Every approved snapshot record is included or assembly
fails: there is no selection, omission or truncation policy.

`AnalystInput` separates trusted context/task objective from per-record metadata
and `untrusted_excerpt_json`. Source text is explicitly labeled
UNTRUSTED_DATA_NOT_INSTRUCTIONS. Provenance metadata records the authoritative
store's assertions; it does not establish source truth or change trust levels.
Structured boundaries preserve embedded instructions, forged JSON, delimiters and
Unicode controls as data. They do not establish resistance of a future model or
renderer to prompt injection. There are no trusted system prompt fields to fill
with source text. No privileged policy object is included, only AI-01's policy
reference. Tier remains advisory and creates no permissions.

Limits: 32 records/references; full canonical excerpt at most 4096 ASCII-escaped
JSON bytes per record; provenance text fields at most 1024 characters; aggregate
metadata/task/context at most 16 KiB; complete canonical package at most the task
input budget, never above 64 KiB. AI-01's conservative raw depth/node/byte limits
also apply. Escaped Unicode counts toward actual serialized bytes. Input budget
and classification live in the embedded immutable task; `truncated=false` and
`executable=false` cannot be changed. Package reconstruction rechecks full
envelope/snapshot integrity and canonical ordering.

Assembly rejects common credential assignment markers, credential-named payload
fields and application-supplied secret canaries, including nested decoded JSON.
It never silently redacts evidence. Missing/ambiguous sensitive-data classification
must be handled before admission by trusted code. Unknown or encoded secrets are
not comprehensively detectable: this is not DLP. Do not admit operational secrets.
Errors expose only stable codes; never log Pydantic input diagnostics.

## Proposal and evaluation

`AnalystProposal` wraps an unchanged AI-01 AnalystResult, up to 32 explicit
ID/hash citations and 48 typed SupportClaims. Citations must equal the union of
finding references, with exact authoritative envelope hashes. Claims identify
section/index, cited evidence ID/hash, kind, fixed source field and bounded value.
One claim per finding location; duplicates, unused citations, conflicting hashes,
unknown fields/versions and forged authority deny. All finding references must
remain inside the original authoritative snapshot.

`evaluate_result` first requires successful assembly, then AI-01 result acceptance.
It budgets the entire proposal and evaluation envelope against the task output
ceiling (at most 16 KiB), not just narrative text. INVALID returns no candidate
content. If even the fixed denial envelope exceeds the task budget, it raises
the sanitized `invalid_analyst_evaluation_budget` instead of returning excess
bytes. No valid task/budget can be inferred from malformed authority input.

Deterministic outcome precedence:

1. INVALID: malformed contract, scope/citation/hash violation, unsupported claim
   type or known contradiction with the cited source. Invalid results have no
   assessment attached. Known contradictions override insufficient evidence.
2. INSUFFICIENT_EVIDENCE: structurally accepted abstention/insufficient status or
   a typed check whose source field/original observation is unavailable. Preserves
   the original uncertainty, missing information and limitations without rewriting
   them or pretending missing support exists.
3. REQUIRES_HUMAN_REVIEW: arbitrary narrative not matching constrained source
   checks, interpretations, conclusions, severity inference or escalation proposal.
   Unverifiable TI verdicts, ATT&CK suggestions and detection assertions remain
   review material, never verified facts.
4. VALID: all findings are observations covered by exact typed comparisons and
   exact constrained prose `field = value`; no inferred severity, interpretations,
   conclusions or escalation. This means only source-field agreement and
   structural acceptance, not incident truth, authenticity, authorization or
   correctness of confidence, limitations or recommended next-step prose.

Every outcome is proposed-only and non-executable. Human review status creates
no approval workflow. Direct model construction is not acceptance: applications
must call these boundary functions with authoritative inputs, not trust submitted
AnalystInput/Evaluation objects. Compromised Python/host code can bypass checks.

## Implemented narrow checks

- IP_EQUALS: exact `source.ip` or `destination.ip` nested field; canonical IP
  equality. Invalid addresses/zones or literal dotted-key ambiguity deny.
- FIELD_EQUALS: exact string `rule.id`, or aware timestamp field. Timestamp must
  agree with both the asserted instant and authoritative envelope event time.
- EVENT_TIME_EQUALS: claimed aware instant equals authoritative event time.

Only original observation envelopes can support these checks. Missing source
fields mean insufficient evidence, not a negative fact. Duplicate JSON keys were
already rejected by AI-01. Malformed timestamps and ambiguous fields deny.
`rule.id` agreement is not proof a detection rule matched. No verified-match,
ATT&CK-taxonomy or TI-verdict checker is implemented; unknown typed claims deny,
and narrative assertions require review. Existing detection/correlation contracts
and algorithms are unchanged. A hash establishes integrity, never source identity.
No natural-language entailment, generic contradiction detection or truth engine
is claimed. A model can omit a factual claim from structured checks; uncovered
finding prose is therefore never VALID. Free-form recommendations remain proposals.

## Verification and next boundary

Synthetic tests exercise all tiers, full-package budgets, immutable serialization,
source/hash/identity attacks, unsupported conclusions, malformed timestamps,
conflicting source fields, synthetic/live confusion, secret-safe failures and
forbidden filesystem/network/process/DB import/dispatch access. AI-01, normalized
events, detection, correlation and gateway suites remain regression requirements.
No operational database or live environment is used.

Recommended AI-03, requiring separate approval: offline renderer/parser contract
and replayable adversarial evaluation fixtures for these packages/results. Keep
model invocation, tool routing, persistence and orchestration outside that scope.
