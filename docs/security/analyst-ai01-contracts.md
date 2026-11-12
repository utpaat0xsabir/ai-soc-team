# AI-01 analyst contracts — schema 1.0

Implemented 2026-11-11, offline only. `analyst_contracts.py` defines proposals and
pure validation, not an analyst service or an authorization system. No settings,
database, network, clock, LLM, gateway dispatcher or persistence is consulted.
TG-04B remains paused/blocked. No other milestones are activated.

## Application and model boundary

Reuse gateway `TrustedContext` and strict frozen version-1.0 base contracts.
Only authenticated application code supplies context, AnalystTask and authoritative
EvidenceSnapshot. Python objects do not authenticate their creator. Do not expose
task creation, snapshot building or context reconstruction to model arguments.
Only AnalystResult is a model candidate; constructing it does not accept it.
Call `validate_assessment(context, task, snapshot, candidate, at=trusted_time)`
before consuming a candidate. Unknown fields (including tenant/principal overrides,
grants and approvals), versions and unsupported transitions fail closed. The
returned ValidatedAssessment remains proposed-only and non-executable, never a
gateway grant, source-authenticity attestation or persistence authorization.

The validator reconstructs bounded immutable inputs, checks tenant/principal,
task and snapshot identities/digests, original evidence membership, supplied time,
deadline, classification and total canonical input/output budgets. The complete
validated wrapper counts toward the output budget. Tasks last at most 24 hours;
snapshots cannot postdate task creation and evidence cannot postdate capture.
No implicit retries, routing, escalation execution or response actions exist.

## Evidence boundaries

EvidenceReference is an in-memory projection of a trusted evidence envelope, not
a second evidence store. It binds ID, tenant, source/reference, event time,
collector provenance, trust level, classification and content hash. Payload is a
bounded canonical JSON object string to preserve deep immutability. The existing
`calculate_evidence_hash` validates the original envelope; no hash algorithm or
existing detection/correlation contract is changed. Duplicate JSON keys, non-JSON
constants, deep payloads, duplicate IDs, invalid ownership and changed hashes deny.

The allowlist includes Wazuh, normalized-event, tool-result and analyst sources;
observation, interpretation and conclusion evidence types remain distinct.
Snapshot digests additionally bind ownership, IDs, order-canonicalized references,
capture time and classification. Hashes prove neither source authenticity nor
truth: trust labels must come from the authoritative store, not model assertions.
Evidence remains untrusted data even when its provenance is source-verified.
All text, including embedded instructions and fabricated citation strings, has
no authority. Structured finding IDs must resolve inside the supplied snapshot.

Limits: 32 evidence items; 8192 characters per payload JSON input; 64 KiB maximum
canonical snapshot and task-plus-snapshot budget; task output ceiling at most
16 KiB; 16 findings per observation/interpretation/conclusion group; 1024 characters
per narrative string. Conservative raw traversal adds depth/node/byte limits and
may reject inputs below the final serialized ceiling. No silent truncation.

## Analyst responsibility and results

L1 tasks are triage; L2 investigation; L3 hunt. Objectives and finding prose can
describe their respective proposed classifications, hypotheses, activity/scope
analysis, ATT&CK suggestions or detection improvements. Tier selects task type
and permissible escalation proposal, never tool permissions. L1 may propose L2,
L2 may propose L3, and all tiers may propose human review or NONE. L3 cannot
escalate into an autonomous response role.

Results separate observations, interpretations and conclusions. Every
EVIDENCE_LINKED finding needs explicit citations, including at least one original
observation in the approved snapshot. Hypotheses may lack citations only with
zero overall confidence and explicit uncertainty. Observations cannot be marked
as hypotheses. ASSESSED requires linked support; INSUFFICIENT/ABSTAINED require
zero confidence and unknown severity. Every result requires uncertainty and
limitations. Membership does not prove entailment, detect every contradiction or
determine whether prose matches a tier's responsibility: semantic evaluation and
human review remain necessary. Findings are never promoted into verified evidence.

## Privacy and prompt injection limits

No credential/approval/grant fields exist. Acceptance rejects common credential
assignment/Bearer/private-key markers and exact known-secret values supplied by
trusted application code. Errors from the acceptance boundary are the stable
`invalid_analyst_assessment`, without candidate text. Do not serialize underlying
Pydantic diagnostic input structures into logs. Pattern/canary matching cannot
detect arbitrary unknown, encoded or paraphrased secrets. Minimize and remove
secrets before admitting evidence; this milestone provides no DLP guarantee.

Prompt injection is contained structurally: log instructions do not alter trusted
scope or execute anything. No prompt construction or model behavior is evaluated.
Compromised application/host code can forge inputs or bypass this pure validator.
No durable revocation, approval, audit, concurrency or replay protection is claimed.

## Verification and next approval

Synthetic tests cover identity/citation/integrity boundaries, malformed and oversized
inputs, immutable serialization, escalation proposals, secret-safe errors and
forbidden I/O/dispatch. Existing event, detection, correlation and gateway suites
are regression requirements. Database/live suites remain excluded under scope.

Recommended AI-02: offline deterministic analyst-input assembly and result
evaluation fixtures using these contracts, including adversarial semantic cases;
no model invocation, tools, routing or persistence without separate approval.
