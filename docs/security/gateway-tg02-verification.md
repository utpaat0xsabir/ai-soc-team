# TG-02 verification report

Verified 2026-11-11 on `master`, latest commit `78e97d5`. This is a design-and-test
milestone, not rollout authorization or proof of future runtime enforcement.

## Deliverables and preservation

New TG-02 files:

- [Threat model](gateway-threat-model.md): assets, attackers, nine trust boundaries,
  authorization binding, risk classes, consent/approvals, advisory analyst tiers,
  quotas, fail-closed rules, 24 adversarial scenarios and later release criteria.
- [Permission matrix version 1.0](gateway-permission-matrix.v1.json): 16 operation
  profiles, five proposed resource profiles, TC-01 through TC-47, and explicit
  `design_only`, `runtime_consumed: false`, default-deny semantics.
- `tests/test_gateway_permission_design.py`: 57 offline design-consistency,
  abstract decision-table and unchanged-runtime denial checks.
- This verification report.

Pre-existing untracked `services/api/app/tool_gateway.py` and
`tests/test_tool_gateway.py` were preserved. Their SHA-256 values matched before
and after this task. `AGENTS.md` and `docs/development-handoff.md` also matched.
No existing tracked files, runtime contracts, database schema, endpoint, worker,
credential, network configuration or integration was changed. No dependency
installation, commit, push, deployment or service activation occurred.

## Checks performed now

| Check | Result |
| --- | --- |
| Initial TG-01 baseline | 71 passed in 0.19s |
| Test-first design check | Failed as expected with FileNotFoundError before the matrix existed |
| Final TG-01 + TG-02 focused run | 128 passed in 0.25s: 71 existing + 57 new |
| Compilation | 65 Python sources compiled using the existing Python 3.10 virtual environment; bytecode redirected to `/tmp` |
| Whitespace | `git diff --check` plus explicit checks of all four new files, including trailing whitespace and final newlines |
| Preservation | TG-01 source/tests and both protected instruction/handoff documents retain their baseline hashes |

Reproduction commands from repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -p no:cacheprovider tests/test_gateway_permission_design.py tests/test_tool_gateway.py
PYTHONPYCACHEPREFIX=/tmp/ai-soc-tg02-pycache .venv/bin/python -m compileall -q services/api tests scripts
git diff --check
```

Ordinary Git diff checks omit untracked files, so the new documents/test also
receive explicit whitespace checks. No runtime settings/database module is needed
by this focused selection, and no live URL or credential is supplied.

## What the tests establish

The matrix contains every catalog ID exactly once, uses unique explicit candidate
capability names, references defined operation/resource profiles and requires
adapter version pinning. It records all binding dimensions and common admission
checks, unknown-version denial and no tier-based authority. Numeric ceilings are
finite and structurally checked. Sensitive operations require human approval;
external disclosure requires consent. Candidate checks separate existing lookup,
new submission, endpoint collection, rule drafting, activation and response.

The decision-table tests model a missing authorization predicate as denial for
every advisory tier. This is an abstract specification oracle, not an implemented
policy engine and not proof that a future service derives the predicates safely.

Each of the 15 non-mock planned operation profiles is submitted to unchanged TG-01
using a matching proposed grant. All deny with zero adapter calls, no evidence,
and a denial audit event. The matrix does not enable those operations. Existing
TG-01 security tests continue covering identity/grant/registry mismatch, forged
models, ambiguous identities, replay, limits, unsafe output, digest tampering,
sink boundaries and forbidden I/O.

## Limits and deferred evidence

TG-01 remains a serial synthetic-only library with trusted caller-supplied context
and grants, test lists and in-memory replay scope. It does not authenticate users,
enforce the new proposed quotas/deadlines, provide sandbox isolation, persist
approvals/consent or guarantee concurrent/durable audit atomicity. Sensitive
operations remain unavailable. The broader controls are requirements, not findings
that current runtime already enforces them.

No full regression, DB-backed test, migration, role/login operation, protected
`ai_soc` access, live Wazuh/provider query, security-tool execution, external
network access or provider/license verification was performed. An independently
confirmed safe full-suite database environment was not established. Historical
687-test offline and earlier full-suite results are not rerun claims for TG-02.
The earlier unresolved health-test stall was not investigated in this scope.

Future acceptance needs actual enforcement tests for consent/approval expiry and
revocation, data redaction, source mapping, SSRF/egress, malicious artifacts,
concurrent quotas/approval consumption, durable replay, atomic persistence and
crash/rollback recovery. Those scenarios are specified in the threat register;
they require separate milestone authorization and isolated test environments.

## Completion and stop

TG-02 is complete as a design-and-test milestone. TG-03 and later controls remain
planned and unimplemented. No master roadmap ID or repository roadmap was changed.
Next proposed milestone is TG-03 design/implementation planning for disclosure,
redaction and egress controls, requiring separate explicit approval. Stop here.
