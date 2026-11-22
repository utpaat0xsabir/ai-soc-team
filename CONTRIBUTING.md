# Contributing to AI SOC Team

Start with the [current state](docs/architecture/current-state.md), the [next milestones](docs/project/next-milestones.md), and [AGENTS.md](AGENTS.md). Keep experiments synthetic and local. The separate earlier prototype is outside this repository's scope.

## Set up for offline work

From the repository root, create a Python 3.10 virtual environment and install the reviewed dependencies. Installation may require network access to an approved package source. Offline environments can use a previously reviewed wheel cache.

```sh
python3.10 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
git diff --check
```

For Python changes use scoped pytest node IDs, starting with the reviewed [offline selection](tests/offline-selection.json). The selection is an inventory, and the test environment must separately deny external I/O. Follow the [offline verification notes](docs/architecture/backend-modular-refactoring-ref01.md) for synthetic settings and test doubles. Keep database credentials absent, prevent dotenv loading, and block socket, real HTTP and database operations. Database-backed modules share directories with pure tests. Inspect fixtures and imports before executing a selection. Use `.venv/bin/python -m compileall -q services/api tests scripts` for syntax checks.

Inside that guarded environment, a first synthetic test selection is:

```sh
.venv/bin/python -m pytest tests/analysts/test_analyst_contracts.py
```

The command selects tests. Establish the I/O boundary before running it. Database tests require separately authorized, explicitly pinned disposable `ai_soc_test` and a verified test identity. Live Wazuh, Ollama, migration, and privileged fixtures each have distinct approval boundaries. Check the [deployment models](docs/architecture/deployment-models.md) and [security index](docs/README.md) before planning them.

## Choose a small contribution

| Contributor | First contribution | Evidence to submit |
|---|---|---|
| AI engineer | Add a synthetic L1 abstention or invalid citation case. | Dataset revision, expected structured outcome, and deterministic baseline comparison. |
| SOC analyst | Label a synthetic alert with observations, competing explanations, escalation rationale, and missing evidence. | Two reviewer labels or a record of disagreement with the evidence IDs. |
| Detection engineer | Add a bounded detection or correlation fixture with a benign near-match. | Positive, negative and tenant-isolation tests with the expected rule/version. |
| Security researcher | Review one trust boundary, such as result disclosure or replay, using a defensive fixture. | A sanitized finding, impact, and a fail-closed regression. Keep sensitive findings private until a maintainer confirms the disclosure route. |
| Backend engineer | Add tenant-qualified validation or bounded recovery to an existing domain. | Tests for isolation, retries and rollback. Describe compatibility with stored data. |
| Integration developer | Create a fixture-based adapter against a versioned contract. | No customer data or keys. Verify cursor behavior, deduplication and tenant binding. |
| Documentation contributor | Trace a status claim to a source file and test or decision. | Update the [evidence index](docs/project/documentation-evidence-index.md) and verify links. |

## Review expectations

State the intended outcome, trust boundary, affected interfaces, tests and failure recovery. Keep source and expected results readable. Include negative cases around authorization, concurrency, isolation, malformed input and partial completion when relevant. For AI changes, report structured-output failures and abstention as well as successful cases.

Use synthetic, redacted fixtures with documented rights. Keep credentials, raw customer incident data and unreviewed indicators out of Git. Separate research from implementation and runtime activation. Changes to roles, database state, deployments or external privileges require their own approvals. Preserve audit and evidence guarantees under failure and retry.

Keep architecture changes in the relevant design page and decision references in the [decision log](docs/project/decision-log.md). Update [current status](docs/project/current-status.md) when the evidence changes. History and approval records retain their original scope. Commit and push only when separately authorized.
