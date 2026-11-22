# Project history and implemented work

This timeline uses reachable Git history and the current source tree. Commit descriptions establish when work entered history. Tests and dated verification records establish a separate evidence boundary.

| Revision or sequence | Work recorded |
|---|---|
| `0f5fba4` | Initial project foundation and API service structure. |
| `7660129`, `b602ff6`, `7642e54` | Evidence provenance, tenant API-key authentication and scoped ingestion. |
| `78e97d5` | Checkpoint of development foundations. Current models and applied-history candidates include audit, Wazuh integration and ingestion state. Actual deployed revision is unknown in this review. |
| `8bffe40` | Modular backend packages and domain mirror test structure. [Refactor decision](../architecture/backend-modular-refactoring-ref01.md) |
| `49add77` | Offline L1 orchestration and IAM trust foundations. |
| `bfb23ac` | Synthetic inference receipts and bound L1 review gate. |
| `c231f54` | Trusted evidence boundary and offline authority validation. |
| Current uncommitted B4 work | Staged source-registry migration, observer, guarded preflight and host containment candidates. Reviewed as working-tree evidence with live approval pending. [B4 status](current-status.md) |

The [evidence index](documentation-evidence-index.md) groups implementation and tests by subsystem. The [November 10 handoff](../development-handoff.md) preserves historical PostgreSQL and Wazuh verification and limitations. Earlier sudo/PAM grouping, service activity and Qwen-assisted investigation are reported historical research in a separate project. This review did not access it or establish equivalent production behavior.
