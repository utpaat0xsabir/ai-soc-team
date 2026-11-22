# B4 five-operation inert installation approval

**UNAPPROVED. BLOCKED pending protected host verification and independent
decision.** This handoff does not authorize apply, daemon reload, worker
activation, credential loading, PostgreSQL access, or migration. It covers
only the five host operations in the exact
[serialized plan](b4-linux-installation-plan.review.json).

## Frozen inputs and reproduction

Checked `master` at `c231f54693d41c028bf9226c99cf1a490ab57eef` with the
existing uncommitted B4 files. All 53 unique inputs match the candidate
byte-for-byte. The reported candidate, plan, archive, unit and DDL values
reproduced. No manifest or source was rewritten.

| Artifact | SHA-256 |
|---|---|
| [Candidate](source-registry-execution-manifest.linux-provisioning.candidate.json) | `ef2a34a42cfc0c65c44e095e66400e753a871a93bfcbff7c46523324e736869c` |
| [Exact plan bytes](b4-linux-installation-plan.review.json) | `532572bdc8a68f0f4c443a3cee754576db7f991bffa4ba572004c85ee01fee69` |
| Deterministically generated USTAR archive | `ceabf9b440df13c928847ec2b15e503f9f42275ed659f5c2fa1aff83e60e939b` |
| [Worker unit](../../deploy/b4/ai-soc-b4-worker@.service) | `67308a9ed8a97ab552884c747860f1a263fa2a9057ff07296183c47fec3cc2f1` |
| [Provisioning script](../../scripts/provision_b4.py) | `62dbda4703b9dab15e9e94b1d7fd9afbd629b028c87e6aae2ecf1d79334d696d` |
| [Local protected inputs](../../services/api/app/database/source_registry_local_inputs.py) | `9f0765da4bd9b18705ba7134fc32b780a46eeb616f4bed8780276337554bc2a6` |
| [Preserved approved manifest](source-registry-execution-manifest.json) | `d829b2916ab5b1fd54fe9113fa7ef3784744aff68675cdd7b29b2338de008de5` |
| Embedded and rendered DDL, 67 statements | `0fc91f8d8b76cf7e978603c5b998682a27bd77f4127516d1d85971439e880bf4` |

Ten-revision chain from parsed migration source:

```text
6cf3679d8b90 → 1e6b673facf2 → 211e576b1806 → 20d4e84d93ca → 5ad5e0e78db3
→ 013505dd4ffd → b71a4c2d9e10 → c82b5d3ea021 → d93c6e4fb132 → e4b2b2000001
```

The in-memory archive contains 54 sorted regular files, consisting of the
53 pinned source files and the exact candidate as `B4-MANIFEST.json`. Entry
metadata is mode 0444, UID/GID 0 and timestamp 0. Its size is 655,360 bytes.
An independent USTAR construction matched the script output byte-for-byte.
The archive contains no live credentials, approval signatures, Git metadata
or deployed interpreter.

Reproduce from the exact checkout with the reviewed Python environment.
The first command invokes only dry-run. The second regenerates and checks
bytes in memory. It neither extracts the archive nor creates host files.

```bash
.venv/bin/python -IB scripts/provision_b4.py --dry-run \
  --candidate docs/security/source-registry-execution-manifest.linux-provisioning.candidate.json \
  --candidate-sha256 ef2a34a42cfc0c65c44e095e66400e753a871a93bfcbff7c46523324e736869c

env -i PATH="$PATH" PYTHONPATH=services/api .venv/bin/python -B - <<'PY'
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import runpy
import tarfile

from app.database.source_registry_artifact import FILES, manifest_bytes
from app.database.source_registry_migration_plan import compile_disabled_stage

p = Path("docs/security/source-registry-execution-manifest.linux-provisioning.candidate.json")
raw = p.read_bytes()
pin = sha256(raw).hexdigest()
assert pin == "ef2a34a42cfc0c65c44e095e66400e753a871a93bfcbff7c46523324e736869c"
assert raw == manifest_bytes(Path.cwd())
manifest = json.loads(raw)
assert len(FILES) == len(set(FILES)) == 53 and set(FILES) == set(manifest["files"])
sources = {name: Path(name).read_bytes() for name in FILES}
assert all(sha256(data).hexdigest() == manifest["files"][name] for name, data in sources.items())
ddl = compile_disabled_stage()
assert len(ddl) == 67
assert sha256("\n".join(ddl).encode()).hexdigest() == manifest["ddl_sha256"]
script = runpy.run_path("scripts/provision_b4.py")
archive, unit = script["_bundle"](p, pin)
independent = BytesIO()
with tarfile.open(fileobj=independent, mode="w", format=tarfile.USTAR_FORMAT) as output:
    for name, data in sorted({**sources, "B4-MANIFEST.json": raw}.items()):
        info = tarfile.TarInfo(name)
        info.mode, info.size = 0o444, len(data)
        output.addfile(info, BytesIO(data))
assert archive == independent.getvalue()
plan = script["_serialize"](script["_plan"](pin, archive, unit))
assert plan == Path("docs/security/b4-linux-installation-plan.review.json").read_bytes()
for name, data in (("candidate", raw), ("archive", archive), ("unit", unit), ("plan", plan)):
    print(name, sha256(data).hexdigest())
PY
```

## Exact destination scope and host evidence

| Operation | Destination | UID:GID | Mode | Observed leaf |
|---|---|---|---|---|
| Create directory | `/var/lib/ai-soc-b4/records` | 0:147 | 0750 | Inaccessible |
| Create directory | `/var/lib/ai-soc-b4/pins` | 0:147 | 0750 | Inaccessible |
| Create directory | `/var/lib/ai-soc-b4/evidence` | 136:147 | 0700 | Inaccessible |
| Install archive | `/opt/ai-soc-b4/source-ef2a34a42cfc0c65c44e095e66400e753a871a93bfcbff7c46523324e736869c.tar` | 0:147 | 0440 | Inaccessible |
| Install dormant unit | `/etc/systemd/system/ai-soc-b4-worker@.service` | 0:0 | 0644 | Absent at inspection |

Read-only host inspection confirmed `ai-soc-b4` UID 136, GID 147,
`/usr/sbin/nologin`, no listed supplementary members of group 147, and
a writable ext4 mount for the B4 state path. Observed parent paths and
ancestors had no symlinks. State and install parents were root:147 mode
0750, configuration root:root mode 0700, and the systemd destination
directory root:root mode 0755. Unprivileged traversal denied inspection
of the four protected destinations and the existing replay directory.
Their existence, exact metadata, and conflicts remain unknown.

The repository dry-run printed the exact plan but stopped on sandbox-masked
`/var/lib` ownership. That run did not clear host validation. Before approval,
an authorized host custodian must use read-only `namei` and `lstat`-equivalent
checks for all five leaf paths, their ancestors and replay. Existing files
must be regular single-link files with the exact owner, group, mode and
hash. Existing directories must have the exact metadata and no symlink.
Also check the authorized service account can traverse its replay path
and confirm no unreviewed unit override or drop-in would take precedence.
Record the host identity and results through the protected approval channel.

## Host verification update — 2026-11-22 UTC

Host hostname observed as `mail.godcompl3x.com`. NSS reported user
`ai-soc-b4` at UID 136, primary GID 147, and shell `/usr/sbin/nologin`.
`id ai-soc-b4` returned only group 147. The NSS account enumeration
returned only `ai-soc-b4` with primary GID 147. The state filesystem
was observed as writable ext4. The parent ownership, modes and lack of
symlinks in the inspected parent chains were reconfirmed.

The unit leaf was absent. Ordinary-user traversal returned permission
denied for records, pins, evidence, the archive and replay. This is
consistent with the protected parent permissions and does not establish
whether those leaves exist or are safe. Both the root metadata check
and the service-identity replay check stopped at
`sudo: a password is required`. No privilege escalation or service
switch succeeded. The current tool session has no secure host sudo
credential-entry channel. Authenticate only in a trusted host terminal.

The authorized custodian needs one read-only inspection for the
remaining leaves and an actual read/search check as the service account.
The two `test` calls check access and perform no filesystem writes.
Do not read the contents of approval, pin, or replay files.

```bash
sudo /usr/bin/namei -l \
  /var/lib/ai-soc-b4/replay /var/lib/ai-soc-b4/records \
  /var/lib/ai-soc-b4/pins /var/lib/ai-soc-b4/evidence \
  /opt/ai-soc-b4/source-ef2a34a42cfc0c65c44e095e66400e753a871a93bfcbff7c46523324e736869c.tar \
  /etc/systemd/system/ai-soc-b4-worker@.service
sudo -u ai-soc-b4 /usr/bin/test -r /var/lib/ai-soc-b4/replay &&
sudo -u ai-soc-b4 /usr/bin/test -x /var/lib/ai-soc-b4/replay
```

Use root `stat` on each existing leaf to record numeric ownership, mode,
type and link count. After confirming that an existing archive or unit
is a regular single-link file, compare its digest to the table above.
Inspect ACL metadata when ACLs are in use. Require the replay directory
to be a directory owned by 136:147 with mode 0700 and successful read and
search checks. Treat inaccessible paths, symlinks, inconsistent ACLs,
unexpected metadata, or digest conflicts as blockers. Record verified
metadata only in the protected approval channel.

### Approval-material access boundary

Proposed mode 0750 with group 147 gives `ai-soc-b4` directory read and
search access to both records and pins outside the worker sandbox.
Whether it can read a particular artifact depends on the file mode and ACL.
Root-owned, group-readable files would be readable to the service account
and must be limited to material approved for the protected supervisor.
Credentials and reviewer private keys do not belong in either directory.
These directory modes prohibit group writes under conventional mode bits,
subject to the actual ACLs and ownership. Leaf permissions and ACLs
remain unverified.

The reviewed unit declares both paths in `InaccessiblePaths` and runs as
`ai-soc-b4`. This is a proposed worker mount boundary. No running worker,
verified bootstrap, or effective isolation evidence was available. In
particular, approval material must remain inaccessible from the worker
through inherited descriptors, other mount views, and same-UID process
access. **Publishing protected approval material or activating the worker
is blocked until independent isolation evidence closes this boundary.**
If ordinary service-account access is forbidden for a class of approval
material, group-readable placement in these directories is unsafe and
requires a separately reviewed provisioning design. Inert installation
review is limited to the five exact paths and grants no approval-material
publication or runtime access.

The current script regenerated byte-identical candidate, archive, unit
and plan bytes. Plan SHA-256 remains
`532572bdc8a68f0f4c443a3cee754576db7f991bffa4ba572004c85ee01fee69`.
Apply was not executed. No protected host path or permission changed.

## Security and failure considerations

- Apply prechecks every existing destination for conflicts. It leaves exact
  existing paths alone and exclusively creates missing paths. Tests used
  temporary paths to verify idempotence, refusal to overwrite and refusal
  with an incorrect plan digest.
- Apply is a sequence, with file and parent fsync. A crash or write failure
  can leave a partial plan or file. Stop, record the affected paths and
  hashes, and obtain separate reconciliation authority. The script refuses
  to overwrite a partial or mismatched file. Do not delete it automatically.
- Python begins executing before the script checks protected source
  ancestry. Authenticate the script and interpreter independently and
  stage the complete checkout in reviewed root-controlled ancestry before
  any root invocation. Do not run apply from an ordinary writable checkout.
- The unit has no install target, requires the isolated bootstrap and
  restricted Docker inspection socket, and declares worker, network and
  resource restrictions. Static verification could not establish the
  executable at `/opt/ai-soc-b4/bootstrap/worker`. No unit was installed
  or activated. Do not supply direct host Docker socket access.
- The local input class implements signed-pin verification and durable
  receipts. It remains abstract for runtime, freeze, process containment,
  recovery and backend monitoring. The three directories alone provide
  no protected approval channel or configured worker. See the
  [provisioning runbook](b4-gate1-provisioning-runbook.md#linux-provisioning-automation).
- The focused isolated regression returned 316 passed, 1 failed and 27
  deselected. The only failure was the enabled preserved-approved-manifest
  byte comparison. Direct PostgreSQL, SQLite and migration-runner
  entry-point cases were outside the run. No services were contacted.

## Independent decision and installation handoff

Review and bind the exact host, script, interpreter, candidate, archive, unit
and plan digests. The independently controlled decision must record reviewer,
timestamp, expiry, host evidence, exact five operations, conflict and
interruption handling, and explicit approve or reject. A local report, a
matching digest, and root privileges each confer no approval.

| Decision item | Independent entry |
|---|---|
| Host identity, protected paths, replay verification and leaf conflict evidence | Pending |
| Frozen checkout and reviewed interpreter | Pending |
| Candidate, plan, archive, unit and script digest acceptance | Pending |
| Authenticated approval or rejection reference, reviewer and expiry | Pending |
| Operator execution decision and permitted window | Pending |
| Unresolved risks and permitted interruption actions | Pending |

**NOT AUTHORIZED TO EXECUTE.** If a separate authenticated approval is issued,
the approved root operator runs from the independently verified frozen source
tree with the reviewed interpreter. Expected success is
`Inert files and directories verified. No service was activated.`

```bash
"$B4_REVIEWED_PYTHON" -IB scripts/provision_b4.py --apply \
  --candidate docs/security/source-registry-execution-manifest.linux-provisioning.candidate.json \
  --candidate-sha256 ef2a34a42cfc0c65c44e095e66400e753a871a93bfcbff7c46523324e736869c \
  --approve-plan-sha256 532572bdc8a68f0f4c443a3cee754576db7f991bffa4ba572004c85ee01fee69
```

Inspect the exact installed metadata and hashes afterwards under that approved
scope. Exclude daemon reload, enablement, activation, trust-anchor publication,
and database access. Gate 1 remains separate and unapproved. Historical
`0eafe3f3` remains an unresolved migration-execution blocker pending
independent provenance or explicit risk disposition.
