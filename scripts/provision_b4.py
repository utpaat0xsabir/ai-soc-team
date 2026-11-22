#!/usr/bin/env python3
"""Plan or install inert B4 infrastructure. Never activates a service."""

import argparse
import ast
from hashlib import sha256
from io import BytesIO
import grp
import json
import os
from pathlib import Path
import pwd
import re
import stat
import sys
import tarfile


ROOT = Path(__file__).resolve().parents[1]
ACCOUNT = "ai-soc-b4"
UID, GID = 136, 147
STATE = Path("/var/lib/ai-soc-b4")
CONFIG = Path("/etc/ai-soc-b4")
INSTALL = Path("/opt/ai-soc-b4")
UNIT = "ai-soc-b4-worker@.service"
UNITS = Path("/etc/systemd/system")


def _check(path, uid, gid, mode, *, directory=True):
    info = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if (not kind(info.st_mode) or info.st_uid != uid or info.st_gid != gid
            or stat.S_IMODE(info.st_mode) != mode or (not directory and info.st_nlink != 1)):
        raise ValueError(f"unexpected protected path metadata: {path}")


def _ancestors(path):
    for parent in (path, *path.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError(f"unprotected ancestry: {parent}")


def _host():
    account = pwd.getpwnam(ACCOUNT)
    group = grp.getgrnam(ACCOUNT)
    if ((account.pw_uid, account.pw_gid, account.pw_shell, group.gr_gid)
            != (UID, GID, "/usr/sbin/nologin", GID) or group.gr_mem
            or any(item.pw_gid == GID and item.pw_name != ACCOUNT for item in pwd.getpwall())):
        raise ValueError("B4 service account or group differs from the reviewed values")
    for path, uid, gid, mode in ((STATE, 0, GID, 0o750), (CONFIG, 0, 0, 0o700),
                                  (INSTALL, 0, GID, 0o750), (STATE / "replay", UID, GID, 0o700)):
        _ancestors(path.parent)
        _check(path, uid, gid, mode)


def _source_bytes(relative, maximum):
    """Read a bounded regular file through an anchored non-symlink walk."""
    parts = relative.parts
    if relative.is_absolute() or not parts or any(part.startswith(".") for part in parts):
        raise ValueError("unsafe source path")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent = os.open(ROOT, flags)
    try:
        for component in parts[:-1]:
            child = os.open(component, flags, dir_fd=parent)
            os.close(parent)
            parent = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent)
        with os.fdopen(fd, "rb") as source:
            meta = os.fstat(source.fileno())
            if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 or meta.st_size > maximum:
                raise ValueError("unsafe source file")
            data = source.read(maximum + 1)
            if len(data) != meta.st_size:
                raise ValueError("unstable source file")
            return data
    finally:
        os.close(parent)


def _bundle(manifest_path, pin, *, prior_pin=None):
    manifest_path = manifest_path.absolute()
    if (manifest_path.parent != ROOT / "docs/security"
            or not re.fullmatch(r"source-registry-execution-manifest\.[a-z0-9-]+\.candidate\.json", manifest_path.name)):
        raise ValueError("expected a local B4 candidate manifest")
    raw = _source_bytes(manifest_path.relative_to(ROOT), 65_536)
    if not re.fullmatch(r"[0-9a-f]{64}", pin) or sha256(raw).hexdigest() != pin:
        raise ValueError("candidate digest mismatch")
    document = json.loads(raw)
    # Read the reviewed inventory definition as data. Never import repository code as root.
    inventory_path = Path("services/api/app/database/source_registry_artifact.py")
    inventory = _source_bytes(inventory_path, 65_536)
    if sha256(inventory).hexdigest() != document["files"].get(str(inventory_path)):
        raise ValueError("inventory definition digest mismatch")
    assignment, = [node for node in ast.parse(inventory).body
                   if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "FILES" for t in node.targets)]
    literal = assignment.value.args[0].args[0].func.value
    names = ast.literal_eval(literal).split()
    if len(names) != len(set(names)) or set(names) != set(document["files"]):
        raise ValueError("candidate inventory mismatch")
    sources = {}
    for name, digest in document["files"].items():
        data = _source_bytes(Path(name), 16_777_216)
        if sha256(data).hexdigest() != digest:
            raise ValueError(f"source digest mismatch: {name}")
        sources[name] = data
    for required in ("scripts/provision_b4.py", f"deploy/b4/{UNIT}",
                     "services/api/app/database/source_registry_local_inputs.py"):
        if required not in sources:
            raise ValueError(f"candidate lacks provisioning input: {required}")
    if prior_pin is not None:
        previous = "docs/security/source-registry-execution-manifest.json"
        frozen = _source_bytes(Path(previous), 65_536)
        if sha256(frozen).hexdigest() != prior_pin:
            raise ValueError("preserved approved manifest differs")
        sources[previous] = frozen
    archive = BytesIO()
    with tarfile.open(fileobj=archive, mode="w", format=tarfile.USTAR_FORMAT) as output:
        for name, data in sorted({**sources, "B4-MANIFEST.json": raw}.items()):
            member = tarfile.TarInfo(name)
            member.size, member.mode = len(data), 0o444
            output.addfile(member, BytesIO(data))
    return archive.getvalue(), sources[f"deploy/b4/{UNIT}"]


def deployment_inventory(manifest_path, pin, prior_pin):
    """Describe the complete inert release for review. This has no apply path."""
    archive, _ = _bundle(manifest_path, pin, prior_pin=prior_pin)
    document = json.loads(_source_bytes(manifest_path.absolute().relative_to(ROOT), 65_536))
    unit_names = sorted(name for name in document["files"] if name.startswith("deploy/b4/"))
    if set(unit_names) != {path.relative_to(ROOT).as_posix() for path in (ROOT / "deploy/b4").iterdir()}:
        raise ValueError("deployment unit inventory mismatch")
    authority = "ai-soc-b4-authority"
    paths = {
        "/var/lib/ai-soc-b4": ("root", "ai-soc-b4", "0750"),
        "/var/lib/ai-soc-b4/records": ("root", "ai-soc-b4", "0750"),
        "/var/lib/ai-soc-b4/pins": ("root", "ai-soc-b4", "0750"),
        "/var/lib/ai-soc-b4/replay": ("ai-soc-b4", "ai-soc-b4", "0700"),
        "/var/lib/ai-soc-b4/evidence": ("ai-soc-b4", "ai-soc-b4", "0700"),
        "/var/lib/ai-soc-b4/broker": ("root", "root", "0700"),
        "/var/lib/ai-soc-b4-authority": (authority, authority, "0700"),
        "/var/lib/ai-soc-b4-host-control": ("root", "root", "0700"),
        "/etc/ai-soc-b4": ("root", "root", "0700"),
        "/etc/ai-soc-b4-authority": ("root", authority, "0750"),
        "/run/ai-soc-b4": ("root", "root", "0755"),
    }
    for base, group, mode in (("/etc/ai-soc-b4/broker", "root", "0700"),
                              ("/etc/ai-soc-b4/host-control", "root", "0700"),
                              ("/etc/ai-soc-b4-authority", authority, "0750")):
        paths[base] = ("root", group, mode)
        for child in ("records", "grants"):
            paths[f"{base}/{child}"] = ("root", group, mode)
    runtime_roots = [f"/opt/ai-soc-b4-{role}" for role in ("broker", "worker", "authority", "host-control")]
    for path in runtime_roots:
        paths[path] = ("root", "root", "0755")
    return {
        "status": "UNAPPROVED_REVIEW_ONLY",
        "candidate": manifest_path.name,
        "candidate_sha256": pin,
        "prior_approved_sha256": prior_pin,
        "archive_sha256": sha256(archive).hexdigest(),
        "source_hashes": document["files"],
        "accounts": {"ai-soc-b4": {"uid": UID, "gid": GID},
                     "authority": authority, "worker": "ai-soc-b4-worker (DynamicUser)", "controller": "root"},
        "required_ipc_group": "ai-soc-b4-worker-ipc",
        "protected_directories": {
            name: dict(zip(("owner", "group", "mode"), values)) for name, values in sorted(paths.items())
        },
        "runtime_roots": runtime_roots,
        "additional_reviewed_inputs": ["pinned interpreters and dependencies", "worker bootstrap/worker executable",
                                       "protected approval and runtime configuration", "independent trust anchors",
                                       "custodian-approved recovery unit", "admission and freeze enforcement",
                                       "loss-detecting authenticated session source"],
        "units": {name: {"destination": str(UNITS / Path(name).name),
                         "owner": "root", "group": "root", "mode": "0644",
                         "sha256": document["files"][name]} for name in unit_names},
        "activation_order": [
            "Verify protected runtime and configuration",
            "b4workers.slice and host-control socket before authority socket",
            "Control, worker and Docker-inspection sockets before broker",
            "Worker only after readiness, admission and independently authorized execution",
        ],
        "failure_recovery": "Close admission, preserve both journals and the freeze, reconcile by signed recovery.",
    }


def _plan(pin, bundle, unit):
    return [
        ("mkdir", STATE / "records", 0, GID, 0o750, None),
        ("mkdir", STATE / "pins", 0, GID, 0o750, None),
        ("mkdir", STATE / "evidence", UID, GID, 0o700, None),
        ("install", INSTALL / f"source-{pin}.tar", 0, GID, 0o440, bundle),
        ("install", UNITS / UNIT, 0, 0, 0o644, unit),
    ]


def _serialize(plan):
    return (json.dumps([
        {"operation": operation, "path": str(path), "uid": uid, "gid": gid, "mode": f"{mode:04o}",
         "sha256": sha256(data).hexdigest() if data is not None else None}
        for operation, path, uid, gid, mode, data in plan
    ], indent=2, sort_keys=True) + "\n").encode()


def _apply(plan):
    # Check all existing paths before creating any. Existing data is never replaced.
    pending = []
    for operation, path, uid, gid, mode, data in plan:
        _ancestors(path.parent)
        try:
            _check(path, uid, gid, mode, directory=operation == "mkdir")
        except FileNotFoundError:
            pending.append((operation, path, uid, gid, mode, data))
        else:
            if data is not None and path.read_bytes() != data:
                raise ValueError(f"existing protected file differs: {path}")
    for operation, path, uid, gid, mode, data in pending:
        if operation == "mkdir":
            path.mkdir(mode=0o700)
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        else:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            if data is not None:
                with os.fdopen(fd, "wb", closefd=False) as output:
                    output.write(data)
                    output.flush()
            os.fchown(fd, uid, gid)
            os.fchmod(fd, mode)
            os.fsync(fd)
        finally:
            os.close(fd)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)


def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--dry-run", action="store_true")
    modes.add_argument("--apply", action="store_true")
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--candidate-sha256", required=True)
    parser.add_argument("--approve-plan-sha256")
    args = parser.parse_args(argv)
    try:
        if args.apply:
            if os.geteuid() != 0 or not re.fullmatch(r"[0-9a-f]{64}", args.approve_plan_sha256 or ""):
                raise ValueError("apply requires root and explicit authorization of the exact plan digest")
            _ancestors(ROOT)
        bundle, unit = _bundle(args.candidate, args.candidate_sha256)
        plan = _plan(args.candidate_sha256, bundle, unit)
        report = _serialize(plan)
        plan_pin = sha256(report).hexdigest()
        print(report.decode(), end="", flush=True)
        print(f"Plan SHA-256 {plan_pin}", flush=True)
        if args.apply and args.approve_plan_sha256 != plan_pin:
            raise ValueError("apply requires root and explicit authorization of the exact plan digest")
        _host()
        if args.apply:
            _apply(plan)
            print("Inert files and directories verified. No service was activated.")
        else:
            print("Dry run complete. No host changes.")
    except (OSError, ValueError, KeyError, TypeError, SyntaxError, AttributeError, IndexError) as exc:
        print(f"Provisioning stopped: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
