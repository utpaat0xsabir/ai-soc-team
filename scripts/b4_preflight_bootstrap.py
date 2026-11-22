#!/usr/bin/env python3
"""Protected supervisor and isolated worker adapters. No default broker or credentials."""

import argparse
from base64 import b64decode
from contextlib import ExitStack
from dataclasses import asdict
import json
import os
from pathlib import Path
import re
import stat
import sys
from time import monotonic


_ROOT = Path(__file__).resolve().parents[1]
_STATE = Path("/var/lib/ai-soc-b4")
_SUPERVISOR_UID = 136
_SUPERVISOR_GID = 147


def _trusted(path, *, directory):
    info = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise PermissionError("unprotected bootstrap inputs")


def _prepare_imports(root):
    _trusted(Path(__file__), directory=False)
    for parent in (root, *root.parents):
        _trusted(parent, directory=True)
    _trusted(root / "scripts", directory=True)
    _trusted(root / "services", directory=True)
    api = root / "services/api"
    _trusted(api, directory=True)
    for directory, directories, files in os.walk(api / "app", followlinks=False):
        _trusted(Path(directory), directory=True)
        for name in directories:
            _trusted(Path(directory) / name, directory=True)
        for name in files:
            _trusted(Path(directory) / name, directory=False)
    _trusted(api / "app", directory=True)
    sys.path.insert(0, str(api))


def _supervisor(decision_id, root):
    from app.database.source_registry_b4_broker import BrokerProtectedInputs
    from app.database.source_registry_preflight_launcher import launch

    for parent in (_STATE, *_STATE.parents):
        _trusted(parent, directory=True)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    with ExitStack() as cleanup:
        descriptors = {}
        for name in ("records", "pins", "evidence"):
            fd = os.open(_STATE / name, flags)
            cleanup.callback(os.close, fd)
            descriptors[name + "_fd"] = fd
        provider = BrokerProtectedInputs(root=root, **descriptors)
        outcome = launch(decision_id, provider=provider, replay_directory=_STATE / "replay")
    print(json.dumps(asdict(outcome), sort_keys=True))
    return 0 if outcome.code == "VERIFIED" else 1


def _worker(decision_id, root):
    from app.database.source_registry_b4_admission import AdmissionProof
    from app.database.source_registry_b4_broker import WORKER_SOCKET, broker_call
    from app.database.source_registry_local_inputs import _approval
    from app.database.source_registry_preflight import run

    handoff = broker_call(WORKER_SOCKET, "worker_handoff", deadline=monotonic() + 5,
                          decision_id=decision_id)
    if type(handoff) is not dict or set(handoff) != {
        "packet", "trusted_digest", "isolation", "ca", "freeze", "run_id", "credentials", "admission",
    }:
        raise ValueError("invalid worker handoff")
    packet = _approval(json.dumps(handoff["packet"], allow_nan=False))
    credentials = handoff["credentials"]
    if (packet.decision_id != decision_id or type(credentials) is not dict
            or set(credentials) != {packet.migrator_secret_ref, packet.observer_secret_ref}):
        raise ValueError("unbound worker handoff")
    admission = AdmissionProof.validate(handoff["admission"], packet, handoff["run_id"],
                                        handoff["trusted_digest"], handoff["admission"]["stop_by"])
    report = run(packet, trusted_approval_sha256=handoff["trusted_digest"], root=root,
                 application_isolation=b64decode(handoff["isolation"], validate=True),
                 ca=b64decode(handoff["ca"], validate=True), freeze=b64decode(handoff["freeze"], validate=True),
                 run_id=handoff["run_id"], credentials=credentials, admission=admission)
    # Only the fixed Report schema crosses the return channel. Do not print credentials or errors.
    stored = broker_call(WORKER_SOCKET, "worker_result", deadline=monotonic() + 2,
                         decision_id=decision_id, run_id=handoff["run_id"], report=asdict(report))
    # The supervisor needs a sanitized failed report too. Exit zero means receipt only.
    return 0 if stored is True else 1


def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("role", choices=("supervisor", "worker", "broker", "recover"))
    parser.add_argument("decision_id", nargs="?")
    parser.add_argument("run_id", nargs="?")
    parser.add_argument("expires_at", nargs="?")
    args = parser.parse_args(argv)
    try:
        if (not sys.flags.isolated or not sys.dont_write_bytecode
                or (args.role != "broker" and not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", args.decision_id or ""))
                or any(key.startswith(("PG", "GIT_", "DOCKER_", "LD_", "OPENSSL_"))
                       or key in {"DATABASE_URL", "TEST_DATABASE_URL", "AI_SOC_MIGRATION_DATABASE_URL"}
                       for key in os.environ)):
            raise PermissionError("untrusted bootstrap process")
        uid = os.geteuid()
        if args.role in {"broker", "recover"}:
            if uid != 0 or (args.role == "broker" and any((args.decision_id, args.run_id, args.expires_at))):
                raise PermissionError("unexpected broker bootstrap identity or arguments")
            if args.role == "recover" and (not re.fullmatch(r"b4-[0-9a-f]{32}", args.run_id or "")
                                           or not args.expires_at):
                raise PermissionError("invalid recovery scope")
            _prepare_imports(_ROOT)
            from app.database.source_registry_b4_runtime import launch_broker

            launch_broker(_ROOT, (args.decision_id, args.run_id, args.expires_at)
                          if args.role == "recover" else None)
            return 0
        if args.run_id is not None or args.expires_at is not None:
            raise PermissionError("unexpected worker or supervisor arguments")
        if args.role == "supervisor":
            if uid != _SUPERVISOR_UID or os.getegid() != _SUPERVISOR_GID:
                raise PermissionError("unexpected supervisor identity")
        elif uid in (0, _SUPERVISOR_UID) or _SUPERVISOR_GID in (os.getegid(), *os.getgroups()):
            raise PermissionError("worker shares protected supervisor identity")
        _prepare_imports(_ROOT)
        entry = _supervisor if args.role == "supervisor" else _worker
        return entry(args.decision_id, _ROOT)
    except Exception:
        print("B4_BOOTSTRAP_UNAVAILABLE", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
