"""Bounded B4 client for an independently controlled local infrastructure broker."""

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
from subprocess import TimeoutExpired
from time import monotonic
from uuid import uuid4

from app.database.source_registry_local_inputs import LocalProtectedInputs, _unique
from app.database.source_registry_preflight import Report, approval_sha256


CONTROL_SOCKET = Path("/run/ai-soc-b4/control.sock")
WORKER_SOCKET = Path("/run/ai-soc-b4/worker.sock")
_LIMIT = 2_200_000
_METHODS = frozenset({
    "frozen", "recovery", "hold", "start", "wait", "report", "close_scope",
    "release", "backends_gone", "target_matches", "worker_handoff", "worker_result",
})


def _remaining(deadline):
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise TimeoutError("broker deadline expired")
    return remaining


def _socket_metadata(path):
    for directory in path.parents:
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError("untrusted broker directory")
    info = path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0:
        raise PermissionError("untrusted broker socket")


def broker_call(path, method, *, deadline, **request):
    if ((path == WORKER_SOCKET and method not in {"worker_handoff", "worker_result"})
            or (path == CONTROL_SOCKET and method in {"worker_handoff", "worker_result"})
            or path not in (CONTROL_SOCKET, WORKER_SOCKET) or method not in _METHODS):
        raise ValueError("unapproved broker request")
    nonce = uuid4().hex
    message = json.dumps({**request, "nonce": nonce, "method": method, "deadline": deadline},
                         allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    if len(message) > _LIMIT:
        raise ValueError("oversized broker request")
    _socket_metadata(path)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.settimeout(_remaining(deadline))
        peer.connect(os.fspath(path))
        size = struct.calcsize("3i")
        if struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, size))[1] != 0:
            raise PermissionError("unexpected broker peer")
        peer.settimeout(_remaining(deadline))
        peer.sendall(message + b"\n")
        data = bytearray()
        while len(data) <= _LIMIT:
            peer.settimeout(_remaining(deadline))
            chunk = peer.recv(min(16_384, _LIMIT + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if b"\n" in chunk:
                break
    _remaining(deadline)
    if len(data) > _LIMIT or not data.endswith(b"\n") or data.count(b"\n") != 1:
        raise ValueError("invalid broker response frame")
    reply = json.loads(data, object_pairs_hook=_unique)
    if type(reply) is not dict or set(reply) != {"nonce", "result"} or reply["nonce"] != nonce:
        raise ValueError("unbound broker response")
    return reply["result"]


@dataclass(frozen=True)
class _Worker:
    identity: dict

    def wait(self, timeout):
        try:
            status = broker_call(CONTROL_SOCKET, "wait", deadline=monotonic() + timeout, **self.identity)
        except TimeoutError:
            raise TimeoutExpired("b4-worker", timeout) from None
        if type(status) is not int or not 0 <= status <= 255:
            raise ValueError("invalid worker exit status")
        return status


class BrokerProtectedInputs(LocalProtectedInputs):
    """Supervisor storage plus authenticated calls to the independent infrastructure authority."""

    @staticmethod
    def _identity(record):
        return {"decision_id": record.packet.decision_id, "approval_sha256": approval_sha256(record.packet)}

    def _check(self, record, method, deadline, **details):
        return broker_call(CONTROL_SOCKET, method, deadline=deadline,
                           **self._identity(record), **details) is True

    def execution_is_frozen(self, record, *, deadline):
        return self._check(record, "frozen", deadline)

    def recovery_authorized(self, record, *, until):
        # Charge authority lookup to a short budget. The authorized recovery
        # horizon is a separate value and does not extend the lookup.
        return self._check(record, "recovery", min(until, monotonic() + 2), until=until)

    def hold_freeze(self, record, run_id, *, deadline):
        return self._check(record, "hold", deadline, run_id=run_id)

    def start_worker(self, record, trusted_digest, run_id, *, deadline):
        identity = self._identity(record)
        if trusted_digest != identity["approval_sha256"] or not re.fullmatch(r"b4-[0-9a-f]{32}", run_id):
            raise ValueError("unbound worker request")
        if not self._check(record, "start", deadline, run_id=run_id):
            raise PermissionError("worker start unconfirmed")
        return _Worker({**identity, "run_id": run_id})

    def read_result(self, process, *, deadline):
        if type(process) is not _Worker:
            raise ValueError("unexpected worker handle")
        fields = broker_call(CONTROL_SOCKET, "report", deadline=deadline, **process.identity)
        if type(fields) is not dict:
            raise ValueError("invalid worker report")
        fields["versions"] = tuple(fields["versions"])
        fields["backend_pids"] = tuple(fields["backend_pids"])
        return Report(**fields)

    def close_worker_scope(self, record, run_id, *, deadline):
        return self._check(record, "close_scope", deadline, run_id=run_id)

    def release_freeze(self, record, run_id, *, deadline):
        return self._check(record, "release", deadline, run_id=run_id)

    def backends_gone(self, record, run_id, *, backend_pids, deadline):
        return self._check(record, "backends_gone", deadline, run_id=run_id, backend_pids=backend_pids)

    def target_matches(self, record, *, deadline):
        return self._check(record, "target_matches", deadline)
