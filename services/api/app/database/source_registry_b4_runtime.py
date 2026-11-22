"""Linux infrastructure adapter. The independent control plane is a deployment dependency."""
from dataclasses import dataclass, field
import errno
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
from time import monotonic, sleep
from uuid import uuid4

from app.database.source_registry_b4_broker import _LIMIT, _remaining, _socket_metadata
from app.database.source_registry_b4_broker_server import Backends, Peer, canonical
from app.database.source_registry_local_inputs import (
    _DECISION, _DIRECTORY, _RUN, _approval, _directory, _read, _unique,
)
from app.database.source_registry_preflight import approval_sha256


AUTHORITY = Path("/run/ai-soc-b4/authority.sock")


def trusted_path(path, *, directory):
    if not path.is_absolute() or ".." in path.parts:
        raise PermissionError("invalid protected path")
    for parent in reversed(path.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError("unsafe protected ancestry")
    info = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if (not kind(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
            or (not directory and info.st_nlink != 1)):
        raise PermissionError("unsafe protected path")
    return info


def listener_metadata(path, *, supervisor, worker_gid):
    _socket_metadata(path)
    info = path.lstat()
    expected = (147 if supervisor else worker_gid, 0o660)
    if (info.st_gid, stat.S_IMODE(info.st_mode)) != expected:
        raise PermissionError("unexpected listener permissions")


class Authority:
    """Fixed local channel. The kernel authenticates the independently managed service."""

    def __init__(self, uid, gid, *, endpoint=AUTHORITY, root_controller=False):
        self.root_controller = (root_controller and (uid, gid) == (0, 0)
                                and endpoint == Path("/run/ai-soc-b4/host-control.sock"))
        if not self.root_controller and (type(uid) is not int or type(gid) is not int or uid <= 0 or gid <= 0
                                         or uid == 136 or gid == 147):
            raise PermissionError("authority must use a dedicated identity")
        self.uid, self.gid, self.endpoint = uid, gid, endpoint

    def request(self, operation, payload, deadline):
        _socket_metadata(self.endpoint)
        info = self.endpoint.lstat()
        socket_group = os.getegid() if self.root_controller else self.gid
        if (info.st_gid, stat.S_IMODE(info.st_mode)) != (socket_group, 0o660):
            raise PermissionError("unprotected authority socket")
        nonce = uuid4().hex
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC) as conn:
            conn.settimeout(_remaining(deadline))
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            conn.connect(os.fspath(self.endpoint))
            if Peer.from_socket(conn).uid != 0:
                raise PermissionError("authority listener is not root-created")
            # Socket activation authenticates the listener creator via SO_PEERCRED.
            # Authenticate the actual serving process before releasing a request.
            conn.settimeout(_remaining(deadline))
            size = struct.calcsize("3i")
            greeting, ancillary, flags, _ = conn.recvmsg(1, socket.CMSG_SPACE(size))
            if (greeting != b"B" or flags & socket.MSG_CTRUNC or len(ancillary) != 1
                    or ancillary[0][:2] != (socket.SOL_SOCKET, socket.SCM_CREDENTIALS)
                    or len(ancillary[0][2]) != size):
                raise PermissionError("missing authority process identity")
            pid, uid, gid = struct.unpack("3i", ancillary[0][2])
            if pid <= 0 or (uid, gid) != (self.uid, self.gid):
                raise PermissionError("authority identity mismatch")
            conn.settimeout(_remaining(deadline))
            conn.sendall(canonical(dict(operation=operation, payload=payload, nonce=nonce,
                                        deadline=deadline)) + b"\n")
            data = bytearray()
            while len(data) <= _LIMIT:
                conn.settimeout(_remaining(deadline))
                chunk = conn.recv(min(16384, _LIMIT + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if b"\n" in chunk:
                    break
        _remaining(deadline)
        if len(data) > _LIMIT or data.count(b"\n") != 1 or not data.endswith(b"\n"):
            raise ValueError("invalid authority frame")
        reply = json.loads(data, object_pairs_hook=_unique)
        if type(reply) is not dict or set(reply) != {"nonce", "result"} or reply["nonce"] != nonce:
            raise PermissionError("unbound authority response")
        return reply["result"]


class Cgroup:
    """Verify membership and kill the exact unified cgroup, including nested processes."""

    def __init__(self, root=Path("/sys/fs/cgroup"), proc=Path("/proc"), *, worker_gid=None):
        self.root, self.proc, self.worker_gid = root, proc, worker_gid
        if root == Path("/sys/fs/cgroup") and not any(
            line.split(" - ", 1)[0].split()[4] == str(root)
            and line.split(" - ", 1)[1].split()[0] == "cgroup2"
            for line in (proc / "self/mountinfo").read_text().splitlines()
        ):
            raise PermissionError("unified kernel cgroup mount required")
        if not (root / "cgroup.controllers").is_file():
            raise PermissionError("cgroup v2 required")

    @staticmethod
    def name(decision):
        if not _DECISION.fullmatch(decision):
            raise ValueError("invalid scope decision")
        return f"/b4workers.slice/ai-soc-b4-worker@{decision}.service"

    def member(self, decision, peer, authority_uid, authority_gid):
        if peer.pid <= 0 or peer.uid in (0, 136, authority_uid) or peer.gid in (0, 147, authority_gid):
            return False
        procfd = os.open(self.proc / str(peer.pid), _DIRECTORY)
        try:
            def read(name):
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=procfd)
                with os.fdopen(fd) as source:
                    value = source.read(32769)
                if len(value) > 32768:
                    raise ValueError("oversized proc metadata")
                return value

            status = dict(line.split(":", 1) for line in read("status").splitlines())
            groups = set(map(int, status["Groups"].split()))
            return (
                read("cgroup") == f"0::{self.name(decision)}\n"
                and list(map(int, status["Uid"].split())) == [peer.uid] * 4
                and list(map(int, status["Gid"].split())) == [peer.gid] * 4
                and not {0, 147, authority_gid}.intersection(groups)
                and (self.worker_gid is None or self.worker_gid in groups)
                and status["NoNewPrivs"].strip() == "1"
                and int(status["CapEff"], 16) == 0
                and int(status["CapBnd"], 16) == 0
            )
        finally:
            os.close(procfd)

    def empty(self, decision):
        path = self.root / self.name(decision).lstrip("/")
        try:
            fd = os.open(path, _DIRECTORY)
        except FileNotFoundError:
            return True
        try:
            _directory(fd, 0)
            events = os.open("cgroup.events", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            with os.fdopen(events) as stream:
                populated = [line for line in stream.read(4096).splitlines()
                             if line.startswith("populated ")]
            return populated == ["populated 0"]
        finally:
            os.close(fd)

    def recursive_kill_available(self, decision):
        """Check the exact worker child cgroup, without sending a signal."""
        path = self.root / self.name(decision).lstrip("/")
        try:
            fd = os.open(path, _DIRECTORY)
            try:
                _directory(fd, 0)
                kind = os.open("cgroup.type", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                with os.fdopen(kind, "rb") as stream:
                    if stream.read(64) != b"domain\n":
                        return False
                kill = os.open("cgroup.kill", os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                os.close(kill)
                return True
            finally:
                os.close(fd)
        except (OSError, ValueError):
            return False

    def kill_and_empty(self, decision, deadline):
        path = self.root / self.name(decision).lstrip("/")
        try:
            fd = os.open(path, _DIRECTORY)
        except FileNotFoundError:
            # The independent controller must also confirm the unit is stopped.
            return True
        try:
            _directory(fd, 0)
            kill = os.open("cgroup.kill", os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            try:
                if os.write(kill, b"1") != 1:
                    return False
            finally:
                os.close(kill)
            while True:
                events = os.open("cgroup.events", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                with os.fdopen(events) as stream:
                    populated = [line for line in stream.read(4096).splitlines()
                                 if line.startswith("populated ")]
                _remaining(deadline)
                if populated == ["populated 0"]:
                    return True
                if populated != ["populated 1"]:
                    return False
                sleep(min(0.025, _remaining(deadline)))
        finally:
            os.close(fd)


@dataclass
class Coverage:
    cursor: int
    unexpected: bool = False
    active: dict = field(default_factory=dict)


class LinuxInfrastructure:
    def __init__(self, *, records_fd, authority, cgroup):
        _directory(records_fd, 0, private=True)
        self.records, self.authority, self.cgroup = records_fd, authority, cgroup
        self.coverage = {}

    def approval(self, decision, deadline):
        _remaining(deadline)
        if not _DECISION.fullmatch(decision):
            raise ValueError("invalid approval decision")
        return _approval(_read(self.records, decision + ".json", 32768, 0))

    def _request(self, operation, packet, deadline, **fields):
        return self.authority.request(operation, dict(decision_id=packet.decision_id,
                                      approval_sha256=approval_sha256(packet), **fields), deadline)

    def frozen(self, packet, deadline):
        return self._request("frozen", packet, deadline) is True

    def hold(self, packet, run, deadline):
        receipt = self._request("hold", packet, deadline, run_id=run)
        if (type(receipt) is not dict or set(receipt) != {"run_id", "durable", "cursor"}
                or receipt["run_id"] != run or receipt["durable"] is not True
                or type(receipt["cursor"]) is not int or receipt["cursor"] < 0):
            return False
        self.coverage[packet.decision_id] = run, Coverage(receipt["cursor"])
        return True

    def start(self, packet, run, deadline):
        if not _RUN.fullmatch(run):
            return False
        scope = self.cgroup.name(packet.decision_id)
        response = self._request("start", packet, deadline, run_id=run, cgroup=scope, stop_by=deadline)
        _remaining(deadline)
        return response == {"run_id": run, "cgroup": scope, "stop_by": deadline,
                            "deadline_armed": True, "sandbox_verified": True}

    def worker(self, packet, peer, deadline):
        _remaining(deadline)
        return self.cgroup.member(packet.decision_id, peer, self.authority.uid, self.authority.gid)

    def handoff(self, packet, run, deadline):
        return self._request("handoff", packet, deadline, run_id=run)

    def status(self, packet, run, deadline):
        return self._request("status", packet, deadline, run_id=run)

    def close(self, packet, run, deadline):
        # Disable restart before killing the cgroup so a new instance cannot replace it.
        fields = dict(run_id=run, cgroup=self.cgroup.name(packet.decision_id))
        return (self._request("stop", packet, deadline, **fields) is True
                and self.cgroup.kill_and_empty(packet.decision_id, deadline)
                and self._request("scope_closed", packet, deadline, **fields) is True)

    def observe(self, packet, deadline):
        run, monitor = self.coverage[packet.decision_id]
        try:
            batch = self._request("observe", packet, deadline, run_id=run, after=monitor.cursor)
            if (set(batch) != {"target_matches", "complete", "through", "events", "sessions"}
                    or batch["target_matches"] is not True or batch["complete"] is not True
                    or type(batch["events"]) is not list or type(batch["sessions"]) is not list
                    or type(batch["through"]) is not int or len(batch["events"]) > 4096
                    or len(batch["sessions"]) > packet.budgets.max_sessions):
                raise ValueError("invalid backend coverage")
            cursor = monitor.cursor
            connected = []
            active = monitor.active.copy()
            for event in batch["events"]:
                if type(event) is not list or len(event) != 5:
                    raise ValueError("invalid backend event")
                seq, kind, pid, login, tag = event
                cursor += 1
                if type(seq) is not int or seq != cursor or kind not in {"connect", "disconnect"}:
                    raise ValueError("backend stream gap")
                if (type(pid) is not int or pid <= 0 or login not in
                        {packet.migrator_login, packet.observer_login} or tag != run):
                    raise ValueError("unexpected backend")
                if kind == "connect":
                    if pid in active or len(active) >= packet.budgets.max_sessions:
                        raise ValueError("unexpected concurrent backend")
                    active[pid] = (login, tag)
                    connected.append((pid, login, tag))
                elif active.pop(pid, None) != (login, tag):
                    raise ValueError("unmatched backend disconnect")
            sessions = tuple(tuple(row) for row in batch["sessions"])
            if (len(sessions) != len(active)
                    or set(sessions) != {(pid, *identity) for pid, identity in active.items()}):
                raise ValueError("backend snapshot disagrees with event stream")
            if cursor != batch["through"]:
                raise ValueError("backend stream truncated")
            monitor.cursor, monitor.active = cursor, active
            return Backends(True, True, sessions, monitor.unexpected,
                            tuple(connected))
        except (KeyError, TypeError, ValueError, OSError):
            monitor.unexpected = True
            return Backends(False, False, (), True)

    def recover_freeze(self, packet, run, expiry, deadline):
        receipt = self._request("recover", packet, deadline, run_id=run, expires_at=expiry.isoformat())
        if (type(receipt) is not dict or set(receipt) != {"run_id", "durable", "cursor"}
                or receipt["run_id"] != run or receipt["durable"] is not True
                or type(receipt["cursor"]) is not int or receipt["cursor"] < 0):
            return False
        self.coverage[packet.decision_id] = run, Coverage(receipt["cursor"])
        return True

    def inspect(self, packet, deadline):
        return self._request("inspect", packet, deadline)

    def release(self, packet, run, deadline):
        _, monitor = self.coverage[packet.decision_id]
        return (not monitor.unexpected and self._request("release", packet, deadline, run_id=run,
                                                        through=monitor.cursor) is True)

    def checkpoint(self, operation, sequence, receipt):
        deadline = monotonic() + 2
        result = self.authority.request(operation, dict(sequence=sequence, sha256=receipt), deadline)
        if result != {"sequence": sequence, "sha256": receipt, "durable": True}:
            raise PermissionError("independent evidence receipt unconfirmed")


def activated_listeners(paths, *, worker_gid):
    """Adopt exactly the named systemd descriptors; never pass them to children."""
    names = os.environ.get("LISTEN_FDNAMES", "").split(":")
    if (os.environ.get("LISTEN_PID") != str(os.getpid())
            or os.environ.get("LISTEN_FDS") != str(len(paths))
            or len(names) != len(paths) or set(names) != set(paths)):
        raise PermissionError("invalid socket activation")
    expected = set(range(3, 3 + len(names)))
    for name in os.listdir("/proc/self/fd"):
        fd = int(name)
        if fd > 2 and fd not in expected:
            try:
                os.fstat(fd)
            except OSError as exc:
                if exc.errno == errno.EBADF:  # The descriptor used by listdir has already closed.
                    continue
                raise
            raise PermissionError("unexpected inherited descriptor")
    listeners = {}
    try:
        for fd, name in enumerate(names, 3):
            os.set_inheritable(fd, False)
            listener = socket.socket(fileno=fd)
            listeners[name] = listener
            path = paths[name]
            listener_metadata(path, supervisor=name == "control", worker_gid=worker_gid)
            if (listener.family != socket.AF_UNIX or listener.getsockname() != os.fspath(path)
                    or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)):
                raise PermissionError("unexpected inherited listener")
        return listeners
    except Exception:
        for listener in listeners.values():
            listener.close()
        raise


def verify_runtime(root, expected):
    from app.database.source_registry_artifact import FILES, manifest_bytes

    for name in ("B4-MANIFEST.json", *FILES):
        trusted_path(root / name, directory=False)
    if sha256(manifest_bytes(root)).hexdigest() != expected:
        raise PermissionError("unapproved runtime inventory")


def launch_broker(root, recovery=None):
    """Fixed, root-operated entry point used by the isolated bootstrap."""
    from contextlib import ExitStack
    from datetime import datetime
    import grp
    import pwd
    import sys

    from app.database.source_registry_b4_broker import CONTROL_SOCKET, WORKER_SOCKET
    from app.database.source_registry_b4_broker_server import Broker, Journal, SignedGrants

    if os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0) or set(os.getgroups()) - {0}:
        raise PermissionError("unexpected broker identity")
    trusted_path(root, directory=True)
    trusted_path(Path(sys.executable).resolve(strict=True), directory=False)
    config = Path("/etc/ai-soc-b4/broker")
    state = Path("/var/lib/ai-soc-b4/broker")
    paths = {"control": CONTROL_SOCKET, "worker": WORKER_SOCKET,
             "docker": Path("/run/ai-soc-b4/docker-inspect.sock")}

    group = grp.getgrnam("ai-soc-b4-worker-ipc")
    with ExitStack() as cleanup:
        if recovery is None:
            listeners = activated_listeners(paths, worker_gid=group.gr_gid)
            for listener in listeners.values():
                cleanup.callback(listener.close)

        def private(path):
            trusted_path(path, directory=True)
            fd = os.open(path, _DIRECTORY)
            cleanup.callback(os.close, fd)
            _directory(fd, 0, private=True)
            return fd

        fd = private(config)
        settings = json.loads(_read(fd, "runtime.json", 4096, 0), object_pairs_hook=_unique)
        if set(settings) != {"authority_uid", "authority_gid", "host", "runtime_sha256", "worker_ipc_gid"}:
            raise PermissionError("invalid broker configuration")
        if (group.gr_gid != settings["worker_ipc_gid"] or group.gr_mem
                or group.gr_gid in {0, 147, settings["authority_gid"]}
                or any(user.pw_gid == group.gr_gid for user in pwd.getpwall())):
            raise PermissionError("unsafe worker socket group")
        verify_runtime(root, settings["runtime_sha256"])
        runtime = LinuxInfrastructure(records_fd=private(config / "records"),
                                      authority=Authority(settings["authority_uid"], settings["authority_gid"]),
                                      cgroup=Cgroup(worker_gid=group.gr_gid))
        grants = SignedGrants(private(config / "grants"), host=settings["host"],
                              runtime_sha256=settings["runtime_sha256"])
        readiness = runtime.authority.request("readiness", {}, monotonic() + 2)
        if readiness != {"credential_custody": True, "durable_freeze": True,
                         "continuous_backend_events": True, "independent_checkpoints": True,
                         "worker_egress_policy": True, "worker_filesystem_policy": True,
                         "independent_scope_deadline": True}:
            raise PermissionError("required independent runtime capabilities unavailable")
        # Bring up custody and validate the existing journal before accepting a client.
        journal = Journal(private(state), checkpoint=runtime.checkpoint)
        broker = Broker(grants, journal, runtime)
        if recovery is not None:
            decision, run, expiry = recovery
            broker.recover(decision=decision, run=run, expires_at=datetime.fromisoformat(expiry),
                           deadline=monotonic() + 30)
            return
        broker.serve(listeners)
