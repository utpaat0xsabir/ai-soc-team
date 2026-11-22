"""Independent B4 broker protocol and durable run-state engine."""

from base64 import b64decode
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import fcntl
from hashlib import sha256
import json
import math
import os
import re
import socket
import struct
from pathlib import Path
from selectors import DefaultSelector, EVENT_READ
from threading import BoundedSemaphore, Lock, Thread
from time import monotonic, sleep
from typing import Protocol

from app.database.source_registry_b4_broker import CONTROL_SOCKET, WORKER_SOCKET, _LIMIT, _remaining, _socket_metadata
from app.database.source_registry_local_inputs import (
    _DECISION, _HEX, _RUN, _approval, _directory, _read, _unique, _verify_ed25519,
)
from app.database.source_registry_preflight import Approval, Report, approval_sha256
from app.database.source_registry_preflight_launcher import _worker_result


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


_CONTROL = {
    "frozen": (), "recovery": ("until",), "hold": ("run_id",), "start": ("run_id",),
    "wait": ("run_id",), "report": ("run_id",), "close_scope": ("run_id",),
    "backends_gone": ("run_id", "backend_pids"), "target_matches": (), "release": ("run_id",),
}
_WORKER = {"worker_handoff": (), "worker_result": ("run_id", "report")}
_EXECUTION = frozenset({"start", "wait", "report", *_WORKER})


@dataclass(frozen=True)
class Peer:
    pid: int
    uid: int
    gid: int

    @classmethod
    def from_socket(cls, connection):
        return cls(*struct.unpack("3i", connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))))


@dataclass(frozen=True)
class Backends:
    """Complete independently observed client sessions, excluding the approved monitor itself."""
    target_matches: bool
    complete: bool
    sessions: tuple[tuple[int, str, str], ...]  # PID, session login, application_name
    unexpected_since_hold: bool  # Sticky, independently maintained by the monitor
    connected: tuple[tuple[int, str, str], ...] = ()


class Infrastructure(Protocol):
    """Protected adapters must honor absolute deadlines and fail on unverifiable results."""

    def approval(self, decision: str, deadline: float) -> Approval: ...
    def frozen(self, packet: Approval, deadline: float) -> bool: ...
    def hold(self, packet: Approval, run: str, deadline: float) -> bool: ...
    # Must arm an independent scope deadline before allowing worker execution.
    def start(self, packet: Approval, run: str, deadline: float) -> bool: ...
    # Verify PID, effective and supplementary identity, and exact scope membership.
    def worker(self, packet: Approval, peer: Peer, deadline: float) -> bool: ...
    def handoff(self, packet: Approval, run: str, deadline: float) -> dict: ...
    def status(self, packet: Approval, run: str, deadline: float) -> int | None: ...
    # Stop the entire scope and independently confirm its cgroup is empty.
    def close(self, packet: Approval, run: str, deadline: float) -> bool: ...
    def observe(self, packet: Approval, deadline: float) -> Backends: ...
    def inspect(self, packet: Approval, deadline: float) -> dict: ...
    def release(self, packet: Approval, run: str, deadline: float) -> bool: ...


class SignedGrants:
    """Separate broker-only reviewer anchor and signed host/runtime authorizations."""

    def __init__(self, fd, *, host, runtime_sha256, private=True):
        _directory(fd, 0, private=private)
        if not host or not _HEX.fullmatch(runtime_sha256):
            raise ValueError("invalid broker runtime identity")
        self.fd, self.host, self.runtime_sha256 = fd, host, runtime_sha256

    def verify(self, packet, digest):
        decision = packet.decision_id
        if not _DECISION.fullmatch(decision):
            raise ValueError("invalid decision")
        raw = _read(self.fd, decision + ".grant", 4096, 0)
        signature = _read(self.fd, decision + ".sig", 64, 0)
        key = _read(self.fd, "reviewer.pem", 4096, 0)
        expected = {
            "host": self.host, "runtime_sha256": self.runtime_sha256,
            "decision_id": decision, "approval_sha256": digest,
            "candidate_sha256": packet.candidate_manifest_sha256,
            "scope": packet.scope, "operations": sorted(set(_CONTROL) | set(_WORKER) | {"inspect"}),
            "expires_at": packet.expires_at.isoformat(),
        }
        if raw != canonical(expected) or not _verify_ed25519(key, b"ai-soc-b4-broker-v1\n" + raw, signature):
            raise PermissionError("broker grant rejected")


    def verify_recovery(self, decision, run, digest, expiry):
        payload = canonical(dict(decision_id=decision, run_id=run, approval_sha256=digest,
                                 expires_at=expiry.isoformat(), host=self.host,
                                 runtime_sha256=self.runtime_sha256,
                                 operations=["close_scope", "observe", "inspect", "release"]))
        key = _read(self.fd, "recovery.pem", 4096, 0)
        signature = _read(self.fd, decision + ".recovery.sig", 64, 0)
        if not _verify_ed25519(key, b"ai-soc-b4-broker-recovery-v1\n" + payload, signature):
            raise PermissionError("recovery grant rejected")


class Journal:
    """Exclusive, append-only journal. Partial writes block further execution."""

    def __init__(self, fd, *, uid=0, checkpoint=None):
        _directory(fd, uid, private=True)
        self.fd, self.uid, self.checkpoint = fd, uid, checkpoint
        # One broker owns the journal until process exit, including across threads.
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.events = []
        names = sorted(os.listdir(fd))
        if len(names) > 10000:
            raise ValueError("journal capacity exhausted")
        for index, name in enumerate(names):
            if name != self.name(index):
                raise ValueError("invalid journal sequence")
            raw = _read(fd, name, 4096, uid)
            event = json.loads(raw, object_pairs_hook=_unique)
            if raw != canonical(event) or event["previous"] != self.previous:
                raise ValueError("invalid journal event")
            self.events.append((event, sha256(raw).hexdigest()))
        if self.checkpoint is not None:
            self.checkpoint("verify_checkpoint", len(self.events), self.previous)
        self.failed = False

    @staticmethod
    def name(index):
        return f"{index:05d}.json"

    @property
    def previous(self):
        return self.events[-1][1] if self.events else "0" * 64

    def append(self, decision, run, digest, event, detail=None):
        if self.failed or len(self.events) >= 10000:
            raise ValueError("journal unavailable")
        value = dict(decision=decision, run=run, approval=digest, event=event,
                     detail=detail, previous=self.previous)
        raw = canonical(value)
        if len(raw) > 4096:
            raise ValueError("journal event too large")
        self.failed = True
        name = self.name(len(self.events))
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.fd)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(self.fd)
        receipt = sha256(raw).hexdigest()
        if _read(self.fd, name, 4096, self.uid) != raw:
            raise ValueError("invalid journal receipt")
        if self.checkpoint is not None:
            self.checkpoint("checkpoint", len(self.events) + 1, receipt)
        self.events.append((json.loads(raw), receipt))
        self.failed = False
        return receipt


class Broker:
    def __init__(self, grants: SignedGrants, journal: Journal, runtime: Infrastructure):
        self.grants, self.journal, self.runtime = grants, journal, runtime
        self.lock = Lock()
        self.active = None
        self.consumed = set()
        self.report = None
        self.worker_peer = None
        self.observed = {}
        self.monitor_failed = False
        self.run_deadline = None
        self.restarted = False
        for event, _ in journal.events:
            if event["event"] == "reserved":
                self.consumed.add(event["decision"])
                self.active = event["decision"], event["run"], event["approval"]
            elif event["event"] == "released":
                self.active = None
        self.restarted = self.active is not None

    def _event(self, name, detail=None):
        return self.journal.append(*self.active, name, detail)

    def _events(self):
        return {event["event"] for event, _ in self.journal.events
                if (event["decision"], event["run"], event["approval"]) == self.active}

    def _grant(self, decision, digest, deadline, method):
        packet = self.runtime.approval(decision, deadline)
        actual = approval_sha256(packet)
        if (packet.decision_id != decision or digest not in (None, actual)
                or packet.scope != "b4-predecessor-read-only-v2"
                or packet.database != "ai_soc_test" or packet.endpoint != ("127.0.0.1", 5432)
                or packet.observed_target != packet.approved_target
                or not 1 <= packet.budgets.deadline_seconds <= 3600
                or not 1 <= packet.budgets.recovery_seconds <= 30):
            raise PermissionError("approval mismatch")
        self.grants.verify(packet, actual)
        now = datetime.now(timezone.utc)
        maximum = (packet.expires_at - now).total_seconds()
        recovery = method in {"close_scope", "backends_gone", "target_matches", "release"}
        if recovery:
            maximum += packet.budgets.recovery_seconds
        if now < packet.valid_from or maximum <= 0 or deadline - monotonic() > maximum:
            raise PermissionError("approval window closed")
        return packet, actual

    def _observe(self, packet, run, deadline, *, empty):
        try:
            self._record_observation(packet, run, deadline, empty=empty)
        except Exception:
            self.monitor_failed = True
            raise

    def _record_observation(self, packet, run, deadline, *, empty):
        check = self.runtime.observe(packet, deadline)
        _remaining(deadline)
        allowed = {packet.migrator_login, packet.observer_login}
        if (type(check) is not Backends or check.target_matches is not True or check.complete is not True
                or check.unexpected_since_hold is not False
                or len(check.sessions) > packet.budgets.max_sessions or (empty and check.sessions)):
            raise PermissionError("backend visibility or teardown unconfirmed")
        seen = {}
        for pid, login, tag in (*check.sessions, *check.connected):
            if type(pid) is not int or pid <= 0 or login not in allowed or tag != run or (pid in seen and seen[pid] != login):
                raise PermissionError("unexpected database backend")
            if pid in self.observed and self.observed[pid] != login:
                raise PermissionError("backend identity changed")
            seen[pid] = login
        if not seen.keys() <= self.observed.keys() or empty:
            self._event("backends_empty" if empty else "backends_observed", sorted(seen))
        self.observed.update(seen)

    def recover(self, *, decision, run, expires_at, deadline):
        """Custodian entry point. Never made available on either worker or control socket."""
        with self.lock:
            if self.active is None or self.active[:2] != (decision, run):
                raise PermissionError("no matching recovery scope")
            _remaining(deadline)
            if (expires_at.tzinfo is None or not 0 < (expires_at - datetime.now(timezone.utc)).total_seconds() <= 300
                    or deadline - monotonic() > 30):
                raise PermissionError("invalid recovery window")
            packet = self.runtime.approval(decision, deadline)
            digest = approval_sha256(packet)
            if digest != self.active[2]:
                raise PermissionError("recovery approval mismatch")
            self.grants.verify(packet, digest)
            self.grants.verify_recovery(decision, run, digest, expires_at)
            if "recovery_intent" in self._events() or "release_intent" in self._events():
                raise PermissionError("prior recovery or release requires manual reconciliation")
            self._event("recovery_intent")
            restore = getattr(self.runtime, "recover_freeze", None)
            if restore is not None and restore(packet, run, expires_at, deadline) is not True:
                raise PermissionError("durable freeze reconciliation failed")
            if self.runtime.close(packet, run, deadline) is not True:
                raise PermissionError("recovery scope unconfirmed")
            self._observe(packet, run, deadline, empty=True)
            docker_projection(self.runtime.inspect(packet, deadline), packet)
            _remaining(deadline)
            if self.runtime.release(packet, run, deadline) is not True:
                raise PermissionError("recovery release unconfirmed")
            self._event("released")
            self.active = None
            self.restarted = False

    def _wait(self, packet, run, deadline):
        try:
            while True:
                with self.lock:
                    if (self.active is None or self.active[1] != run or self.monitor_failed
                            or "close_intent" in self._events()
                            or self.runtime.frozen(packet, deadline) is not True):
                        raise PermissionError("worker no longer monitorable")
                    self._observe(packet, run, deadline, empty=False)
                    status = self.runtime.status(packet, run, deadline)
                    _remaining(deadline)
                    if status is not None:
                        if type(status) is not int or not 0 <= status <= 255:
                            raise ValueError("invalid worker status")
                        self._event("worker_exited", status)
                        return status
                sleep(min(0.05, _remaining(deadline)))
        except Exception:
            with self.lock:
                self.monitor_failed = True
                if self.active is not None and self.active[1] == run:
                    self._event("monitor_or_wait_failed")
            raise

    def dispatch(self, channel, peer, request):
        worker = channel == "worker"
        if not worker and (channel != "control" or (peer.uid, peer.gid) != (136, 147)):
            raise PermissionError("unauthorized broker peer")
        method = request["method"]
        fields = (_WORKER if worker else _CONTROL)[method]
        decision, deadline = request["decision_id"], request["deadline"]
        common = {"method", "decision_id", "deadline", "nonce"}
        if not worker:
            common.add("approval_sha256")
        if (set(request) != common | set(fields) or not _DECISION.fullmatch(decision)
                or not re.fullmatch(r"[0-9a-f]{32}", request["nonce"])
                or type(deadline) not in (int, float) or not math.isfinite(deadline)
                or not 0 < deadline - monotonic() <= 3630):
            raise ValueError("invalid broker request")
        run = request.get("run_id")
        if "run_id" in fields and (type(run) is not str or not _RUN.fullmatch(run)):
            raise ValueError("invalid run")
        if worker and (peer.uid in (0, 136) or peer.gid in (0, 147) or peer.pid <= 0):
            raise PermissionError("unauthorized worker peer")
        input_digest = request.get("approval_sha256")
        if not worker and (type(input_digest) is not str or not _HEX.fullmatch(input_digest)):
            raise ValueError("invalid approval digest")
        packet, digest = self._grant(decision, input_digest, deadline, method)
        with self.lock:
            _remaining(deadline)
            if self.journal.failed or self.restarted:
                raise PermissionError("broker recovery required")
            if method == "frozen":
                return self.active is None and self.runtime.frozen(packet, deadline) is True
            if method == "recovery":
                until = request["until"]
                return (type(until) in (int, float) and math.isfinite(until) and deadline <= until
                        <= monotonic() + packet.budgets.deadline_seconds + packet.budgets.recovery_seconds
                        and until - monotonic() <= (packet.expires_at - datetime.now(timezone.utc)).total_seconds()
                        + packet.budgets.recovery_seconds)
            if method == "hold":
                if self.active is not None or decision in self.consumed:
                    raise PermissionError("decision already used or target held")
                self.journal.append(decision, run, digest, "reserved")
                self.consumed.add(decision)
                self.active = decision, run, digest
                self.run_deadline = min(deadline, monotonic() + packet.budgets.deadline_seconds)
                self.observed.clear()
                self.report = None
                self.worker_peer = None
                self.monitor_failed = False
                if self.runtime.hold(packet, run, deadline) is not True:
                    raise PermissionError("administrative freeze unconfirmed")
                self._event("held")
                return True
            if self.active is None or self.active[0] != decision or self.active[2] != digest:
                raise PermissionError("no matching active run")
            if run is not None and run != self.active[1]:
                raise PermissionError("run mismatch")
            run = self.active[1]
            if method in {"close_scope", "backends_gone", "target_matches", "release"}:
                deadline = min(deadline, self.run_deadline + packet.budgets.recovery_seconds)
                _remaining(deadline)
            events = self._events()
            if worker and (
                "start_intent" not in events or "close_intent" in events
                or (self.worker_peer is not None and self.worker_peer != peer)
                or self.runtime.worker(packet, peer, deadline) is not True
            ):
                raise PermissionError("worker containment unconfirmed")
            if method in _EXECUTION and (monotonic() >= self.run_deadline or self.monitor_failed or "held" not in events or "close_intent" in events
                                        or self.runtime.frozen(packet, deadline) is not True):
                raise PermissionError("execution freeze unconfirmed")
            if method in _EXECUTION:
                deadline = min(deadline, self.run_deadline)
            if method == "start" and "start_intent" not in events:
                self._observe(packet, run, deadline, empty=True)
                self._event("start_intent")
                if self.runtime.start(packet, run, deadline) is not True:
                    raise PermissionError("worker launch unconfirmed")
                self._event("started")
                return True
            if method == "worker_handoff" and "handoff" not in events:
                data = self.runtime.handoff(packet, run, deadline)
                if (type(data) is not dict or set(data) !=
                        {"packet", "trusted_digest", "isolation", "ca", "freeze", "run_id", "credentials", "admission"}
                        or data["trusted_digest"] != digest or data["run_id"] != run
                        or len(canonical(data)) > _LIMIT - 128):
                    raise ValueError("invalid worker handoff")
                if (_approval(canonical(data["packet"])) != packet
                        or type(data["credentials"]) is not dict
                        or set(data["credentials"]) != {packet.migrator_secret_ref, packet.observer_secret_ref}):
                    raise PermissionError("unbound credential handoff")
                for field, expected in (("isolation", packet.application_isolation_sha256),
                                        ("ca", packet.tls_ca_sha256), ("freeze", packet.freeze_sha256)):
                    if sha256(b64decode(data[field], validate=True)).hexdigest() != expected:
                        raise PermissionError("unbound handoff artifact")
                _remaining(deadline)
                from app.database.source_registry_b4_admission import AdmissionProof

                proof = AdmissionProof.validate(data["admission"], packet, run, digest,
                                                data["admission"]["stop_by"])
                if proof.stop_by > self.run_deadline:
                    raise PermissionError("admission deadline exceeds broker window")
                self._event("handoff", proof.digest)
                self.worker_peer = peer
                return data
            if method == "worker_result" and "handoff" in events and "worker_result" not in events:
                fields = request["report"]
                if type(fields) is not dict or len(canonical(fields)) > 4096:
                    raise ValueError("invalid worker report")
                report = Report(**{**fields, "versions": tuple(fields["versions"]),
                                   "backend_pids": tuple(fields["backend_pids"])})
                self._observe(packet, run, deadline, empty=False)
                code, pids = _worker_result(report, digest, run)
                if (code == "INVALID_REPORT" or report.run_id not in (None, run)
                        or report.approval_sha256 not in (None, digest)):
                    raise PermissionError("invalid worker report")
                if code == "VERIFIED" and ({self.observed.get(pid) for pid in pids}
                                            != {packet.migrator_login, packet.observer_login}):
                    raise PermissionError("worker backends not independently observed")
                sanitized = (asdict(report) if code == "VERIFIED" else asdict(
                    Report("FAIL", "worker", code, (), None, None, "UNCONFIRMED", run, (), digest)
                ))
                self._event("worker_result", sanitized)
                self.report = sanitized
                return True
            if method == "report" and "worker_exited" in events and self.report is not None:
                return self.report
            if method == "close_scope":
                self._event("close_intent")
                try:
                    if self.runtime.close(packet, run, deadline) is not True:
                        raise PermissionError("scope teardown unconfirmed")
                except Exception:
                    self.monitor_failed = True
                    self._event("containment_failed")
                    raise
                self._event("closed")
                return True
            if method == "backends_gone" and "closed" in events:
                pids = request["backend_pids"]
                if type(pids) is not list or len(pids) > 2 or any(type(pid) is not int or pid <= 0 for pid in pids):
                    raise ValueError("invalid backend list")
                self._observe(packet, run, deadline, empty=True)
                self._event("teardown")
                return True
            if method == "target_matches":
                docker_projection(self.runtime.inspect(packet, deadline), packet)
                self._event("target_checked")
                return True
            if method == "release" and {"closed", "teardown", "target_checked"} <= events:
                if self.monitor_failed or "release_intent" in events:
                    raise PermissionError("freeze release requires independent recovery")
                self._observe(packet, run, deadline, empty=True)
                docker_projection(self.runtime.inspect(packet, deadline), packet)
                self._event("release_intent")
                if self.runtime.release(packet, run, deadline) is not True:
                    raise PermissionError("freeze release unconfirmed")
                self._event("released")
                self.active = None
                return True
            if method != "wait" or "started" not in events or "worker_exited" in events:
                raise PermissionError("operation outside run lifecycle")
        return self._wait(packet, run, deadline)

    def serve(self, listeners):
        """Accept on protected, prebound listeners, with separate per-channel admission limits."""
        paths = {"control": CONTROL_SOCKET, "worker": WORKER_SOCKET,
                 "docker": Path("/run/ai-soc-b4/docker-inspect.sock")}
        if set(listeners) != set(paths):
            raise ValueError("missing broker listeners")
        capacity = {name: BoundedSemaphore(4) for name in paths}

        def serve_request(name, connection):
            try:
                if name == "docker":
                    handle_docker(self, paths[name], connection)
                else:
                    self.handle(paths[name], connection, channel=name)
            finally:
                capacity[name].release()

        with DefaultSelector() as selector:
            for name, path in paths.items():
                listener = listeners[name]
                _socket_metadata(path)
                if (listener.family != socket.AF_UNIX or
                        listener.getsockname() != os.fspath(path) or
                        not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)):
                    raise ValueError("unbound broker listener")
                selector.register(listener, EVENT_READ, name)
            while True:
                for key, _ in selector.select():
                    connection, _ = key.fileobj.accept()
                    if not capacity[key.data].acquire(blocking=False):
                        connection.close()
                        continue
                    try:
                        Thread(target=serve_request, args=(key.data, connection), daemon=True).start()
                    except Exception:
                        connection.close()
                        capacity[key.data].release()
                        raise

    def handle(self, path, connection, *, channel):
        """Serve one request on an already bound, protected Unix listener."""
        try:
            _socket_metadata(path)
            peer = Peer.from_socket(connection)
            deadline = monotonic() + 2
            data = bytearray()
            while len(data) <= _LIMIT:
                connection.settimeout(_remaining(deadline))
                chunk = connection.recv(min(16384, _LIMIT + 1 - len(data)))
                if not chunk:
                    return
                data.extend(chunk)
                if b"\n" in chunk:
                    break
            if len(data) > _LIMIT or not data.endswith(b"\n") or data.count(b"\n") != 1:
                return
            request = json.loads(data, object_pairs_hook=_unique)
            result = self.dispatch(channel, peer, request)
            reply = canonical({"nonce": request["nonce"], "result": result})
            if len(reply) <= _LIMIT:
                connection.settimeout(_remaining(request["deadline"]))
                connection.sendall(reply + b"\n")
        except Exception:
            # Never reflect rejected payloads, credentials, or infrastructure errors.
            return
        finally:
            connection.close()


def docker_projection(value, packet):
    pin = packet.approved_target
    networks = value["NetworkSettings"]["Networks"]
    ports = value["NetworkSettings"]["Ports"]
    if (value["Id"] != pin.container_id or value["Image"] != pin.image_id
            or value["Name"] != "/ai-soc-postgres" or value["Config"]["Image"] != "postgres:16"
            or value["State"]["Status"] != "running"
            or ports != {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "5432"}]}
            or set(networks) != {pin.network}):
        raise PermissionError("Docker identity changed")
    network = networks[pin.network]
    if (network["NetworkID"] != pin.network_id
            or (network["IPAddress"], network["Gateway"]) != tuple(map(str, pin.address_pair))):
        raise PermissionError("Docker network changed")
    return {
        "Id": value["Id"], "Image": value["Image"], "Name": value["Name"],
        "Config": {"Image": value["Config"]["Image"]},
        "State": {"Status": value["State"]["Status"]},
        "NetworkSettings": {"Ports": ports, "Networks": {pin.network: {
            name: network[name] for name in ("NetworkID", "Gateway", "IPAddress")
        }}},
    }


def docker_response(broker, peer, method, path, deadline):
    """Allow only Docker CLI negotiation and the one preflight container inspection."""
    with broker.lock:
        if (broker.active is None or broker.restarted or broker.monitor_failed or
                broker.journal.failed or "start_intent" not in broker._events() or
                "close_intent" in broker._events() or broker.worker_peer != peer or
                (peer.uid in (0, 136) or peer.gid in (0, 147) or peer.pid <= 0)):
            raise PermissionError("Docker inspection denied")
        deadline = min(deadline, broker.run_deadline)
        _remaining(deadline)
        decision, _, digest = broker.active
        packet, _ = broker._grant(decision, digest, deadline, "worker_handoff")
        if (broker.runtime.worker(packet, peer, deadline) is not True or
                broker.runtime.frozen(packet, deadline) is not True):
            raise PermissionError("Docker peer or freeze unverified")
        if path == "/_ping" and method in {"HEAD", "GET"}:
            return b"" if method == "HEAD" else b"OK"
        if method != "GET" or not re.fullmatch(r"/v1\.[0-9]{2}/containers/ai-soc-postgres/json", path):
            raise PermissionError("unapproved Docker request")
        result = canonical(docker_projection(broker.runtime.inspect(packet, deadline), packet))
        _remaining(deadline)
        return result


def handle_docker(broker, path, connection):
    """Serve one bounded HTTP/1 request. The request is never forwarded."""
    try:
        _socket_metadata(path)
        peer = Peer.from_socket(connection)
        deadline = monotonic() + 2
        data = bytearray()
        while b"\r\n\r\n" not in data and len(data) < 8192:
            connection.settimeout(_remaining(deadline))
            chunk = connection.recv(min(4096, 8192 - len(data)))
            if not chunk:
                return
            data.extend(chunk)
        header, body = bytes(data).split(b"\r\n\r\n", 1)
        request, *headers = header.decode("ascii").split("\r\n")
        method, endpoint, protocol = request.split(" ")
        seen = set()
        for line in headers:
            name, value = line.split(":", 1)
            name = name.lower()
            if (not re.fullmatch(r"[a-z0-9-]+", name) or name in seen or name == "transfer-encoding"
                    or (name == "content-length" and value.strip() != "0")):
                return
            seen.add(name)
        if body or protocol != "HTTP/1.1":
            return
        payload = docker_response(broker, peer, method, endpoint, deadline)
        connection.settimeout(_remaining(deadline))
        connection.sendall(
            b"HTTP/1.1 200 OK\r\nApi-Version: 1.44\r\nOstype: linux\r\n"
            b"Content-Type: application/json\r\nConnection: close\r\nContent-Length: "
            + str(len(payload)).encode("ascii") + b"\r\n\r\n" + payload
        )
    except Exception:
        return
    finally:
        connection.close()
