"""Independent local B4 authority. Host attestations are explicit, mandatory inputs."""
from datetime import datetime, timezone
import json
import math
import re
from threading import Lock
from time import monotonic

from app.database.source_registry_b4_admission import AdmissionProof
from app.database.source_registry_b4_broker import _LIMIT, _remaining
from app.database.source_registry_b4_broker_server import Peer, canonical, docker_projection
from app.database.source_registry_b4_runtime import Cgroup
from app.database.source_registry_local_inputs import _DECISION, _HEX, _RUN, _unique
from app.database.source_registry_preflight import approval_sha256


_FIELDS = {
    "frozen": (), "hold": ("run_id",), "start": ("run_id", "cgroup", "stop_by"),
    "handoff": ("run_id",), "status": ("run_id",), "stop": ("run_id", "cgroup"),
    "scope_closed": ("run_id", "cgroup"), "observe": ("run_id", "after"),
    "recover": ("run_id", "expires_at"), "inspect": (), "release": ("run_id", "through"),
}
_CAPABILITIES = dict(credential_custody=True, durable_freeze=True, continuous_backend_events=True,
                     independent_checkpoints=True, worker_egress_policy=True,
                     worker_filesystem_policy=True, independent_scope_deadline=True)
_RECOVERY = {"recover", "stop", "scope_closed", "observe", "inspect", "release"}


class AuthorityService:
    """Durable protocol state. All host effects use the separately controlled host adapter.

    Host operations must enforce their deadlines independently of the RPC. In
    particular start() may only succeed once a kernel/service-manager deadline
    survives both service processes exiting. stop() disables scope recreation.
    """

    def __init__(self, journal, grants, host, *, broker_peer):
        self.journal, self.grants, self.host, self.broker_peer = journal, grants, host, broker_peer
        self.lock = Lock()
        self.active = None
        self.consumed = set()
        self.checkpoints = []
        for event, _ in journal.events:
            name = event["event"]
            if name == "checkpoint":
                self.checkpoints.append(event["detail"])
            elif name == "reserve":
                self.active = event["decision"], event["run"], event["approval"]
                self.consumed.add(event["decision"])
            elif name == "released":
                self.active = None
        self.restart = self.active is not None
        self.deadline = None
        self.recovery_until = None

    def _events(self):
        return {event["event"]: event["detail"] for event, _ in self.journal.events
                if (event["decision"], event["run"], event["approval"]) == self.active}

    def _record(self, operation, detail=None):
        self.journal.append(*self.active, operation, detail)

    def _admission(self, packet, run, digest, deadline, *, expected=None, cleanup=False):
        raw = self.host.admission(packet, run, deadline)
        proof = AdmissionProof.validate(raw, packet, run, digest,
                                        self.deadline if expected is None else expected["stop_by"],
                                        cleanup=cleanup)
        if expected is not None and proof.digest != expected["digest"]:
            raise PermissionError("admission or freeze proof drift")
        _remaining(deadline)
        return proof, raw

    def _checkpoint(self, operation, payload):
        if (set(payload) != {"sequence", "sha256"} or type(payload["sequence"]) is not int
                or payload["sequence"] < 0 or not _HEX.fullmatch(payload["sha256"])):
            raise ValueError("invalid checkpoint")
        sequence = payload["sequence"]
        head = self.checkpoints[-1] if self.checkpoints else {"sequence": 0, "sha256": "0" * 64}
        if operation == "checkpoint" and sequence == head["sequence"] + 1:
            self.journal.append("", "", "", "checkpoint", dict(payload))
            self.checkpoints.append(dict(payload))
        elif payload != head:
            raise PermissionError("checkpoint does not match independently retained head")
        return {**payload, "durable": True}

    def dispatch(self, peer, operation, payload, deadline):
        if not self.broker_peer(peer):
            raise PermissionError("unauthenticated broker process")
        if type(payload) is not dict or type(deadline) not in (int, float) or not math.isfinite(deadline):
            raise ValueError("invalid request")
        if not 0 < _remaining(deadline) <= 3630:
            raise ValueError("invalid deadline")
        with self.lock:
            _remaining(deadline)
            if self.journal.failed:
                raise PermissionError("authority journal unavailable")
            if operation == "readiness" and not payload:
                if self.host.ready(deadline) is not True:
                    raise PermissionError("host enforcement unavailable")
                return dict(_CAPABILITIES)
            if operation in {"checkpoint", "verify_checkpoint"}:
                return self._checkpoint(operation, payload)
            if set(payload) != {"decision_id", "approval_sha256", *_FIELDS[operation]}:
                raise ValueError("unexpected authority arguments")
            decision, digest = payload["decision_id"], payload["approval_sha256"]
            run = payload.get("run_id")
            if (not _DECISION.fullmatch(decision) or not _HEX.fullmatch(digest)
                    or ("run_id" in payload and not _RUN.fullmatch(run))):
                raise ValueError("invalid authority scope")
            packet = self.host.approval(decision, deadline)
            if (packet.decision_id != decision or approval_sha256(packet) != digest
                    or packet.scope != "b4-predecessor-read-only-v2" or packet.database != "ai_soc_test"
                    or packet.endpoint != ("127.0.0.1", 5432)
                    or packet.approved_target != packet.observed_target):
                raise PermissionError("approval scope mismatch")
            self.grants.verify(packet, digest)
            now = datetime.now(timezone.utc)
            if now < packet.valid_from:
                raise PermissionError("approval not yet valid")
            remaining = (packet.expires_at - now).total_seconds()
            if operation not in _RECOVERY and remaining <= 0:
                raise PermissionError("approval expired")
            if operation == "frozen":
                if self.active is None:
                    return self.host.ready(deadline) is True
                if self.active[::2] != (decision, digest):
                    return False
                events = self._events()
                if "admission_unconfirmed" in events:
                    return False
                try:
                    if "admission" in events and self.host.frozen(packet, self.active[1], deadline) is True:
                        self._admission(packet, self.active[1], digest, deadline, expected=events["admission"])
                        return True
                except Exception:
                    self._record("admission_unconfirmed")
                    raise
                self._record("admission_unconfirmed")
                return False
            if operation == "hold":
                if self.active is not None or decision in self.consumed or self.host.ready(deadline) is not True:
                    raise PermissionError("target frozen, decision consumed, or host unavailable")
                if remaining <= 0:
                    raise PermissionError("approval expired")
                self.active = decision, run, digest
                self._record("reserve")
                self.consumed.add(decision)
                self.deadline = min(deadline, monotonic() + remaining, monotonic() + packet.budgets.deadline_seconds)
                cursor = self.host.hold(packet, run, self.deadline)
                if type(cursor) is not int or cursor < 0:
                    raise PermissionError("exclusive freeze unconfirmed")
                proof, _ = self._admission(packet, run, digest, self.deadline)
                self._record("admission", {"digest": proof.digest, "stop_by": proof.stop_by})
                self._record("held", cursor)
                return {"run_id": run, "durable": True, "cursor": cursor}
            if self.active is None or self.active[::2] != (decision, digest) or (
                    run is not None and self.active[1] != run):
                raise PermissionError("no matching freeze")
            run = self.active[1]
            events = self._events()
            if operation == "recover":
                expiry = datetime.fromisoformat(payload["expires_at"])
                if (expiry.utcoffset() is None or not 0 < (expiry - now).total_seconds() <= 300
                        or "recovery" in events or "released" in events or "release_intent" in events
                        or "held" not in events):
                    raise PermissionError("recovery unavailable")
                self.grants.verify_recovery(decision, run, digest, expiry)
                self._record("recovery")
                self.recovery_until = min(deadline, monotonic() + (expiry - now).total_seconds())
                return {"run_id": run, "durable": True, "cursor": events["held"]}
            recovery_active = self.recovery_until is not None and monotonic() < self.recovery_until
            stale = (self.restart or self.deadline is None or
                     monotonic() >= self.deadline + packet.budgets.recovery_seconds or
                     remaining <= -packet.budgets.recovery_seconds)
            if stale and not recovery_active:
                raise PermissionError("independent recovery required")
            if "held" not in events:
                raise PermissionError("administrative freeze not recorded")
            try:
                if self.host.frozen(packet, run, deadline) is not True:
                    raise PermissionError("administrative freeze unconfirmed")
            except Exception:
                if "admission_unconfirmed" not in events:
                    self._record("admission_unconfirmed")
                raise
            if "cgroup" in payload and payload["cgroup"] != Cgroup.name(decision):
                raise PermissionError("unexpected cgroup")
            if operation in {"start", "handoff", "status"} and (
                    recovery_active or remaining <= 0 or monotonic() >= self.deadline or "stop" in events):
                raise PermissionError("execution window closed")
            if operation in {"start", "handoff", "status", "release"}:
                if "admission" not in events:
                    raise PermissionError("admission proof not recorded")
                try:
                    proof, raw_proof = self._admission(packet, run, digest, deadline,
                                                       expected=events["admission"], cleanup=operation == "release")
                except Exception:
                    self._record("admission_unconfirmed")
                    raise
                if "admission_unconfirmed" in events:
                    raise PermissionError("admission continuity requires manual reconciliation")
            if operation == "start" and "start_intent" not in events:
                stop_by = payload["stop_by"]
                if (type(stop_by) not in (float, int) or not math.isfinite(stop_by)
                        or not monotonic() < stop_by <= deadline or stop_by > self.deadline):
                    raise PermissionError("invalid worker deadline")
                self._record("start_intent", stop_by)
                try:
                    if self.host.start(packet, run, Cgroup.name(decision), stop_by) is not True:
                        raise PermissionError("worker containment or deadline unverified")
                except Exception:
                    self._record("admission_unconfirmed")
                    raise
                self._record("started")
                return {"run_id": run, "cgroup": Cgroup.name(decision), "stop_by": stop_by,
                        "deadline_armed": True, "sandbox_verified": True}
            if operation == "handoff" and "started" in events and "handoff" not in events:
                try:
                    if self.host.deadline_armed(packet, run, events["start_intent"], deadline) is not True:
                        raise PermissionError("service-manager deadline unconfirmed")
                except Exception:
                    self._record("admission_unconfirmed")
                    raise
                result = self.host.handoff(packet, run, min(deadline, self.deadline))
                if type(result) is not dict or "admission" in result:
                    raise PermissionError("invalid trusted credential handoff")
                result = {**result, "admission": raw_proof}
                _remaining(self.deadline)
                self._record("handoff")
                return result
            if operation == "status" and "started" in events:
                return self.host.status(packet, run, min(deadline, self.deadline))
            if operation == "stop":
                if "stop" not in events:
                    self._record("stop")
                return self.host.stop(packet, run, deadline) is True
            if operation == "scope_closed" and "stop" in events:
                if self.host.scope_closed(packet, run, deadline) is not True:
                    return False
                if "closed" not in events:
                    self._record("closed")
                return True
            if operation == "observe":
                try:
                    report = self.host.observe(packet, run, payload["after"], deadline)
                    if (type(report) is not dict or report.get("complete") is not True
                            or report.get("target_matches") is not True):
                        raise PermissionError("monitor unavailable")
                    return report
                except Exception:
                    if "monitor_failed" not in events:
                        self._record("monitor_failed")
                    raise
            if operation == "inspect":
                return docker_projection(self.host.inspect(packet, deadline), packet)
            if operation == "release" and "closed" in events and "release_intent" not in events:
                through = payload["through"]
                if type(through) is not int or through < events["held"]:
                    raise PermissionError("invalid release barrier")
                if self.host.scope_closed(packet, run, deadline) is not True:
                    raise PermissionError("worker teardown unconfirmed")
                if not HostEvidence.empty(packet, run, events["held"],
                                          self.host.observe(packet, run, events["held"], deadline), through):
                    self._record("monitor_failed")
                    raise PermissionError("full monitoring coverage unconfirmed")
                if "monitor_failed" in events:
                    raise PermissionError("prior monitoring failure requires manual reconciliation")
                docker_projection(self.host.inspect(packet, deadline), packet)
                self._record("release_intent", through)
                # The host gate must atomically compare stream coverage, zero active
                # sessions, unchanged target and ownership before releasing.
                if self.host.release(packet, run, through, deadline) is not True:
                    raise PermissionError("freeze release unconfirmed")
                self._record("released")
                self.active = None
                self.restart = False
                self.recovery_until = None
                return True
            raise PermissionError("operation outside authority lifecycle")

    def handle(self, conn):
        """Serve one authenticated, bounded request without exposing failure details."""
        try:
            peer = Peer.from_socket(conn)
            if not self.broker_peer(peer):
                return
            deadline = monotonic() + 2
            conn.settimeout(_remaining(deadline))
            conn.sendall(b"B")
            raw = bytearray()
            while len(raw) <= _LIMIT:
                conn.settimeout(_remaining(deadline))
                part = conn.recv(min(16384, _LIMIT + 1 - len(raw)))
                if not part:
                    return
                raw.extend(part)
                if b"\n" in part:
                    break
            if len(raw) > _LIMIT or raw.count(b"\n") != 1 or not raw.endswith(b"\n"):
                return
            message = json.loads(raw, object_pairs_hook=_unique)
            if (set(message) != {"operation", "payload", "nonce", "deadline"}
                    or not re.fullmatch(r"[0-9a-f]{32}", message["nonce"])):
                return
            result = self.dispatch(peer, message["operation"], message["payload"], message["deadline"])
            reply = canonical({"nonce": message["nonce"], "result": result})
            if len(reply) <= _LIMIT:
                conn.settimeout(_remaining(message["deadline"]))
                conn.sendall(reply + b"\n")
        except Exception:
            return
        finally:
            conn.close()


class HostEvidence:
    """Validate a complete event history against an independent active snapshot."""

    @staticmethod
    def empty(packet, run, cursor, batch, through):
        if (type(batch) is not dict or set(batch) != {"target_matches", "complete", "through", "events", "sessions"}
                or batch["complete"] is not True or batch["target_matches"] is not True
                or type(through) is not int or type(batch["through"]) is not int or through != batch["through"]
                or type(batch["events"]) is not list or len(batch["events"]) > 4096 or batch["sessions"] != []):
            return False
        sessions = {}
        for index, event in enumerate(batch["events"], cursor + 1):
            if type(event) is not list or len(event) != 5:
                return False
            sequence, kind, pid, role, tag = event
            if (type(sequence) is not int or sequence != index or type(pid) is not int or pid <= 0
                    or role not in (packet.migrator_login, packet.observer_login) or tag != run):
                return False
            if kind == "connect" and pid not in sessions and len(sessions) < packet.budgets.max_sessions:
                sessions[pid] = role
            elif kind != "disconnect" or sessions.pop(pid, None) != role:
                return False
        return not sessions and through == cursor + len(batch["events"])


class LinuxHost:
    """Narrow bridge to host control and event collection, with local cgroup checks."""

    def __init__(self, records_fd, cgroup, control):
        self.records_fd, self.cgroup, self.control = records_fd, cgroup, control

    def approval(self, decision, deadline):
        from app.database.source_registry_local_inputs import _approval, _read

        _remaining(deadline)
        if not _DECISION.fullmatch(decision):
            raise ValueError("invalid approval decision")
        return _approval(_read(self.records_fd, decision + ".json", 32768, 0))

    def request(self, name, packet, deadline, **fields):
        return self.control.request(name, dict(decision_id=packet.decision_id,
                                    approval_sha256=approval_sha256(packet), **fields), deadline)

    def ready(self, deadline):
        return self.control.request("readiness", {}, deadline) == _CAPABILITIES

    def frozen(self, packet, run, deadline):
        return self.request("frozen", packet, deadline, run_id=run) is True

    def hold(self, packet, run, deadline):
        receipt = self.request("hold", packet, deadline, run_id=run)
        if (type(receipt) is not dict or set(receipt) != {"run_id", "durable", "cursor"}
                or receipt["run_id"] != run or receipt["durable"] is not True):
            raise PermissionError("no durable administrative freeze")
        return receipt["cursor"]

    def start(self, packet, run, scope, deadline):
        armed = self.request("arm_scope", packet, deadline, run_id=run, cgroup=scope, stop_by=deadline)
        if armed != {"run_id": run, "cgroup": scope, "stop_by": deadline}:
            return False
        receipt = self.request("start", packet, deadline, run_id=run, cgroup=scope, stop_by=deadline)
        if (type(receipt) is not dict or set(receipt) != {"run_id", "cgroup", "stop_by", "sandbox_verified",
                                                        "deadline_armed", "pid", "uid", "gid"}
                or receipt["run_id"] != run or receipt["cgroup"] != scope or receipt["stop_by"] != deadline
                or receipt["sandbox_verified"] is not True or receipt["deadline_armed"] is not True
                or any(type(receipt[field]) is not int or receipt[field] <= 0 for field in ("pid", "uid", "gid"))):
            return False
        _remaining(deadline)
        return (self.cgroup.member(packet.decision_id, Peer(receipt["pid"], receipt["uid"], receipt["gid"]),
                                   self.control.uid, self.control.gid)
                and self.deadline_armed(packet, run, deadline, deadline))

    def admission(self, packet, run, deadline):
        return self.request("admission", packet, deadline, run_id=run)

    def deadline_armed(self, packet, run, stop_by, deadline):
        receipt = self.request("service_deadline", packet, deadline, run_id=run, stop_by=stop_by)
        return receipt == {"run_id": run, "cgroup": self.cgroup.name(packet.decision_id),
                           "stop_by": stop_by, "manager_verified": True}

    def handoff(self, packet, run, deadline):
        return self.request("handoff", packet, deadline, run_id=run)

    def status(self, packet, run, deadline):
        return self.request("status", packet, deadline, run_id=run)

    def stop(self, packet, run, deadline):
        return self.request("stop", packet, deadline, run_id=run) is True

    def scope_closed(self, packet, run, deadline):
        return (self.request("scope_closed", packet, deadline, run_id=run) is True
                and self.cgroup.empty(packet.decision_id))

    def observe(self, packet, run, after, deadline):
        if type(after) is not int or after < 0:
            raise ValueError("invalid monitor cursor")
        return self.request("observe", packet, deadline, run_id=run, after=after)

    def inspect(self, packet, deadline):
        return self.request("inspect", packet, deadline)

    def release(self, packet, run, through, deadline):
        return self.request("release", packet, deadline, run_id=run, through=through) is True
