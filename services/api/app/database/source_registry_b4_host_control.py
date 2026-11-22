"""Root-owned checkpoint custody and cgroup watchdog for B4."""
from datetime import datetime, timezone
import math
import re
import signal
from subprocess import SubprocessError, run as run_command
from threading import Lock
from time import monotonic

from app.database.source_registry_b4_authority import AuthorityService
from app.database.source_registry_b4_broker import _remaining
from app.database.source_registry_b4_runtime import Cgroup
from app.database.source_registry_local_inputs import _DECISION, _HEX, _RUN, _approval, _read
from app.database.source_registry_preflight import approval_sha256


def manager_deadline(decision, stop_by, deadline, *, command=run_command):
    """Return the effective PID 1 unit invocation and activation time, or reject."""
    if not _DECISION.fullmatch(decision):
        return None

    def read(args):
        response = command(args,
                           timeout=min(2, _remaining(deadline)), check=True, capture_output=True,
                           text=True, env={"PATH": "/usr/bin", "LC_ALL": "C"})
        _remaining(deadline)
        return response.stdout.splitlines()

    def query(keys, unit=None):
        lines = read(["/usr/bin/systemctl", "--system", "show", "--no-pager", "--all",
                      *(f"--property={key}" for key in keys), *(["--", unit] if unit else [])])
        values = dict(line.split("=", 1) for line in lines)
        if len(values) != len(lines):
            raise ValueError("duplicate manager property")
        return values

    required = {
        "Type": "exec", "ActiveState": "active", "SubState": "running",
        "ControlGroup": Cgroup.name(decision), "TimeoutStartUSec": "5s",
        "RuntimeMaxUSec": "30s", "TimeoutStopUSec": "5s",
        "TimeoutStopFailureMode": "kill", "Restart": "no", "KillMode": "control-group",
        "SendSIGKILL": "yes",
    }
    jitter = "RuntimeRandomizedExtraUSec"
    keys = (*required, "ActiveEnterTimestampMonotonic", "InvocationID", "FinalKillSignal", jitter)
    try:
        manager_keys = ("UserspaceTimestampMonotonic", "Version")
        manager = query(manager_keys)
        version = re.fullmatch(r"([0-9]{3,4})(?:[. ~+-][ -~]+)?", manager.get("Version", ""))
        epoch = manager.get("UserspaceTimestampMonotonic", "")
        if (set(manager) != set(manager_keys) or version is None or int(version[1]) < 249
                or not re.fullmatch(r"[1-9][0-9]{0,19}", epoch)):
            return None
        unit = f"ai-soc-b4-worker@{decision}.service"
        values = query(keys, unit)
        # systemctl 249 omits empty Exec arrays even with --all. Read
        # their typed values so missing properties cannot pass as empty.
        label = "".join(ch if ch.isalnum() else f"_{ord(ch):02x}" for ch in unit)
        hooks = read(["/usr/bin/busctl", "--system", "--no-pager", "get-property",
                      "org.freedesktop.systemd1", f"/org/freedesktop/systemd1/unit/{label}",
                      "org.freedesktop.systemd1.Service", "ExecStop", "ExecStopPost"])
        if hooks != ["a(sasbttttuii) 0"] * 2:
            return None
        if query(manager_keys) != manager:
            return None
    except (OSError, SubprocessError, ValueError):
        return None
    # Stock 249 has no jitter setting. On newer managers (or backports
    # exposing it), an explicitly observed zero value is required.
    expected_keys = set(keys)
    if int(version[1]) == 249 and jitter not in values:
        expected_keys.remove(jitter)
    if (set(values) != expected_keys or any(values[key] != value for key, value in required.items())
            or (jitter in values and values[jitter] not in {"0", "0us"})
            or values["FinalKillSignal"] not in {str(signal.SIGKILL.value), "SIGKILL"}):
        return None
    entered, invocation = values["ActiveEnterTimestampMonotonic"], values["InvocationID"]
    if (not re.fullmatch(r"[0-9]{1,20}", entered) or not re.fullmatch(r"[0-9a-f]{32}", invocation)
            or invocation == "0" * 32):
        return None
    active_at = int(entered) / 1_000_000
    now = monotonic()
    if 0 < active_at <= now < active_at + 30 and active_at + 35 <= stop_by:
        return manager["Version"], epoch, invocation, entered
    return None


class HostController:
    # Reuse the bounded, peer-authenticated authority wire transport.
    handle = AuthorityService.handle

    def __init__(self, journal, grants, cgroup, records_fd, *, authority_peer):
        self.journal, self.grants, self.cgroup = journal, grants, cgroup
        self.records_fd, self.broker_peer = records_fd, authority_peer
        self.lock = Lock()
        self.head = {"sequence": 0, "sha256": "0" * 64}
        self.guard = None
        self.invocation = None
        self.used = set()
        for event, _ in journal.events:
            if event["event"] == "authority_checkpoint":
                self.head = event["detail"]
            if event["event"] == "scope_armed":
                self.guard = (event["decision"], event["run"], event["approval"], 0)
                self.used.add(event["decision"])
        # Monotonic deadlines are never resumed across a controller restart.
        # A still-present scope must be killed before further operation.

    def tick(self):
        guard = self.guard
        if guard is None or monotonic() < guard[3]:
            return True
        return self.cgroup.kill_and_empty(guard[0], monotonic() + 1)

    def dispatch(self, peer, operation, payload, deadline):
        if not self.broker_peer(peer):
            raise PermissionError("unauthenticated authority process")
        if type(payload) is not dict or type(deadline) not in (float, int) or not math.isfinite(deadline):
            raise ValueError("invalid host control request")
        _remaining(deadline)
        with self.lock:
            _remaining(deadline)
            if self.journal.failed:
                raise PermissionError("host controller journal unavailable")
            if operation in {"authority_checkpoint", "verify_authority_checkpoint"}:
                return self.checkpoint(operation, payload)
            if operation == "readiness" and not payload:
                # There is no approved authenticated PostgreSQL producer or
                # gate for all administrative paths. Do not admit a B4 run.
                return False
            if operation == "service_deadline":
                if set(payload) != {"decision_id", "approval_sha256", "run_id", "stop_by"}:
                    raise ValueError("invalid deadline proof request")
                decision, run, digest, stop_by = (payload[key] for key in
                                                  ("decision_id", "run_id", "approval_sha256", "stop_by"))
                if (type(stop_by) not in (int, float) or self.guard != (decision, run, digest, stop_by)
                        or not monotonic() < stop_by):
                    raise PermissionError("service-manager deadline unconfirmed")
                invocation = manager_deadline(decision, stop_by, deadline)
                if (invocation is None or (self.invocation is not None and invocation != self.invocation)
                        or not self.cgroup.recursive_kill_available(decision)):
                    raise PermissionError("service-manager scope or recursive kill unconfirmed")
                _remaining(min(stop_by, deadline))
                self.invocation = invocation
                return {"run_id": run, "cgroup": Cgroup.name(decision), "stop_by": stop_by,
                        "manager_verified": True}
            if operation == "arm_scope":
                return self.arm(payload, deadline)
            raise PermissionError("unsupported host operation")

    def checkpoint(self, operation, payload):
        if (set(payload) != {"sequence", "sha256"} or type(payload["sequence"]) is not int
                or payload["sequence"] < 0 or type(payload["sha256"]) is not str
                or not _HEX.fullmatch(payload["sha256"])):
            raise ValueError("invalid authority checkpoint")
        if operation == "authority_checkpoint" and payload["sequence"] == self.head["sequence"] + 1:
            self.journal.append("", "", "", "authority_checkpoint", dict(payload))
            self.head = dict(payload)
        elif self.head != payload:
            raise PermissionError("authority checkpoint differs from independent head")
        return {**payload, "durable": True}

    def arm(self, payload, deadline):
        if set(payload) != {"decision_id", "approval_sha256", "run_id", "cgroup", "stop_by"}:
            raise ValueError("invalid cgroup watchdog request")
        decision, run, digest = (payload[key] for key in ("decision_id", "run_id", "approval_sha256"))
        stop_by = payload["stop_by"]
        if (not _DECISION.fullmatch(decision) or not _RUN.fullmatch(run) or not _HEX.fullmatch(digest)
                or payload["cgroup"] != Cgroup.name(decision) or type(stop_by) not in (float, int)
                or not math.isfinite(stop_by) or not monotonic() < stop_by <= deadline):
            raise PermissionError("invalid watchdog scope")
        packet = _approval(_read(self.records_fd, decision + ".json", 32768, 0))
        self.grants.verify(packet, digest)
        now = datetime.now(timezone.utc)
        if (packet.decision_id != decision or approval_sha256(packet) != digest
                or packet.scope != "b4-predecessor-read-only-v2" or packet.database != "ai_soc_test"
                or packet.endpoint != ("127.0.0.1", 5432) or packet.observed_target != packet.approved_target
                or now < packet.valid_from
                or not 0 < stop_by - monotonic() <= min(packet.budgets.deadline_seconds,
                                                         (packet.expires_at - now).total_seconds())):
            raise PermissionError("watchdog approval mismatch")
        if self.guard is not None or decision in self.used:
            raise PermissionError("watchdog ownership requires independent reconciliation")
        self.journal.append(decision, run, digest, "scope_armed")
        self.guard = decision, run, digest, stop_by
        self.used.add(decision)
        _remaining(stop_by)
        return {"run_id": run, "cgroup": Cgroup.name(decision), "stop_by": stop_by}
