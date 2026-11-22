"""Trusted B4 orchestration. Protected providers must be provisioned independently."""

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
from subprocess import TimeoutExpired
from time import monotonic
from typing import TYPE_CHECKING, Protocol
from uuid import uuid4

if TYPE_CHECKING:
    from app.database.source_registry_preflight import Approval, Report


@dataclass(frozen=True)
class Record:
    packet: "Approval"
    root: Path
    isolation: bytes
    ca: bytes
    freeze: bytes


@dataclass(frozen=True)
class Outcome:
    code: str
    run_id: str | None = None
    worker_code: str | None = None
    teardown: str = "NOT_ATTEMPTED"
    target_recheck: str = "NOT_ATTEMPTED"
    containment: str = "NOT_ATTEMPTED"
    freeze: str = "NOT_ATTEMPTED"
    evidence_sha256: str | None = None
    evidence_storage: str = "NOT_ATTEMPTED"
    evidence_receipt_sha256: str | None = None


class WorkerHandle(Protocol):
    def wait(self, timeout: float) -> int: ...


class ProtectedInputs(Protocol):
    """Trusted bootstrap authenticates this provider before invoking launch."""

    def load(self, decision_id: str) -> Record:
        """Return the stored packet and corresponding evidence artifacts."""

    def approval_pin(self, decision_id: str) -> str:
        """Read the authenticated pin from a separately protected approval channel."""

    def execution_is_frozen(self, record: Record, *, deadline: float) -> bool:
        """Verify immutable worker, executable environment and approved source snapshot."""

    def recovery_authorized(self, record: Record, *, until: float) -> bool:
        """Verify separate recovery authority through this monotonic deadline, including after expiry."""

    def evidence_ready(self, record: Record, *, deadline: float) -> bool:
        """Verify authorization and availability of the protected append-only sink."""

    def store_evidence(self, record: Record, run_id: str, payload: bytes, *, deadline: float) -> str:
        """Persist the exact observation bytes durably and return their SHA-256 on authenticated transport."""

    def hold_freeze(self, record: Record, run_id: str, *, deadline: float) -> bool:
        """Durably hold the authenticated freeze and register closed-by-default containment.

        The hold must survive exceptions and process loss until explicitly released.
        """

    def start_worker(self, record: Record, trusted_digest: str, run_id: str, *, deadline: float) -> WorkerHandle:
        """Start only within the pre-registered run scope, even on partial startup failure."""

    def read_result(self, process: WorkerHandle, *, deadline: float) -> "Report":
        """Read bounded structured worker result, without raw diagnostics."""

    def close_worker_scope(self, record: Record, run_id: str, *, deadline: float) -> bool:
        """Revoke admission, terminate remaining processes, and confirm the entire scope is empty."""

    def release_freeze(self, record: Record, run_id: str, *, deadline: float) -> bool:
        """Release the durable hold only after containment, backend and target reconciliation."""

    def backends_gone(self, record: Record, run_id: str, *, backend_pids: tuple[int, ...], deadline: float) -> bool:
        """Independently reconcile the run tag and both login identities on the pinned server."""

    def target_matches(self, record: Record, *, deadline: float) -> bool:
        """Independently recheck Docker even if the worker never returned."""


def reserve_once(directory: Path, decision_id: str, run_id: str) -> bool:
    """Consume a decision before launch. A crash never releases a reservation."""
    if (not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", decision_id)
            or not re.fullmatch(r"b4-[0-9a-f]{32}", run_id)):
        raise ValueError("invalid reservation identity")
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        state = os.fstat(parent)
        if state.st_uid != os.geteuid() or stat.S_IMODE(state.st_mode) != 0o700:
            raise PermissionError("unprotected replay directory")
        try:
            marker = os.open(decision_id, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY | os.O_CLOEXEC,
                             0o600, dir_fd=parent)
        except FileExistsError:
            return False
        try:
            tag = (run_id + "\n").encode("ascii")
            if os.write(marker, tag) != len(tag):
                raise OSError("short reservation write")
            os.fsync(marker)
            os.fsync(parent)
        finally:
            os.close(marker)
        return True
    finally:
        os.close(parent)


_FAILURE_CODES = frozenset("""
AMBIENT_CONFIGURATION APPROVAL_EXPIRED APPROVAL_REQUIRED ARTIFACT_MISMATCH
BUDGET_NOT_APPROVED CLOSE_FAILED CONNECTION_NOT_INDEPENDENTLY_AUTHENTICATED
CREDENTIAL_TARGET_MISMATCH DATABASE_PRIVILEGE_BOUNDARY DEADLINE_UNAVAILABLE
DEFAULT_PRIVILEGES_MISMATCH DOCKER_IDENTITY_MISMATCH DOCKER_RECHECK_UNVERIFIED
FREEZE_EVIDENCE_MISMATCH IDENTITIES_NOT_APPROVED INCONSISTENT_OBSERVATIONS
INCONSISTENT_SNAPSHOT ISOLATION_MISMATCH MANIFEST_MISMATCH MIGRATOR_SECURITY_MISMATCH
MISSING_CONTAINER_PIN POSTGRES_VERSION_MISMATCH PREFLIGHT_DEADLINE PREFLIGHT_FAILED
QUERY_FAILED QUERY_INVENTORY_MISMATCH QUERY_RESULT_SHAPE_MISMATCH QUERY_ROW_LIMIT
QUERY_TIMEOUT ROLLBACK_FAILED RUN_ID_REQUIRED SECURITY_STATE_UNVERIFIED
SESSION_IDENTITY_MISMATCH TARGET_NOT_APPROVED TIMEOUT_SETTINGS_MISMATCH TLS_CA_INVALID
TLS_CA_MISMATCH TRANSACTION_LOST TRANSACTION_SETTINGS_MISMATCH UNAPPROVED_OBSERVATION_POLICY
UNAPPROVED_QUERY UNAPPROVED_QUERY_TIMEOUT
""".split())


def _window_open(record: Record, deadline: float) -> bool:
    return monotonic() < deadline and datetime.now(timezone.utc) < record.packet.expires_at


def launch(decision_id: str, *, provider: ProtectedInputs | None, replay_directory: Path | None) -> Outcome:
    """Coordinate one protected decision. Trusted provider methods must honor their deadlines."""
    if provider is None or replay_directory is None:
        return Outcome("TRUST_INPUTS_UNAVAILABLE")
    outcome = Outcome("APPROVAL_UNAVAILABLE")
    try:
        if type(decision_id) is not str or not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", decision_id):
            return outcome
        record = provider.load(decision_id)
        if type(record) is not Record or record.packet.decision_id != decision_id:
            return outcome
        budget = record.packet.budgets.deadline_seconds
        if type(budget) is not int or not 0 < budget <= 3600:
            return Outcome("BUDGET_NOT_APPROVED")
        started = monotonic()
        lifetime = (record.packet.expires_at - datetime.now(timezone.utc)).total_seconds()
        deadline = started + min(budget, lifetime)
        if not _window_open(record, deadline):
            return outcome
        if provider.execution_is_frozen(record, deadline=deadline) is not True:
            return Outcome("EXECUTABLE_NOT_FROZEN")

        from app.database import source_registry_preflight as worker

        trusted_digest = provider.approval_pin(decision_id)
        worker._validate(record.packet, trusted_digest, record.root, record.isolation,
                         record.ca, record.freeze)
        recovery_seconds = record.packet.budgets.recovery_seconds
        outcome = Outcome("RECOVERY_AUTHORITY_UNVERIFIED")
        if provider.recovery_authorized(record, until=deadline + recovery_seconds) is not True:
            return outcome
        if not _window_open(record, deadline):
            return Outcome("APPROVAL_WINDOW_CLOSED")
        outcome = Outcome("EVIDENCE_STORAGE_UNAVAILABLE")
        if provider.evidence_ready(record, deadline=deadline) is not True:
            return outcome
        if not _window_open(record, deadline):
            return Outcome("APPROVAL_WINDOW_CLOSED")
        outcome = Outcome("REPLAY_STORE_UNAVAILABLE")
        run_id = "b4-" + uuid4().hex
        if not reserve_once(replay_directory, decision_id, run_id):
            return Outcome("DECISION_ALREADY_USED")
        if not _window_open(record, deadline):
            return Outcome("APPROVAL_WINDOW_CLOSED", run_id)
        outcome = Outcome("FREEZE_UNVERIFIED", run_id, freeze="UNCONFIRMED")
        if provider.hold_freeze(record, run_id, deadline=deadline) is not True:
            return outcome
        outcome = Outcome("RECOVERY_UNCONFIRMED", run_id, freeze="HELD")
        outcome = _run_worker(provider, record, trusted_digest, run_id, deadline, recovery_seconds)
        return _store_observation(provider, record, trusted_digest, outcome, deadline, recovery_seconds)
    except Exception:
        if outcome.code == "VERIFIED":
            return replace(outcome, code="EVIDENCE_STORAGE_UNCONFIRMED", evidence_sha256=None,
                           evidence_storage="UNCONFIRMED")
        return outcome


def _worker_result(report, trusted_digest, run_id):
    from app.database.source_registry_preflight import Report
    from app.database.migration_guard import BASELINE
    from app.database.source_registry_observer import Failure

    if type(report) is not Report or type(report.code) is not str:
        return "INVALID_REPORT", ()
    if report.status == "FAIL":
        allowed = _FAILURE_CODES | {failure.value for failure in Failure}
        return (report.code if report.code in allowed else "FAILED"), ()
    pids = report.backend_pids
    versions = report.versions
    if (report.status == "PASS" and report.code == "VERIFIED" and report.stage == "complete"
            and report.target_recheck == "MATCH" and report.run_id == run_id
            and report.approval_sha256 == trusted_digest and report.predecessor == BASELINE
            and type(report.evidence_sha256) is str and re.fullmatch(r"[0-9a-f]{64}", report.evidence_sha256)
            and type(versions) is tuple and len(versions) == 2 and versions[0] == versions[1]
            and all(type(version) is int and version // 10000 == 16 for version in versions)
            and type(pids) is tuple and len(pids) == 2 and pids[0] != pids[1]
            and all(type(pid) is int and pid > 0 for pid in pids)):
        return "VERIFIED", pids
    return "INVALID_REPORT", ()


def _run_worker(provider, record, trusted_digest, run_id, deadline, recovery_seconds):
    code = "WORKER_FAILED"
    worker_code = None
    backend_pids = ()
    digest = None
    try:
        if _window_open(record, deadline):
            process = provider.start_worker(record, trusted_digest, run_id, deadline=deadline)
            if process.wait(timeout=max(0, deadline - monotonic())) == 0 and _window_open(record, deadline):
                report = provider.read_result(process, deadline=deadline)
                worker_code, backend_pids = _worker_result(report, trusted_digest, run_id)
                if worker_code == "VERIFIED":
                    code = "VERIFIED"
                    digest = report.evidence_sha256
        else:
            code = "APPROVAL_WINDOW_CLOSED"
    except TimeoutExpired:
        code = "HARD_DEADLINE"
    except Exception:
        pass
    finally:
        if monotonic() >= deadline and code != "APPROVAL_WINDOW_CLOSED":
            code = "HARD_DEADLINE"
        recovery = min(monotonic() + recovery_seconds, deadline + recovery_seconds)
        containment = teardown = target = "UNCONFIRMED"
        freeze = "HELD"
        try:
            if monotonic() < recovery and provider.close_worker_scope(record, run_id, deadline=recovery) is True:
                if monotonic() < recovery:
                    containment = "CONFIRMED"
        except Exception:
            pass
        try:
            if containment == "CONFIRMED" and monotonic() < recovery:
                if provider.backends_gone(record, run_id, backend_pids=backend_pids, deadline=recovery) is True:
                    if monotonic() < recovery:
                        teardown = "CONFIRMED"
        except Exception:
            pass
        try:
            if monotonic() < recovery and provider.target_matches(record, deadline=recovery) is True:
                if monotonic() < recovery:
                    target = "MATCH"
        except Exception:
            pass
        if (containment, teardown, target) == ("CONFIRMED", "CONFIRMED", "MATCH") and monotonic() < recovery:
            # Release may succeed before its response is lost. Do not claim that the hold remains.
            freeze = "UNCONFIRMED"
            try:
                if provider.release_freeze(record, run_id, deadline=recovery) is True and monotonic() < recovery:
                    freeze = "RELEASED"
            except Exception:
                pass
    if code == "VERIFIED":
        if not _window_open(record, deadline):
            code = "APPROVAL_WINDOW_CLOSED"
        elif freeze != "RELEASED":
            code = "POSTFLIGHT_UNVERIFIED"
    return Outcome(code, run_id, worker_code, teardown, target, containment, freeze,
                   digest if code == "VERIFIED" else None)


def _store_observation(provider, record, trusted_digest, outcome, deadline, recovery_seconds):
    # Success evidence must be acknowledged within the approval window.
    # Failed attempts may use the separately approved recovery window.
    verified = outcome.code == "VERIFIED"
    limit = deadline if verified else deadline + recovery_seconds
    payload = json.dumps({
        "schema": "b4-preflight-observation-v1",
        "decision_id": record.packet.decision_id,
        "run_id": outcome.run_id,
        "approval_sha256": trusted_digest,
        "manifest_sha256": record.packet.approved_manifest_sha256,
        "observer_inventory_sha256": record.packet.observer_inventory_sha256,
        "supplemental_inventory_sha256": record.packet.supplemental_inventory_sha256,
        "observation_code": outcome.code,
        "worker_code": outcome.worker_code,
        "teardown": outcome.teardown,
        "target_recheck": outcome.target_recheck,
        "containment": outcome.containment,
        "freeze": outcome.freeze,
        "evidence_sha256": outcome.evidence_sha256,
    }, sort_keys=True, separators=(",", ":")).encode("ascii")
    expected = sha256(payload).hexdigest()
    receipt = None
    try:
        if monotonic() < limit and (not verified or _window_open(record, deadline)):
            reply = provider.store_evidence(record, outcome.run_id, payload, deadline=limit)
            if type(reply) is str and reply == expected and monotonic() < limit:
                receipt = expected
    except Exception:
        pass
    if verified and not _window_open(record, deadline):
        outcome = replace(outcome, code="APPROVAL_WINDOW_CLOSED", evidence_sha256=None)
    elif verified and receipt is None:
        outcome = replace(outcome, code="EVIDENCE_STORAGE_UNCONFIRMED", evidence_sha256=None)
    return replace(outcome, evidence_storage="CONFIRMED" if receipt else "UNCONFIRMED",
                   evidence_receipt_sha256=receipt)
