"""Test the controller's durable watchdog and independent evidence anchor offline."""
from datetime import datetime, timedelta, timezone
import os
from time import monotonic
from types import SimpleNamespace

import pytest

from app.database import source_registry_b4_host_control as host
from app.database.source_registry_b4_broker_server import Journal, Peer

PEER = Peer(20, 400, 401)
RUN = "b4-" + "a" * 32
DIGEST = "a" * 64


@pytest.fixture
def controller(tmp_path, monkeypatch):
    path = tmp_path / "journal"
    path.mkdir(mode=0o700)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    wall = datetime.now(timezone.utc)
    packet = SimpleNamespace(decision_id="reviewed", scope="b4-predecessor-read-only-v2",
                             database="ai_soc_test", endpoint=("127.0.0.1", 5432),
                             observed_target=1, approved_target=1, expires_at=wall + timedelta(minutes=1),
                             valid_from=wall - timedelta(minutes=1), budgets=SimpleNamespace(deadline_seconds=30))
    monkeypatch.setattr(host, "approval_sha256", lambda _: DIGEST)
    monkeypatch.setattr(host, "_read", lambda *_: b"fixture")
    monkeypatch.setattr(host, "_approval", lambda _: packet)
    grants = SimpleNamespace(verify=lambda *_: None)
    calls = []
    cgroup = SimpleNamespace(kill_and_empty=lambda decision, deadline: (calls.append(decision), True)[1])
    try:
        service = host.HostController(Journal(fd, uid=os.getuid()), grants, cgroup, 90,
                                      authority_peer=lambda peer: peer == PEER)
        yield service, calls
    finally:
        os.close(fd)


def arm(service, deadline):
    return service.dispatch(PEER, "arm_scope", dict(
        decision_id="reviewed", approval_sha256=DIGEST, run_id=RUN,
        cgroup=host.Cgroup.name("reviewed"), stop_by=deadline), deadline)


def restart(service):
    return host.HostController(service.journal, service.grants, service.cgroup,
                               service.records_fd, authority_peer=service.broker_peer)


def test_expired_original_scope_stops_without_broker(controller, monkeypatch):
    service, killed = controller
    deadline = monotonic() + 1
    assert arm(service, deadline)["stop_by"] == deadline
    assert service.tick() and not killed
    monkeypatch.setattr(host, "monotonic", lambda: deadline)
    assert service.tick() and killed == ["reviewed"]


def test_restart_terminates_exact_armed_scope_and_rejects_reuse(controller):
    service, killed = controller
    deadline = monotonic() + 1
    arm(service, deadline)
    recovered = restart(service)
    assert recovered.tick() and killed == ["reviewed"]
    with pytest.raises(PermissionError):
        arm(recovered, deadline)


def test_incomplete_teardown_is_not_confirmed(controller):
    service, _ = controller
    arm(service, monotonic() + 1)
    recovered = restart(service)
    recovered.cgroup.kill_and_empty = lambda *args: False
    assert recovered.tick() is False


def test_unapproved_grant_cannot_arm(controller):
    service, _ = controller

    def denied(*args):
        raise PermissionError("invalid grant")

    service.grants.verify = denied
    with pytest.raises(PermissionError, match="grant"):
        arm(service, monotonic() + 1)
    assert service.journal.events == []


def test_checkpoint_custody_rejects_corruption_rollback_and_other_writer(controller):
    service, _ = controller
    head = dict(sequence=1, sha256=DIGEST)
    deadline = monotonic() + 1
    with pytest.raises(PermissionError):
        service.dispatch(Peer(21, 136, 147), "authority_checkpoint", head, deadline)
    assert service.dispatch(PEER, "authority_checkpoint", head, deadline)["durable"]
    recovered = restart(service)
    assert recovered.dispatch(PEER, "verify_authority_checkpoint", head, deadline)["durable"]
    for malformed in (dict(sequence=0, sha256="0" * 64), dict(sequence=1, sha256="b" * 64)):
        with pytest.raises(PermissionError):
            recovered.dispatch(PEER, "verify_authority_checkpoint", malformed, deadline)
    assert recovered.dispatch(PEER, "readiness", {}, deadline) is False


def test_authority_fails_closed_if_crash_leaves_unanchored_tail(controller, tmp_path):
    service, _ = controller
    path = tmp_path / "authority"
    path.mkdir(mode=0o700)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)

    def checkpoint(operation, sequence, digest):
        scope = {"checkpoint": "authority_checkpoint", "verify_checkpoint": "verify_authority_checkpoint"}
        service.dispatch(PEER, scope[operation], dict(sequence=sequence, sha256=digest), monotonic() + 1)

    try:
        journal = Journal(fd, uid=os.getuid(), checkpoint=checkpoint)
        journal.append("reviewed", RUN, DIGEST, "reserve")
        assert restart(service).head == {"sequence": 1, "sha256": journal.previous}

        def crash(*args):
            raise OSError("independent receipt not durable")

        journal.checkpoint = crash
        with pytest.raises(OSError):
            journal.append("reviewed", RUN, DIGEST, "held")
        with pytest.raises(PermissionError, match="independent head"):
            Journal(fd, uid=os.getuid(), checkpoint=checkpoint)
    finally:
        os.close(fd)


@pytest.mark.parametrize("failure", ["child unavailable", "manager unavailable", "new invocation", "controller restart"])
def test_deadline_receipt_requires_stable_manager_and_recursive_scope(controller, monkeypatch, failure):
    service, _ = controller
    stop_by = monotonic() + 5
    arm(service, stop_by)
    payload = dict(decision_id="reviewed", approval_sha256=DIGEST, run_id=RUN, stop_by=stop_by)

    def verify():
        return service.dispatch(PEER, "service_deadline", payload, monotonic() + 1)

    service.cgroup.recursive_kill_available = lambda _: True
    monkeypatch.setattr(host, "manager_deadline", lambda *args: ("249", "1", "a" * 32, "123"))
    assert verify()["manager_verified"]
    if failure == "child unavailable":
        service.cgroup.recursive_kill_available = lambda _: False
    elif failure == "manager unavailable":
        monkeypatch.setattr(host, "manager_deadline", lambda *args: None)
    elif failure == "new invocation":
        monkeypatch.setattr(host, "manager_deadline", lambda *args: ("249", "1", "b" * 32, "124"))
    else:
        service = restart(service)
    with pytest.raises(PermissionError):
        verify()
    assert service.guard is not None
