"""Offline independent authority state, recovery and evidence tests."""
from datetime import datetime, timedelta, timezone
import os
from time import monotonic
from types import SimpleNamespace

import pytest

from app.database import source_registry_b4_authority as authority
from app.database.source_registry_b4_broker_server import Journal, Peer
from tests.database.test_source_registry_b4_admission import admission_wire

RUN = "b4-" + "a" * 32
PIN = "a" * 64
PEER = Peer(51, 0, 0)


@pytest.fixture
def setup(tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    packet = SimpleNamespace(decision_id="one", database="ai_soc_test", endpoint=("127.0.0.1", 5432),
                             scope="b4-predecessor-read-only-v2", approved_target="pin", observed_target="pin",
                             valid_from=now - timedelta(minutes=1), expires_at=now + timedelta(minutes=1),
                             budgets=SimpleNamespace(deadline_seconds=30, recovery_seconds=10, max_sessions=2),
                             migrator_login="m", observer_login="o")
    packet.approved_target = packet.observed_target = SimpleNamespace(container_id="a" * 64)
    packet.tls_server_identity = "127.0.0.1"
    packet.tls_ca_sha256 = "b" * 64
    packet.freeze_sha256 = "c" * 64
    monkeypatch.setattr(authority, "approval_sha256", lambda _: PIN)
    monkeypatch.setattr(authority, "docker_projection", lambda value, _: value)
    host = SimpleNamespace(approval=lambda *args: packet, ready=lambda _: True, hold=lambda *args: 0,
                           frozen=lambda *args: True, start=lambda *args: True, stop=lambda *args: True,
                           scope_closed=lambda *args: True, release=lambda *args: True, inspect=lambda *args: {},
                           observe=lambda *args: dict(target_matches=True, complete=True, through=0,
                                                      events=[], sessions=[]))
    grants = SimpleNamespace(verify=lambda *args: None, verify_recovery=lambda *args: None)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        local = Journal(fd, uid=os.getuid())
        service = authority.AuthorityService(local, grants, host, broker_peer=lambda peer: peer == PEER)
        host.hold = lambda packet, run, deadline: 0
        host.admission = lambda *args: admission_wire(packet, RUN, PIN, service.deadline)
        yield service, packet
    finally:
        os.close(fd)


def call(service, operation, *, peer=PEER, **fields):
    if operation in authority._FIELDS:
        fields.update(decision_id="one", approval_sha256=PIN)
        if "run_id" in authority._FIELDS[operation]:
            fields.setdefault("run_id", RUN)
        if "cgroup" in authority._FIELDS[operation]:
            fields.setdefault("cgroup", authority.Cgroup.name("one"))
    return service.dispatch(peer, operation, fields, monotonic() + 1)


def test_recovery_after_authority_restart_requires_signature(setup):
    first, _ = setup
    assert call(first, "hold")["durable"]
    second = authority.AuthorityService(first.journal, first.grants, first.host, broker_peer=first.broker_peer)
    with pytest.raises(PermissionError):
        call(second, "stop")
    expiry = (datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat()

    def reject(*args):
        raise PermissionError("invalid signature")

    second.grants.verify_recovery = reject
    with pytest.raises(PermissionError):
        call(second, "recover", expires_at=expiry)
    second.grants.verify_recovery = lambda *args: None
    assert call(second, "recover", expires_at=expiry)["cursor"] == 0
    assert call(second, "stop")
    assert call(second, "scope_closed")
    assert call(second, "release", through=0)
    with pytest.raises(PermissionError):
        call(second, "hold")


def test_freeze_exclusive_and_requires_teardown(setup):
    service, _ = setup
    assert call(service, "hold")
    for operation in ("hold", "release"):
        with pytest.raises(PermissionError):
            call(service, operation, **({"through": 0} if operation == "release" else {}))
    assert call(service, "stop")
    service.host.scope_closed = lambda *args: False
    assert call(service, "scope_closed") is False
    with pytest.raises(PermissionError):
        call(service, "release", through=0)


def test_deadline_must_be_armed_before_start_receipt(setup):
    service, _ = setup
    assert call(service, "hold")
    with pytest.raises(PermissionError):
        call(service, "start", stop_by=monotonic() - 1)
    saw = []
    service.host.start = lambda packet, run, scope, deadline: (saw.append(deadline), True)[1]
    stop_by = monotonic() + 0.4
    assert call(service, "start", stop_by=stop_by)["deadline_armed"]
    assert saw == [stop_by]


def test_checkpoints_block_corruption_and_rollback(setup):
    service, _ = setup
    expected = {"sequence": 1, "sha256": PIN}
    assert call(service, "checkpoint", **expected)["durable"]
    for sequence, digest in ((0, "0" * 64), (1, "b" * 64), (2, PIN)):
        with pytest.raises(PermissionError):
            call(service, "verify_checkpoint", sequence=sequence, sha256=digest)
    with pytest.raises(PermissionError):
        call(service, "checkpoint", peer=Peer(99, 136, 147), **expected)


@pytest.mark.parametrize("events,through", [
    ([[1, "connect", 50, "unknown", RUN], [2, "disconnect", 50, "unknown", RUN]], 2),
    ([[2, "connect", 50, "m", RUN]], 2),
    ([], 1),
])
def test_monitor_loss_or_short_lived_unapproved_session_blocks_release(setup, events, through):
    service, _ = setup
    assert call(service, "hold")
    assert call(service, "stop") and call(service, "scope_closed")
    service.host.observe = lambda *args: dict(target_matches=True, complete=True, through=through,
                                              events=events, sessions=[])
    with pytest.raises(PermissionError, match="monitoring"):
        call(service, "release", through=through)
    service.host.observe = lambda *args: dict(target_matches=True, complete=True, through=0,
                                              events=[], sessions=[])
    with pytest.raises(PermissionError, match="monitoring"):
        call(service, "release", through=0)
    assert service.active is not None


def test_missing_admission_reserves_decision_without_start(setup):
    service, _ = setup
    service.host.admission = lambda *_: None
    with pytest.raises(PermissionError, match="missing admission"):
        call(service, "hold")
    assert service.active is not None
    assert "started" not in service._events()


def test_admission_drift_cannot_be_cleared_by_later_matching_proof(setup):
    service, _ = setup
    call(service, "hold")
    normal = service.host.admission
    service.host.admission = lambda *args: {**normal(*args), "policy_sha256": "9" * 64}
    with pytest.raises(PermissionError, match="drift"):
        call(service, "start", stop_by=monotonic() + 0.4)
    service.host.admission = normal
    assert call(service, "stop") and call(service, "scope_closed")
    with pytest.raises(PermissionError, match="reconciliation"):
        call(service, "release", through=0)


def test_deadline_receipt_loss_denies_handoff_and_release(setup):
    service, _ = setup
    call(service, "hold")
    assert call(service, "start", stop_by=monotonic() + 0.4)
    service.host.deadline_armed = lambda *args: False
    with pytest.raises(PermissionError, match="service-manager deadline"):
        call(service, "handoff")
    assert call(service, "stop") and call(service, "scope_closed")
    with pytest.raises(PermissionError, match="reconciliation"):
        call(service, "release", through=0)


def test_freeze_loss_blocks_release_even_when_host_recovers(setup):
    service, _ = setup
    call(service, "hold")
    service.host.frozen = lambda *_: False
    with pytest.raises(PermissionError, match="freeze"):
        call(service, "start", stop_by=monotonic() + 0.4)
    service.host.frozen = lambda *_: True
    assert call(service, "stop") and call(service, "scope_closed")
    with pytest.raises(PermissionError, match="reconciliation"):
        call(service, "release", through=0)
