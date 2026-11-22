"""Broker tests with fake infrastructure and no network access."""

from base64 import b64encode
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import json
import os
from threading import Barrier, Thread
from time import monotonic

import pytest

from app.database import source_registry_b4_broker_server as server
from app.database.source_registry_preflight import Report, approval_sha256
from tests.database.test_source_registry_b4_admission import admission_wire
from tests.database.test_source_registry_preflight import scenario, snapshots  # noqa: F401


RUN = "b4-" + "1" * 32
CONTROL = server.Peer(21, 136, 147)
WORKER = server.Peer(22, 500, 501)


class Runtime:
    def __init__(self, packet):
        self.packet = packet
        self.sessions = ()
        self.calls = []
        self.target = True
        self.complete = True
        self.unexpected = False

    def approval(self, decision, deadline):
        return self.packet

    def frozen(self, *args):
        return True

    def hold(self, *args):
        self.calls.append("hold")
        return True

    def start(self, *args):
        self.calls.append("start")
        return True

    def worker(self, packet, peer, deadline):
        return peer == WORKER

    def handoff(self, packet, run, deadline):
        fields = asdict(packet)
        for name in ("valid_from", "expires_at"):
            fields[name] = fields[name].isoformat()
        for name in ("observed_target", "approved_target"):
            fields[name]["address_pair"] = list(map(str, fields[name]["address_pair"]))
        material = {name: b64encode(data).decode("ascii") for name, data in (
            ("isolation", b"independent evidence"), ("ca", b"synthetic CA"), ("freeze", b"independent freeze")
        )}
        return dict(packet=fields, trusted_digest=approval_sha256(packet), **material, run_id=run,
                    admission=admission_wire(packet, run, approval_sha256(packet), deadline),
                    credentials={packet.migrator_secret_ref: "<test>", packet.observer_secret_ref: "<test>"})

    def close(self, *args):
        self.calls.append("close")
        return True

    def release(self, *args):
        self.calls.append("release")
        return True

    def status(self, *args):
        return 0

    def observe(self, *args):
        return server.Backends(self.target, self.complete, self.sessions, self.unexpected)

    def inspect(self, *args):
        pin = self.packet.approved_target
        address, gateway = map(str, pin.address_pair)
        return {
            "Id": pin.container_id, "Image": pin.image_id, "Name": "/ai-soc-postgres",
            "Config": {"Image": "postgres:16", "Env": ["secret"]},
            "State": {"Status": "running"},
            "NetworkSettings": {
                "Ports": {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "5432"}]},
                "Networks": {pin.network: {"Gateway": gateway, "IPAddress": address,
                                            "NetworkID": pin.network_id}},
            },
        }


class Grants:
    accepted = True

    def verify(self, *args):
        if not self.accepted:
            raise PermissionError("signature")

    def verify_recovery(self, *args):
        raise PermissionError("recovery not approved")


@pytest.fixture
def broker(scenario, tmp_path):
    packet = scenario.packet
    path = tmp_path / "journal"
    path.mkdir(mode=0o700)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield server.Broker(Grants(), server.Journal(fd, uid=os.getuid()), Runtime(packet)), path
    finally:
        os.close(fd)


def call(broker, method, *, peer=None, **overrides):
    worker = method in server._WORKER
    fields = (server._WORKER if worker else server._CONTROL)[method]
    packet = broker.runtime.packet
    request = dict(method=method, decision_id=packet.decision_id, nonce="a" * 32,
                   deadline=monotonic() + 1)
    if not worker:
        request["approval_sha256"] = approval_sha256(packet)
    if "run_id" in fields:
        request["run_id"] = RUN
    request.update(overrides)
    return broker.dispatch("worker" if worker else "control", peer or (WORKER if worker else CONTROL), request)


@pytest.mark.parametrize("peer", [server.Peer(21, 0, 0), server.Peer(21, 136, 168),
                                server.Peer(21, 456, 147)])
def test_rejects_unauthorized_control_peer(broker, peer):
    instance, _ = broker
    with pytest.raises(PermissionError):
        call(instance, "hold", peer=peer)
    assert not instance.journal.events


@pytest.mark.parametrize("failure", ["signature", "expired", "digest", "extra"])
def test_rejects_bad_approval(broker, failure):
    instance, _ = broker
    args = {}
    if failure == "signature":
        instance.grants.accepted = False
    elif failure == "expired":
        instance.runtime.packet = replace(instance.runtime.packet, expires_at=datetime.now(timezone.utc))
    elif failure == "digest":
        args["approval_sha256"] = "f" * 64
    else:
        args["uid"] = 136
    with pytest.raises((ValueError, PermissionError)):
        call(instance, "hold", **args)
    assert not instance.runtime.calls


def test_concurrent_reservation_and_replay(broker):
    instance, _ = broker
    barrier = Barrier(2)
    outcomes = []

    def claim():
        barrier.wait()
        try:
            outcomes.append(call(instance, "hold"))
        except PermissionError:
            outcomes.append(False)

    workers = [Thread(target=claim) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=2)
    assert sorted(outcomes) == [False, True]
    assert instance.runtime.calls == ["hold"]
    finish(instance)
    with pytest.raises(PermissionError):
        call(instance, "hold")


def finish(instance):
    assert call(instance, "close_scope")
    assert call(instance, "backends_gone", backend_pids=[])
    assert call(instance, "target_matches")
    assert call(instance, "release")


def test_complete_run_and_receipts(broker):
    instance, path = broker
    packet = instance.runtime.packet
    with pytest.raises(PermissionError):
        call(instance, "worker_handoff")
    assert call(instance, "hold")
    assert call(instance, "start")
    with pytest.raises(PermissionError):
        call(instance, "worker_handoff", peer=replace(WORKER, pid=999))
    assert call(instance, "worker_handoff")["run_id"] == RUN
    with pytest.raises(PermissionError):
        call(instance, "worker_handoff")
    instance.runtime.sessions = ((31, packet.migrator_login, RUN), (32, packet.observer_login, RUN))
    report = Report("PASS", "complete", "VERIFIED", (160001, 160001), "d93c6e4fb132", "e" * 64,
                    "MATCH", RUN, (31, 32), approval_sha256(packet))
    assert call(instance, "worker_result", report=asdict(report))
    instance.runtime.sessions = ()
    assert call(instance, "wait") == 0
    assert call(instance, "report")["code"] == "VERIFIED"
    with pytest.raises(PermissionError):
        call(instance, "release")
    finish(instance)
    assert instance.active is None
    assert instance.runtime.calls == ["hold", "start", "close", "release"]
    for index, (event, receipt) in enumerate(instance.journal.events):
        raw = (path / server.Journal.name(index)).read_bytes()
        assert json.loads(raw) == event
        assert server.sha256(raw).hexdigest() == receipt


@pytest.mark.parametrize("failure", ["visibility", "stranger", "target", "timeout"])
def test_monitor_failure_blocks_result(broker, failure):
    instance, _ = broker
    assert call(instance, "hold") and call(instance, "start")
    args = {}
    if failure == "visibility":
        instance.runtime.complete = False
    elif failure == "stranger":
        instance.runtime.sessions = ((31, "unexpected", RUN),)
    elif failure == "target":
        instance.runtime.target = False
    else:
        instance.runtime.status = lambda *args: None
        args["deadline"] = monotonic() + 0.02
    with pytest.raises((PermissionError, TimeoutError)):
        call(instance, "wait", **args)
    assert instance.monitor_failed
    with pytest.raises(PermissionError):
        call(instance, "report")


def test_interrupted_teardown_retains_freeze(broker):
    instance, _ = broker
    assert call(instance, "hold") and call(instance, "start")
    instance.runtime.close = lambda *args: False
    with pytest.raises(PermissionError):
        call(instance, "close_scope")
    with pytest.raises(PermissionError):
        call(instance, "release")
    assert instance.active is not None


def test_crash_state_blocks_new_run_and_requires_recovery(broker):
    instance, path = broker
    assert call(instance, "hold")
    with pytest.raises(BlockingIOError):
        fd = os.open(path, os.O_RDONLY)
        try:
            server.Journal(fd, uid=os.getuid())
        finally:
            os.close(fd)
    server.fcntl.flock(instance.journal.fd, server.fcntl.LOCK_UN)
    restarted = server.Broker(instance.grants, server.Journal(instance.journal.fd, uid=os.getuid()),
                              instance.runtime)
    assert restarted.restarted
    with pytest.raises(PermissionError):
        call(restarted, "start")
    with pytest.raises(PermissionError):
        restarted.recover(decision=instance.runtime.packet.decision_id, run=RUN,
                          expires_at=datetime.now(timezone.utc) + timedelta(seconds=20), deadline=monotonic() + 1)


def test_fsync_failure_poisoned_journal(broker, monkeypatch):
    instance, _ = broker

    def fail(*args):
        raise OSError("disk failure")

    monkeypatch.setattr(server.os, "fsync", fail)
    with pytest.raises(OSError):
        call(instance, "hold")
    assert not instance.runtime.calls
    with pytest.raises(PermissionError):
        call(instance, "hold")


@pytest.mark.parametrize("method,path", [
    ("POST", "/v1.44/containers/ai-soc-postgres/json"),
    ("GET", "/v1.44/containers/other/json"),
    ("GET", "/v1.44/containers/ai-soc-postgres/json?size=1"),
    ("GET", "/v1.44/containers/../ai-soc-postgres/json"),
    ("GET", "/v1.44/networks/bridge"),
])
def test_docker_api_rejects_unapproved_requests(broker, method, path):
    instance, _ = broker
    assert call(instance, "hold") and call(instance, "start")
    assert call(instance, "worker_handoff")
    with pytest.raises(PermissionError):
        server.docker_response(instance, WORKER, method, path, monotonic() + 1)


def test_docker_projection_redacts_and_rejects_drift(broker):
    instance, _ = broker
    assert call(instance, "hold") and call(instance, "start")
    endpoint = "/v1.44/containers/ai-soc-postgres/json"
    with pytest.raises(PermissionError):
        server.docker_response(instance, WORKER, "GET", endpoint, monotonic() + 1)
    assert call(instance, "worker_handoff")
    assert b"secret" not in server.docker_response(instance, WORKER, "GET", endpoint, monotonic() + 1)
    drift = instance.runtime.inspect()
    drift["Id"] = "f" * 64
    instance.runtime.inspect = lambda *args: drift
    with pytest.raises(PermissionError):
        server.docker_response(instance, WORKER, "GET", endpoint, monotonic() + 1)


def test_signed_grant_binds_independent_host_runtime_and_packet(broker, monkeypatch):
    instance, _ = broker
    packet = instance.runtime.packet
    digest = approval_sha256(packet)
    raw = server.canonical({
        "host": "registered-host", "runtime_sha256": "b" * 64,
        "decision_id": packet.decision_id, "approval_sha256": digest,
        "candidate_sha256": packet.candidate_manifest_sha256,
        "scope": packet.scope, "operations": sorted(set(server._CONTROL) | set(server._WORKER) | {"inspect"}),
        "expires_at": packet.expires_at.isoformat(),
    })
    calls = []
    monkeypatch.setattr(server, "_directory", lambda *args, **kwargs: None)
    monkeypatch.setattr(server, "_read", lambda _, name, *args: {
        packet.decision_id + ".grant": raw, packet.decision_id + ".sig": b"signature",
        "reviewer.pem": b"anchor",
    }[name])

    def verify(key, payload, signature):
        calls.append((key, payload, signature))
        return True

    monkeypatch.setattr(server, "_verify_ed25519", verify)
    grant = server.SignedGrants(0, host="registered-host", runtime_sha256="b" * 64)
    grant.verify(packet, digest)
    for host, runtime, approval in (("other", "b" * 64, digest),
                                    ("registered-host", "c" * 64, digest),
                                    ("registered-host", "b" * 64, "d" * 64)):
        wrong = server.SignedGrants(0, host=host, runtime_sha256=runtime)
        with pytest.raises(PermissionError):
            wrong.verify(packet, approval)
    assert calls == [(b"anchor", b"ai-soc-b4-broker-v1\n" + raw, b"signature")]
    monkeypatch.setattr(server, "_verify_ed25519", lambda *args: False)
    with pytest.raises(PermissionError):
        grant.verify(packet, digest)


def test_missing_evidence_receipt_blocks_side_effect(broker, monkeypatch):
    instance, _ = broker
    monkeypatch.setattr(server, "_read", lambda *args: b"mismatched receipt")
    with pytest.raises(ValueError, match="receipt"):
        call(instance, "hold")
    assert instance.journal.failed
    assert instance.runtime.calls == []


def test_handoff_artifact_is_checked_before_delivery(broker, monkeypatch):
    instance, _ = broker
    assert call(instance, "hold") and call(instance, "start")
    data = instance.runtime.handoff(instance.runtime.packet, RUN, monotonic() + 1)
    monkeypatch.setattr(instance.runtime, "handoff", lambda *args: {**data, "ca": "d3Jvbmc="})
    with pytest.raises(PermissionError, match="artifact"):
        call(instance, "worker_handoff")


def test_sticky_unexpected_backend_blocks_teardown_release(broker):
    instance, _ = broker
    assert call(instance, "hold") and call(instance, "start")
    assert call(instance, "close_scope")
    instance.runtime.unexpected = True
    with pytest.raises(PermissionError):
        call(instance, "backends_gone", backend_pids=[])
    with pytest.raises(PermissionError):
        call(instance, "release")
    assert instance.active is not None


def test_failed_worker_report_is_accepted_and_sanitized(broker):
    instance, _ = broker
    assert call(instance, "hold") and call(instance, "start")
    assert call(instance, "worker_handoff")
    report = Report("FAIL", "sensitive payload", "sensitive detail")
    assert call(instance, "worker_result", report=asdict(report))
    assert call(instance, "wait") == 0
    stored = call(instance, "report")
    assert stored["status"] == "FAIL"
    assert "sensitive" not in str(stored)


def test_socket_uses_kernel_identity_and_does_not_echo_rejected_data(broker, monkeypatch):
    instance, _ = broker
    monkeypatch.setattr(server, "_socket_metadata", lambda _: None)

    class Connection:
        sent = None
        closed = False

        def getsockopt(self, level, option, size):
            assert (level, option, size) == (server.socket.SOL_SOCKET, server.socket.SO_PEERCRED,
                                             server.struct.calcsize("3i"))
            return server.struct.pack("3i", 99, 1234, 1234)

        def settimeout(self, timeout):
            assert timeout > 0

        def recv(self, size):
            return b'{"method":"hold","uid":136,"credential":"redact"}\n'

        def sendall(self, data):
            self.sent = data

        def close(self):
            self.closed = True

    connection = Connection()
    instance.handle(server.CONTROL_SOCKET, connection, channel="control")
    assert connection.closed and connection.sent is None
    assert instance.journal.events == []
