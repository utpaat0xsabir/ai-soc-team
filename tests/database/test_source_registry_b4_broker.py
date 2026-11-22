"""Synthetic broker transcripts. No test opens a socket or starts a worker."""

from dataclasses import asdict
from base64 import b64encode
import json
from pathlib import Path
import runpy
import struct
from time import monotonic

import pytest

from app.database import source_registry_b4_broker as broker
from app.database import source_registry_preflight as worker
from app.database.source_registry_observer_adapter import _wire
from app.database.source_registry_preflight_launcher import Record
from tests.database.test_source_registry_b4_admission import admission_wire
from tests.database.test_source_registry_preflight import scenario, snapshots  # noqa: F401


class Peer:
    uid = 0
    wrong_nonce = False
    response = True
    suffix = b""
    request = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def settimeout(self, timeout):
        assert 0 < timeout <= 5

    def connect(self, path):
        assert path == str(broker.CONTROL_SOCKET)

    def getsockopt(self, level, option, size):
        assert size == struct.calcsize("3i")
        return struct.pack("3i", 1, self.uid, 0)

    def sendall(self, payload):
        self.request = json.loads(payload)

    def recv(self, limit):
        assert limit > 0
        nonce = "wrong" if self.wrong_nonce else self.request["nonce"]
        return json.dumps({"nonce": nonce, "result": self.response}).encode() + b"\n" + self.suffix


@pytest.fixture
def peer(monkeypatch):
    fake = Peer()
    monkeypatch.setattr(broker, "_socket_metadata", lambda path: None)
    monkeypatch.setattr(broker.socket, "socket", lambda *args: fake)
    return fake


def test_root_peer_and_exact_response_binding(peer):
    assert broker.broker_call(broker.CONTROL_SOCKET, "hold", deadline=monotonic() + 5,
                              decision_id="fixture", run_id="b4-" + "a" * 32) is True
    assert peer.request["method"] == "hold"
    assert peer.request["decision_id"] == "fixture"


def test_non_root_peer_rejected_before_sending(peer):
    peer.uid = 136
    with pytest.raises(PermissionError, match="unexpected broker peer"):
        broker.broker_call(broker.CONTROL_SOCKET, "start", deadline=monotonic() + 5)
    assert peer.request is None


@pytest.mark.parametrize("defect", ["nonce", "trailing", "expired", "wrong_socket"])
def test_untrusted_frames_and_routes_fail_closed(peer, defect):
    method = "close_scope"
    deadline = monotonic() + 5
    if defect == "nonce":
        peer.wrong_nonce = True
    if defect == "trailing":
        peer.suffix = b"extra\n"
    if defect == "expired":
        deadline = monotonic()
    if defect == "wrong_socket":
        method = "worker_handoff"
    with pytest.raises((ValueError, TimeoutError)):
        broker.broker_call(broker.CONTROL_SOCKET, method, deadline=deadline)


def test_provider_binds_start_and_reconciliation_to_approval(scenario, monkeypatch):
    provider = object.__new__(broker.BrokerProtectedInputs)
    record = Record(scenario.packet, scenario.inputs["root"], scenario.inputs["application_isolation"],
                    scenario.inputs["ca"], scenario.inputs["freeze"])
    pin = worker.approval_sha256(record.packet)
    run_id = "b4-" + "f" * 32
    requests = []

    def authority(path, method, *, deadline, **fields):
        assert path == broker.CONTROL_SOCKET and deadline > monotonic()
        assert fields["decision_id"] == record.packet.decision_id and fields["approval_sha256"] == pin
        requests.append((method, fields))
        return 0 if method == "wait" else True

    monkeypatch.setattr(broker, "broker_call", authority)
    with pytest.raises(ValueError, match="unbound worker request"):
        provider.start_worker(record, "0" * 64, run_id, deadline=monotonic() + 5)
    assert not requests
    assert provider.hold_freeze(record, run_id, deadline=monotonic() + 5)
    process = provider.start_worker(record, pin, run_id, deadline=monotonic() + 5)
    assert process.wait(1) == 0
    assert provider.close_worker_scope(record, run_id, deadline=monotonic() + 5)
    assert provider.backends_gone(record, run_id, backend_pids=(1, 2), deadline=monotonic() + 5)
    assert provider.release_freeze(record, run_id, deadline=monotonic() + 5)
    assert [item[0] for item in requests] == ["hold", "start", "wait", "close_scope", "backends_gone", "release"]
    assert all(fields["run_id"] == run_id for _, fields in requests)


def test_worker_adapter_uses_only_authenticated_handoff(scenario, monkeypatch, capsys):
    module = runpy.run_path(str(Path(__file__).resolve().parents[2] / "scripts/b4_preflight_bootstrap.py"))
    packet = scenario.packet
    inputs = scenario.inputs
    handoff = {
        "packet": json.loads(json.dumps(asdict(packet), default=_wire)),
        "trusted_digest": inputs["trusted_approval_sha256"],
        "isolation": b64encode(inputs["application_isolation"]).decode(),
        "ca": b64encode(inputs["ca"]).decode(),
        "freeze": b64encode(inputs["freeze"]).decode(),
        "run_id": inputs["run_id"],
        "credentials": inputs["credentials"],
        "admission": admission_wire(packet, inputs["run_id"], inputs["trusted_approval_sha256"], monotonic() + 1),
    }
    calls = []

    def authority(path, method, *, deadline, **fields):
        assert path == broker.WORKER_SOCKET and fields["decision_id"] == packet.decision_id
        calls.append(method)
        if method == "worker_handoff":
            return handoff
        assert fields["report"]["code"] == "QUERY_TIMEOUT"
        assert "secret-value" not in repr(fields)
        return True

    def execute(received, **kwargs):
        assert received == packet
        assert kwargs["credentials"] == inputs["credentials"]
        assert kwargs["trusted_approval_sha256"] == inputs["trusted_approval_sha256"]
        return worker.Report("FAIL", "observer", "QUERY_TIMEOUT")

    monkeypatch.setattr(broker, "broker_call", authority)
    monkeypatch.setattr(worker, "run", execute)
    assert module["_worker"](packet.decision_id, inputs["root"]) == 0
    assert calls == ["worker_handoff", "worker_result"]
    assert capsys.readouterr().out == ""
    handoff["credentials"] = {"unexpected": "secret-value"}
    with pytest.raises(ValueError, match="unbound worker handoff"):
        module["_worker"](packet.decision_id, inputs["root"])


def test_bootstrap_rejects_worker_with_supervisor_uid_or_group(monkeypatch, capsys):
    from types import SimpleNamespace

    module = runpy.run_path(str(Path(__file__).resolve().parents[2] / "scripts/b4_preflight_bootstrap.py"))
    main = module["main"]
    monkeypatch.setitem(main.__globals__, "sys", SimpleNamespace(
        flags=SimpleNamespace(isolated=1), dont_write_bytecode=True, stderr=__import__("sys").stderr,
    ))
    fake_os = SimpleNamespace(environ={}, geteuid=lambda: 136, getegid=lambda: 200, getgroups=lambda: [])
    monkeypatch.setitem(main.__globals__, "os", fake_os)
    monkeypatch.setitem(main.__globals__, "_prepare_imports", lambda _: pytest.fail("worker admitted"))
    assert main(["worker", "test-approval"]) == 1
    fake_os.geteuid = lambda: 200
    fake_os.getgroups = lambda: [147]
    assert main(["worker", "test-approval"]) == 1
    assert capsys.readouterr().err.splitlines() == ["B4_BOOTSTRAP_UNAVAILABLE"] * 2
