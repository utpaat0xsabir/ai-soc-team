"""Protected runtime tests. No live services or credentials."""
from pathlib import Path
from time import monotonic
from types import SimpleNamespace

import pytest

from app.database import source_registry_b4_runtime as runtime
from app.database.source_registry_b4_broker_server import Journal, Peer


RUN = "b4-" + "a" * 32


@pytest.fixture
def adapter(monkeypatch):
    monkeypatch.setattr(runtime, "_directory", lambda *args, **kwargs: None)

    class Authority:
        uid, gid = 400, 401
        responses = {}

        def request(self, operation, request, deadline):
            return self.responses[operation]

    authority = Authority()
    adapter = runtime.LinuxInfrastructure(records_fd=7, authority=authority,
                                         cgroup=SimpleNamespace())
    packet = SimpleNamespace(decision_id="approved", migrator_login="migrator", observer_login="observer",
                             budgets=SimpleNamespace(max_sessions=2))
    monkeypatch.setattr(runtime, "approval_sha256", lambda _: "a" * 64)
    authority.responses["hold"] = {"run_id": RUN, "durable": True, "cursor": 4}
    assert adapter.hold(packet, RUN, monotonic() + 1)
    return adapter, authority, packet


def batch(events, through, sessions=None):
    return dict(complete=True, target_matches=True, through=through, events=events,
                sessions=[] if sessions is None else sessions)


def test_short_lived_approved_backend_is_retained(adapter):
    service, authority, packet = adapter
    authority.responses["observe"] = batch([
        [5, "connect", 104, "migrator", RUN], [6, "disconnect", 104, "migrator", RUN],
    ], 6)
    result = service.observe(packet, monotonic() + 1)
    assert result.complete and not result.sessions
    assert result.connected == ((104, "migrator", RUN),)


@pytest.mark.parametrize("corruption", ["gap", "short-lived-other", "truncated", "snapshot", "lost"])
def test_monitor_fault_stays_sticky_and_blocks_release(adapter, corruption):
    service, authority, packet = adapter
    reports = {
        "gap": batch([[6, "connect", 104, "migrator", RUN]], 6),
        "short-lived-other": batch([[5, "connect", 104, "other", RUN],
                                    [6, "disconnect", 104, "other", RUN]], 6),
        "truncated": batch([], 6),
        "snapshot": batch([[5, "connect", 104, "migrator", RUN]], 5),
        "lost": {**batch([], 4), "complete": False},
    }
    authority.responses["observe"] = reports[corruption]
    assert not service.observe(packet, monotonic() + 1).complete
    authority.responses["observe"] = batch([], 4)
    assert service.observe(packet, monotonic() + 1).unexpected_since_hold
    assert not service.release(packet, RUN, monotonic() + 1)


def test_cgroup_peer_requires_exact_scope_and_no_protected_groups(tmp_path):
    (tmp_path / "cgroup.controllers").touch()
    proc = tmp_path / "proc"
    process = proc / "51"
    process.mkdir(parents=True)
    scope = runtime.Cgroup(tmp_path, proc)
    (process / "cgroup").write_text("0::" + scope.name("approved") + "\n")
    status = "Uid: 500 500 500 500\nGid: 501 501 501 501\nGroups: 501\nNoNewPrivs: 1\nCapEff: 0000\nCapBnd: 0000\n"
    (process / "status").write_text(status)
    peer = Peer(51, 500, 501)
    assert scope.member("approved", peer, 400, 401)
    assert not scope.member("other", peer, 400, 401)
    (process / "status").write_text(status.replace("Groups: 501", "Groups: 501 147"))
    assert not scope.member("approved", peer, 400, 401)


def test_teardown_requires_unpopulated_descendants(tmp_path, monkeypatch):
    (tmp_path / "cgroup.controllers").touch()
    scope = runtime.Cgroup(tmp_path)
    path = tmp_path / scope.name("approved").lstrip("/")
    path.mkdir(parents=True)
    (path / "cgroup.kill").touch()
    (path / "cgroup.events").write_text("populated 1\n")
    monkeypatch.setattr(runtime, "_directory", lambda *args: None)
    with pytest.raises(TimeoutError):
        scope.kill_and_empty("approved", monotonic() + 0.04)
    assert (path / "cgroup.kill").read_text() == "1"
    (path / "cgroup.events").write_text("populated 0\n")
    assert scope.kill_and_empty("approved", monotonic() + 1)


def test_unsafe_socket_permissions(monkeypatch):
    monkeypatch.setattr(runtime, "_socket_metadata", lambda _: None)
    fake = SimpleNamespace(lstat=lambda: SimpleNamespace(st_gid=147, st_mode=0o666))
    with pytest.raises(PermissionError):
        runtime.listener_metadata(fake, supervisor=True, worker_gid=402)


def test_extra_inherited_descriptor_is_rejected(monkeypatch):
    monkeypatch.setenv("LISTEN_FDNAMES", "control:worker:docker")
    monkeypatch.setenv("LISTEN_PID", str(runtime.os.getpid()))
    monkeypatch.setenv("LISTEN_FDS", "3")
    monkeypatch.setattr(runtime.os, "listdir", lambda path: ["0", "1", "2", "3", "4", "5", "99"])
    monkeypatch.setattr(runtime.os, "fstat", lambda fd: object())
    with pytest.raises(PermissionError, match="descriptor"):
        runtime.activated_listeners(dict.fromkeys(("control", "worker", "docker")), worker_gid=402)


def test_symlink_ancestry_rejected(tmp_path, monkeypatch):
    original = Path.lstat
    link = tmp_path / "unsafe"
    link.symlink_to(tmp_path, target_is_directory=True)
    def lstat(path):
        metadata = original(path)
        return SimpleNamespace(st_mode=metadata.st_mode & ~0o022, st_uid=0, st_nlink=1)
    monkeypatch.setattr(Path, "lstat", lstat)
    with pytest.raises(PermissionError, match="ancestry"):
        runtime.trusted_path(link / "file", directory=False)


def test_missing_checkpoint_receipt_poisoned_journal(tmp_path):
    import os

    path = tmp_path / "journal"
    path.mkdir(mode=0o700)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        def checkpoint(operation, sequence, digest):
            if operation == "checkpoint":
                raise PermissionError("receipt lost")
        journal = Journal(fd, uid=os.getuid(), checkpoint=checkpoint)
        with pytest.raises(PermissionError):
            journal.append("approval", RUN, "f" * 64, "reserved")
        assert journal.failed
        assert (path / "00000.json").is_file()
    finally:
        os.close(fd)


def test_wrong_kernel_authority_does_not_receive_request(monkeypatch):
    monkeypatch.setattr(runtime, "_socket_metadata", lambda _: None)
    class Endpoint:
        def __fspath__(self):
            return "/not-used"

        def lstat(self):
            return SimpleNamespace(st_gid=401, st_mode=0o660)

    monkeypatch.setattr(runtime, "AUTHORITY", Endpoint())

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def settimeout(self, value):
            assert value > 0

        def connect(self, path):
            assert path == "/not-used"

        def setsockopt(self, level, option, value):
            assert (level, option, value) == (runtime.socket.SOL_SOCKET, runtime.socket.SO_PASSCRED, 1)

        def recvmsg(self, size, ancillary_size):
            credential = runtime.struct.pack("3i", 42, 500, 401)
            return b"B", [(runtime.socket.SOL_SOCKET, runtime.socket.SCM_CREDENTIALS, credential)], 0, None

        def sendall(self, data):
            pytest.fail("unauthorized peer received a request")

    monkeypatch.setattr(runtime.socket, "socket", lambda *args: Connection())
    monkeypatch.setattr(runtime.Peer, "from_socket", lambda _: Peer(1, 0, 0))
    with pytest.raises(PermissionError, match="identity"):
        runtime.Authority(400, 401, endpoint=runtime.AUTHORITY).request("readiness", {}, monotonic() + 1)


def test_start_requires_bound_kernel_scope_and_deadline_receipt(adapter):
    service, authority, packet = adapter
    service.cgroup = runtime.Cgroup
    deadline = monotonic() + 1
    authority.responses["start"] = True
    assert not service.start(packet, RUN, deadline)
    receipt = {"run_id": RUN, "cgroup": runtime.Cgroup.name(packet.decision_id), "stop_by": deadline,
               "deadline_armed": True, "sandbox_verified": True}
    authority.responses["start"] = {**receipt, "stop_by": deadline + 1}
    assert not service.start(packet, RUN, deadline)
    authority.responses["start"] = receipt
    assert service.start(packet, RUN, deadline)


def test_recursive_kill_requires_child_support_but_not_root_file(tmp_path, monkeypatch):
    (tmp_path / "cgroup.controllers").touch()
    scope = runtime.Cgroup(tmp_path)
    path = tmp_path / scope.name("approved").lstrip("/")
    path.mkdir(parents=True)
    (path / "cgroup.type").write_text("domain\n")
    monkeypatch.setattr(runtime, "_directory", lambda *args: None)
    assert not scope.recursive_kill_available("approved")
    kill = path / "cgroup.kill"
    kill.touch()
    assert scope.recursive_kill_available("approved")
    assert kill.read_bytes() == b""
    (path / "cgroup.type").write_text("threaded\n")
    assert not scope.recursive_kill_available("approved")
    assert not (tmp_path / "cgroup.kill").exists()
