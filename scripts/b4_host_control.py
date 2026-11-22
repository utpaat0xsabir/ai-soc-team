#!/usr/bin/env python3
"""Start the narrow root-owned host controller from a frozen installation."""
from contextlib import ExitStack
import errno
import json
import os
from pathlib import Path
import socket
import stat
import sys
from threading import BoundedSemaphore, Thread
from time import sleep

ROOT = Path("/opt/ai-soc-b4-host-control")
CONFIG = Path("/etc/ai-soc-b4/host-control")
STATE = Path("/var/lib/ai-soc-b4-host-control")
SOCKET = Path("/run/ai-soc-b4/host-control.sock")


def main():
    if (not sys.flags.isolated or not sys.dont_write_bytecode or len(sys.argv) != 1
            or os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0) or set(os.getgroups()) - {0}):
        raise PermissionError("isolated root controller required")
    entry = ROOT / "scripts/b4_host_control.py"
    if Path(__file__).absolute() != entry:
        raise PermissionError("unexpected controller entry point")
    for path in (ROOT / "scripts", ROOT / "services/api", ROOT / "services", ROOT, *ROOT.parents):
        info = path.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or not stat.S_ISDIR(info.st_mode):
            raise PermissionError("unsafe controller ancestry")
    info = entry.lstat()
    if info.st_uid != 0 or info.st_mode & 0o022 or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise PermissionError("unsafe controller entry point")
    for path in (ROOT / "services/api").rglob("*"):
        info = path.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or not (
                stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) and info.st_nlink == 1):
            raise PermissionError("unsafe controller runtime")
    sys.path.insert(0, str(ROOT / "services/api"))

    from app.database.source_registry_b4_broker import _socket_metadata
    from app.database.source_registry_b4_broker_server import Journal, SignedGrants
    from app.database.source_registry_b4_host_control import HostController
    from app.database.source_registry_b4_runtime import Cgroup, trusted_path, verify_runtime
    from app.database.source_registry_local_inputs import _DIRECTORY, _directory, _read, _unique

    if (os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1"
            or os.environ.get("LISTEN_FDNAMES") != "host-control"):
        raise PermissionError("controller listener unavailable")
    for name in os.listdir("/proc/self/fd"):
        fd = int(name)
        if fd <= 3:
            continue
        try:
            os.fstat(fd)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
            raise
        raise PermissionError("unexpected inherited descriptor")

    with ExitStack() as stack:
        def private(path):
            trusted_path(path, directory=True)
            fd = os.open(path, _DIRECTORY)
            stack.callback(os.close, fd)
            _directory(fd, 0, private=True)
            return fd

        trusted_path(Path(sys.executable).resolve(strict=True), directory=False)
        config_fd = private(CONFIG)
        config = json.loads(_read(config_fd, "runtime.json", 4096, 0), object_pairs_hook=_unique)
        if set(config) != {"authority_uid", "authority_gid", "host", "runtime_sha256"}:
            raise PermissionError("invalid controller configuration")
        uid, gid = config["authority_uid"], config["authority_gid"]
        if (type(uid) is not int or type(gid) is not int or uid <= 0 or gid <= 0
                or uid == 136 or gid == 147):
            raise PermissionError("invalid authority identity")
        verify_runtime(ROOT, config["runtime_sha256"])

        def authority_peer(peer):
            if (peer.uid, peer.gid) != (uid, gid) or peer.pid <= 0:
                return False
            try:
                return (Path("/proc") / str(peer.pid) / "cgroup").read_text() == (
                    "0::/system.slice/ai-soc-b4-authority.service\n")
            except OSError:
                return False

        os.set_inheritable(3, False)
        listener = stack.enter_context(socket.socket(fileno=3))
        _socket_metadata(SOCKET)
        info = SOCKET.lstat()
        if ((info.st_gid, stat.S_IMODE(info.st_mode)) != (gid, 0o660)
                or listener.family != socket.AF_UNIX or listener.getsockname() != str(SOCKET)
                or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)):
            raise PermissionError("unsafe controller listener")
        grants = SignedGrants(private(CONFIG / "grants"), host=config["host"],
                              runtime_sha256=config["runtime_sha256"])
        controller = HostController(Journal(private(STATE)), grants, Cgroup(),
                                    private(CONFIG / "records"), authority_peer=authority_peer)
        slots = BoundedSemaphore(4)

        def watch():
            while True:
                try:
                    if not controller.tick():
                        raise PermissionError("cgroup teardown unconfirmed")
                except Exception:
                    os._exit(1)
                sleep(0.025)

        def handle(conn):
            try:
                controller.handle(conn)
            finally:
                slots.release()

        if not controller.tick():
            raise PermissionError("restart containment unconfirmed")
        Thread(target=watch, daemon=True).start()
        while True:
            conn, _ = listener.accept()
            if not slots.acquire(blocking=False):
                conn.close()
                continue
            Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.exit("B4_HOST_CONTROL_UNAVAILABLE")
