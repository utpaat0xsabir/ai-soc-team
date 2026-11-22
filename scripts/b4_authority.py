#!/usr/bin/env python3
"""Start the separately provisioned B4 authority from a frozen runtime."""
from contextlib import ExitStack
import errno
import json
import os
from pathlib import Path
import socket
import stat
import sys
from time import monotonic

# Local modules are loaded exclusively from the protected deployed inventory.
ROOT = Path("/opt/ai-soc-b4-authority")
CONFIG = Path("/etc/ai-soc-b4-authority")
STATE = Path("/var/lib/ai-soc-b4-authority")
RUNTIME = Path("/run/ai-soc-b4")


def protected(path, directory=False):
    for parent in reversed(path.parents):
        item = parent.lstat()
        if not stat.S_ISDIR(item.st_mode) or item.st_uid != 0 or item.st_mode & 0o022:
            raise PermissionError("unsafe authority ancestry")
    item = path.lstat()
    if item.st_uid != 0 or item.st_mode & 0o022 or not (
            stat.S_ISDIR(item.st_mode) if directory else stat.S_ISREG(item.st_mode) and item.st_nlink == 1):
        raise PermissionError("unsafe authority file")


def broker_peer(peer):
    if peer.pid <= 0 or (peer.uid, peer.gid) != (0, 0):
        return False
    try:
        membership = (Path("/proc") / str(peer.pid) / "cgroup").read_text()
    except OSError:
        return False
    return membership in {
        "0::/system.slice/ai-soc-b4-broker.service\n",
        "0::/system.slice/ai-soc-b4-recover.service\n",
    }


def main():
    if not sys.flags.isolated or not sys.dont_write_bytecode or len(sys.argv) != 1:
        raise PermissionError("isolated authority invocation required")
    protected(Path(sys.executable).resolve(strict=True))
    protected(Path(__file__).absolute())
    protected(ROOT / "services/api/app", directory=True)
    for path in (ROOT / "services/api/app").rglob("*.py"):
        protected(path)
    sys.path.insert(0, str(ROOT / "services/api"))

    from app.database.source_registry_b4_authority import AuthorityService, LinuxHost
    from app.database.source_registry_b4_broker import _socket_metadata
    from app.database.source_registry_b4_broker_server import Journal, SignedGrants
    from app.database.source_registry_b4_runtime import Authority, Cgroup, verify_runtime
    from app.database.source_registry_local_inputs import _DIRECTORY, _read, _unique

    # Inspect inherited descriptors before opening private files.
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
        raise PermissionError("unexpected inherited authority descriptor")

    with ExitStack() as stack:
        def directory(path):
            descriptor = os.open(path, _DIRECTORY)
            stack.callback(os.close, descriptor)
            return descriptor

        protected(CONFIG, directory=True)
        config = json.loads(_read(directory(CONFIG), "runtime.json", 4096, 0), object_pairs_hook=_unique)
        if set(config) != {"uid", "gid", "host_uid", "host_gid", "host", "runtime_sha256"}:
            raise PermissionError("authority configuration invalid")
        uid, gid = config["uid"], config["gid"]
        if (uid in (0, 136, config["host_uid"]) or gid in (0, 147, config["host_gid"])
                or os.getresuid() != (uid, uid, uid) or os.getresgid() != (gid, gid, gid)
                or set(os.getgroups()) - {gid, config["host_gid"]}):
            raise PermissionError("authority identity invalid")
        verify_runtime(ROOT, config["runtime_sha256"])
        if (os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1"
                or os.environ.get("LISTEN_FDNAMES") != "authority"):
            raise PermissionError("authority listener unavailable")
        os.set_inheritable(3, False)
        listener = stack.enter_context(socket.socket(fileno=3))
        path = RUNTIME / "authority.sock"
        _socket_metadata(path)
        info = path.lstat()
        if ((info.st_gid, stat.S_IMODE(info.st_mode)) != (gid, 0o660) or listener.family != socket.AF_UNIX
                or listener.getsockname() != str(path) or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)):
            raise PermissionError("unexpected authority socket")
        protected(CONFIG / "grants", directory=True)
        grants = SignedGrants(directory(CONFIG / "grants"), host=config["host"],
                              runtime_sha256=config["runtime_sha256"], private=False)
        protected(CONFIG / "records", directory=True)
        host = LinuxHost(directory(CONFIG / "records"), Cgroup(),
                         Authority(config["host_uid"], config["host_gid"], endpoint=RUNTIME / "host-control.sock",
                                   root_controller=(config["host_uid"], config["host_gid"]) == (0, 0)))
        def checkpoint(operation, sequence, digest):
            operation = {"checkpoint": "authority_checkpoint",
                         "verify_checkpoint": "verify_authority_checkpoint"}[operation]
            payload = dict(sequence=sequence, sha256=digest)
            receipt = host.control.request(operation, payload, monotonic() + 2)
            if receipt != {**payload, "durable": True}:
                raise PermissionError("controller checkpoint verification failed")

        service = AuthorityService(Journal(directory(STATE), uid=uid, checkpoint=checkpoint), grants, host,
                                   broker_peer=broker_peer)
        while True:
            conn, _ = listener.accept()
            service.handle(conn)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.exit("B4_AUTHORITY_UNAVAILABLE")
