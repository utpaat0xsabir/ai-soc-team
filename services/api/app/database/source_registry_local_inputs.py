"""Local protected storage for B4. Deployment supplies the live provider operations."""

from abc import ABC, abstractmethod
from base64 import b64decode
from contextlib import ExitStack
from datetime import datetime
from hashlib import sha256
from ipaddress import IPv4Address
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from time import monotonic

from app.database.source_registry_preflight import Approval, Budgets, DockerPin
from app.database.source_registry_preflight_launcher import Record


_ROOT_UID = 0
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_DECISION = re.compile(r"[a-zA-Z0-9_-]{1,128}")
_RUN = re.compile(r"b4-[0-9a-f]{32}")
_HEX = re.compile(r"[0-9a-f]{64}")
_OPENSSL = "/usr/bin/openssl"


def _directory(fd, uid, *, private=False):
    info = os.fstat(fd)
    mode = stat.S_IMODE(info.st_mode)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or mode & 0o022
            or (private and mode != 0o700)):
        raise ValueError("unsafe protected directory")


def _read_fd(source, maximum, uid, *, private=False):
    info = os.fstat(source)
    mode = stat.S_IMODE(info.st_mode)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1
            or mode & 0o022 or (private and mode != 0o600)
            or not 0 < info.st_size <= maximum):
        raise ValueError("unsafe protected file")
    with os.fdopen(source, "rb", closefd=False) as stream:
        value = stream.read(maximum + 1)
    if len(value) != info.st_size:
        raise ValueError("unstable protected file")
    return value


def _read(fd, name, maximum, uid):
    source = os.open(name, _READ, dir_fd=fd)
    try:
        return _read_fd(source, maximum, uid)
    finally:
        os.close(source)


def _unique(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate approval field")
    return result


def _approval(raw):
    fields = json.loads(raw, object_pairs_hook=_unique)
    for name in ("observed_target", "approved_target"):
        target = fields[name]
        target["address_pair"] = tuple(IPv4Address(ip) for ip in target["address_pair"])
        fields[name] = DockerPin(**target)
    for name in ("valid_from", "expires_at"):
        fields[name] = datetime.fromisoformat(fields[name])
        if fields[name].utcoffset() is None:
            raise ValueError("invalid approval timezone")
    fields["endpoint"] = tuple(fields["endpoint"])
    fields["predecessor_queries"] = tuple(fields["predecessor_queries"])
    fields["budgets"] = Budgets(**fields["budgets"])
    return Approval(**fields)


def _verify_ed25519(public_key, payload, signature):
    lines = public_key.splitlines()
    if (len(signature) != 64 or len(lines) != 3
            or lines[0] != b"-----BEGIN PUBLIC KEY-----" or lines[2] != b"-----END PUBLIC KEY-----"):
        return False
    try:
        der = b64decode(lines[1], validate=True)
    except ValueError:
        return False
    if len(der) != 44 or not der.startswith(bytes.fromhex("302a300506032b6570032100")):
        return False
    with ExitStack() as cleanup:
        descriptors = []
        for data in (public_key, payload, signature):
            fd = os.memfd_create("b4-public-verification", os.MFD_CLOEXEC)
            cleanup.callback(os.close, fd)
            if os.write(fd, data) != len(data):
                raise OSError("short verification write")
            os.lseek(fd, 0, os.SEEK_SET)
            descriptors.append(fd)
        key, message, sig = (f"/proc/self/fd/{fd}" for fd in descriptors)
        result = subprocess.run(
            [_OPENSSL, "pkeyutl", "-verify", "-pubin", "-inkey", key, "-rawin",
             "-in", message, "-sigfile", sig],
            pass_fds=tuple(descriptors), env={"OPENSSL_CONF": "/dev/null"},
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=3, check=False,
        )
        return result.returncode == 0


class LocalProtectedInputs(ABC):
    """Storage implementation for a bootstrap with independently verified directory FDs.

    The bootstrap owns their lifetime, protected ancestry, runtime integrity,
    revocation policy, and the separately authorized live operations.
    """

    def __init__(self, *, records_fd: int, pins_fd: int, evidence_fd: int, root: Path):
        for fd in (records_fd, pins_fd):
            _directory(fd, _ROOT_UID)
        _directory(evidence_fd, os.geteuid(), private=True)
        if os.path.samestat(os.fstat(records_fd), os.fstat(pins_fd)):
            raise ValueError("approval and independent pin stores must be distinct")
        self._records = records_fd
        self._pins = pins_fd
        self._evidence = evidence_fd
        self._root = root

    def load(self, decision_id: str) -> Record:
        if not _DECISION.fullmatch(decision_id):
            raise ValueError("invalid decision id")
        fd = os.open(decision_id, _DIRECTORY, dir_fd=self._records)
        try:
            _directory(fd, _ROOT_UID)
            packet = _approval(_read(fd, "approval.json", 32_768, _ROOT_UID))
            if packet.decision_id != decision_id:
                raise ValueError("approval identity mismatch")
            return Record(packet, self._root, _read(fd, "isolation", 1_048_576, _ROOT_UID),
                          _read(fd, "ca.pem", 256_000, _ROOT_UID),
                          _read(fd, "freeze", 65_536, _ROOT_UID))
        finally:
            os.close(fd)

    def approval_pin(self, decision_id: str) -> str:
        if not _DECISION.fullmatch(decision_id):
            raise ValueError("invalid decision id")
        pin = _read(self._pins, decision_id + ".pin", 64, _ROOT_UID).decode("ascii")
        if not _HEX.fullmatch(pin):
            raise ValueError("bad approval digest")
        signature = _read(self._pins, decision_id + ".sig", 64, _ROOT_UID)
        key = _read(self._pins, "reviewer.pem", 4096, _ROOT_UID)
        payload = f"ai-soc-b4-preflight-pin-v1\n{decision_id}\n{pin}\n".encode("ascii")
        if not _verify_ed25519(key, payload, signature):
            raise ValueError("unverified approval signature")
        return pin

    def evidence_ready(self, record, *, deadline):
        _directory(self._evidence, os.geteuid(), private=True)
        return monotonic() < deadline and os.access(".", os.W_OK | os.X_OK, dir_fd=self._evidence)

    def store_evidence(self, record, run_id, payload, *, deadline):
        if (not _RUN.fullmatch(run_id) or not _DECISION.fullmatch(record.packet.decision_id)
                or type(payload) is not bytes or not 0 < len(payload) <= 4096 or monotonic() >= deadline):
            raise ValueError("invalid evidence request")
        name = f"{record.packet.decision_id}.{run_id}.json"
        try:
            fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY | os.O_CLOEXEC,
                         0o600, dir_fd=self._evidence)
        except FileExistsError:
            fd = os.open(name, _READ, dir_fd=self._evidence)
            try:
                if _read_fd(fd, 4096, os.geteuid(), private=True) != payload:
                    raise ValueError("evidence conflict") from None
            except BaseException:
                os.close(fd)
                raise
        else:
            try:
                if os.write(fd, payload) != len(payload):
                    raise OSError("short evidence write")
            except BaseException:
                os.close(fd)
                raise
        try:
            os.fsync(fd)
            os.fsync(self._evidence)
        finally:
            os.close(fd)
        if monotonic() >= deadline:
            raise TimeoutError("evidence receipt expired")
        return sha256(payload).hexdigest()

    @abstractmethod
    def execution_is_frozen(self, record, *, deadline): ...

    @abstractmethod
    def recovery_authorized(self, record, *, until): ...

    @abstractmethod
    def hold_freeze(self, record, run_id, *, deadline): ...

    @abstractmethod
    def start_worker(self, record, trusted_digest, run_id, *, deadline): ...

    @abstractmethod
    def read_result(self, process, *, deadline): ...

    @abstractmethod
    def close_worker_scope(self, record, run_id, *, deadline): ...

    @abstractmethod
    def release_freeze(self, record, run_id, *, deadline): ...

    @abstractmethod
    def backends_gone(self, record, run_id, *, backend_pids, deadline): ...

    @abstractmethod
    def target_matches(self, record, *, deadline): ...
