"""Offline tests for local B4 custody and inert host provisioning."""
from base64 import b64encode
from contextlib import ExitStack
from dataclasses import asdict
from hashlib import sha256
import json
import os
from pathlib import Path
import runpy
from time import monotonic

import pytest

from app.database import source_registry_local_inputs as local
from app.database.source_registry_observer_adapter import _wire
from tests.database.test_source_registry_preflight import scenario, snapshots  # noqa: F401


class SyntheticLocal(local.LocalProtectedInputs):
    """No live hook may be reached from these tests."""
    def execution_is_frozen(self, *args, **kwargs): raise AssertionError
    recovery_authorized = hold_freeze = start_worker = read_result = execution_is_frozen
    close_worker_scope = release_freeze = backends_gone = target_matches = execution_is_frozen


@pytest.fixture
def protected(scenario, monkeypatch, tmp_path):
    monkeypatch.setattr(local, "_ROOT_UID", os.geteuid())
    ident = scenario.packet.decision_id
    with ExitStack() as cleanup:
        fds = []
        directories = [tmp_path / n for n in ("records", "pins", "evidence")]
        for directory in directories:
            directory.mkdir(mode=0o700)
            fd = os.open(directory, local._DIRECTORY)
            cleanup.callback(os.close, fd)
            fds.append(fd)
        records, pins, evidence = directories
        entry = records / ident
        entry.mkdir(mode=0o700)
        (entry / "approval.json").write_text(json.dumps(asdict(scenario.packet), default=_wire))
        for name, key in (("ca.pem", "ca"), ("isolation", "application_isolation"), ("freeze", "freeze")):
            (entry / name).write_bytes(scenario.inputs[key])
        digest = scenario.inputs["trusted_approval_sha256"]
        (pins / f"{ident}.pin").write_text(digest)
        (pins / f"{ident}.sig").write_bytes(b"x" * 64)
        (pins / "reviewer.pem").write_bytes(b"synthetic public key")
        for file in (*entry.iterdir(), *pins.iterdir()):
            file.chmod(0o640)
        provider = SyntheticLocal(records_fd=fds[0], pins_fd=fds[1], evidence_fd=fds[2], root=tmp_path)
        yield provider, ident, digest, entry, pins, evidence


def test_load_and_independent_pin_bind_exact_decision(protected, monkeypatch):
    provider, ident, digest, _, _, _ = protected

    def verify(key, payload, signature):
        assert key == b"synthetic public key" and signature == b"x" * 64
        assert payload == f"ai-soc-b4-preflight-pin-v1\n{ident}\n{digest}\n".encode()
        return True

    monkeypatch.setattr(local, "_verify_ed25519", verify)
    record = provider.load(ident)
    assert record.packet.decision_id == ident
    assert provider.approval_pin(ident) == digest


def test_bad_signatures_denied(protected, monkeypatch):
    provider, ident, *_ = protected
    monkeypatch.setattr(local, "_verify_ed25519", lambda *args: False)
    with pytest.raises(ValueError, match="unverified approval signature"):
        provider.approval_pin(ident)


@pytest.mark.parametrize("file", ["approval.json", "ca.pem"])
def test_writable_protected_input_is_denied(protected, file):
    provider, ident, _, entry, _, _ = protected
    (entry / file).chmod(0o666)
    with pytest.raises(ValueError, match="unsafe protected file"):
        provider.load(ident)


def test_symlink_and_decision_escape_denied(protected):
    provider, ident, _, _, pins, _ = protected
    (pins / f"{ident}.sig").unlink()
    (pins / f"{ident}.sig").symlink_to("reviewer.pem")
    with pytest.raises(OSError):
        provider.approval_pin(ident)
    with pytest.raises(ValueError, match="invalid decision id"):
        provider.load("../pins")


def test_evidence_durable_idempotent_and_conflicts_fail(protected, monkeypatch):
    provider, ident, _, _, _, evidence = protected
    record = provider.load(ident)
    deadline = monotonic() + 3
    tag, payload = "b4-" + "0" * 32, b'{"observation_code":"FAILED"}'
    assert provider.evidence_ready(record, deadline=deadline)
    assert provider.store_evidence(record, tag, payload, deadline=deadline) == sha256(payload).hexdigest()
    assert provider.store_evidence(record, tag, payload, deadline=deadline) == sha256(payload).hexdigest()
    assert list(evidence.iterdir())[0].stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError, match="evidence conflict"):
        provider.store_evidence(record, tag, b"other", deadline=deadline)
    with pytest.raises(ValueError, match="invalid evidence request"):
        provider.store_evidence(record, tag, payload, deadline=monotonic())
    monkeypatch.setattr(os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("failed durability")))
    with pytest.raises(OSError, match="failed durability"):
        provider.store_evidence(record, tag, payload, deadline=deadline)


def test_signature_process_is_fixed_and_uses_no_path_from_approval(monkeypatch):
    der = bytes.fromhex("302a300506032b6570032100") + b"x" * 32
    key = b"-----BEGIN PUBLIC KEY-----\n" + b64encode(der) + b"\n-----END PUBLIC KEY-----\n"

    def verify(argv, **kwargs):
        assert argv[:4] == ["/usr/bin/openssl", "pkeyutl", "-verify", "-pubin"]
        assert kwargs["env"] == {"OPENSSL_CONF": "/dev/null"}
        assert kwargs["timeout"] == 3
        assert os.read(kwargs["pass_fds"][1], 100) == b"message"
        return type("Result", (), {"returncode": 1})()

    monkeypatch.setattr(local.subprocess, "run", verify)
    assert local._verify_ed25519(key, b"message", b"x" * 64) is False
    assert local._verify_ed25519(b"invalid key", b"message", b"x" * 64) is False


def test_provisioning_plan_is_read_only_and_apply_requires_exact_digest(monkeypatch):
    script = runpy.run_path(str(Path(__file__).resolve().parents[2] / "scripts" / "provision_b4.py"))
    main = script["main"]
    calls = []
    monkeypatch.setitem(main.__globals__, "_bundle", lambda *args: (b"archive", b"unit"))
    monkeypatch.setitem(main.__globals__, "_host", lambda: calls.append("host"))
    monkeypatch.setitem(main.__globals__, "_apply", lambda plan: calls.append("apply"))
    args = ["--candidate", "fixture", "--candidate-sha256", "0" * 64]
    assert main(["--dry-run", *args]) == 0 and calls == ["host"]
    assert main(["--apply", *args, "--approve-plan-sha256", "f" * 64]) == 1
    assert calls == ["host"]


def test_inert_apply_is_idempotent_and_never_overwrites(monkeypatch, tmp_path):
    script = runpy.run_path(str(Path(__file__).resolve().parents[2] / "scripts" / "provision_b4.py"))
    apply = script["_apply"]
    monkeypatch.setitem(apply.__globals__, "_ancestors", lambda path: None)
    destination = tmp_path / "package.tar"
    plan = [("install", destination, os.geteuid(), os.getegid(), 0o440, b"exact")]
    apply(plan)
    original = destination.stat()
    apply(plan)
    assert destination.stat().st_ino == original.st_ino
    with pytest.raises(ValueError, match="existing protected file differs"):
        apply([(*plan[0][:-1], b"replacement")])
    assert destination.read_bytes() == b"exact"


def test_provisioner_rejects_symlink_ancestors_and_leaves(monkeypatch, tmp_path):
    script = runpy.run_path(str(Path(__file__).resolve().parents[2] / "scripts" / "provision_b4.py"))
    read = script["_source_bytes"]
    monkeypatch.setitem(read.__globals__, "ROOT", tmp_path)
    data = tmp_path / "real"
    data.mkdir()
    (data / "file").write_bytes(b"fixture")
    (tmp_path / "ancestor").symlink_to("real", target_is_directory=True)
    (tmp_path / "leaf").symlink_to("real/file")
    assert read(Path("real/file"), 100) == b"fixture"
    for unsafe in ("ancestor/file", "leaf", "real/../real/file"):
        with pytest.raises((ValueError, OSError)):
            read(Path(unsafe), 100)


def test_apply_checks_source_ancestry_before_reading_candidate(monkeypatch):
    script = runpy.run_path(str(Path(__file__).resolve().parents[2] / "scripts" / "provision_b4.py"))
    main = script["main"]
    monkeypatch.setattr(os, "geteuid", lambda: 0)

    def unprotected(_):
        raise ValueError("unprotected ancestry")

    def forbidden(*args):
        pytest.fail("candidate read before ancestry validation")

    monkeypatch.setitem(main.__globals__, "_ancestors", unprotected)
    monkeypatch.setitem(main.__globals__, "_bundle", forbidden)
    assert main(["--apply", "--candidate", "fixture", "--candidate-sha256", "0" * 64,
                 "--approve-plan-sha256", "0" * 64]) == 1


def test_frozen_archive_reproduces_manifest_without_git(tmp_path, monkeypatch):
    from app.database import source_registry_artifact as artifact

    root = Path(__file__).resolve().parents[2]
    pinned = artifact.manifest_bytes(root)
    for name in artifact.FILES:
        file = tmp_path / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes((root / name).read_bytes())
    marker = tmp_path / "B4-MANIFEST.json"
    marker.write_bytes(pinned)

    def unavailable(*args):
        pytest.fail("deployed archive tried to invoke Git")

    monkeypatch.setattr(artifact, "_git", unavailable)
    assert artifact.manifest_bytes(tmp_path) == pinned
    decoded = json.loads(pinned)
    decoded["runtime"]["python"] = "unexpected"
    marker.write_bytes(artifact._canonical(decoded))
    with pytest.raises(ValueError, match="frozen_manifest_drift"):
        artifact.manifest_bytes(tmp_path)
    marker.write_bytes(pinned)
    (tmp_path / ".git").mkdir()
    with pytest.raises(ValueError, match="ambiguous_artifact_source"):
        artifact.manifest_bytes(tmp_path)
    (tmp_path / ".git").rmdir()
    (tmp_path / "scripts/provision_b4.py").write_bytes(b"changed")
    with pytest.raises(ValueError, match="frozen_manifest_drift"):
        artifact.manifest_bytes(tmp_path)
