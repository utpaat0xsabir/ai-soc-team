"""Trusted launcher tests use only synthetic approval, process and monitor inputs."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from subprocess import TimeoutExpired

import pytest

from app.database import source_registry_preflight as worker
from app.database import source_registry_preflight_launcher as launcher
from tests.database.test_source_registry_preflight import scenario, snapshots  # noqa: F401


class Process:
    pid = 987654

    def __init__(self, timeout):
        self.timeout = timeout
        self.status = None

    def wait(self, timeout):
        assert 0 < timeout <= 60
        if self.timeout:
            raise TimeoutExpired("synthetic", timeout)
        self.status = 0
        return self.status

    def poll(self):
        return self.status


class Provider:
    def __init__(self, record, pin):
        self.record = record
        self.pin = pin
        self.frozen = True
        self.freeze_valid = True
        self.gone = True
        self.target = True
        self.timeout = False
        self.starts = 0
        self.held = False
        self.report_overrides = {}
        self.recovery_allowed = True
        self.scope_closed = False
        self.scope_closable = True
        self.partial_startup = False
        self.release_confirmed = True
        self.sink_ready = True
        self.receipt_valid = True
        self.stored = []

    def load(self, decision_id):
        return self.record

    def approval_pin(self, decision_id):
        return self.pin

    def execution_is_frozen(self, record, *, deadline):
        return self.frozen

    def recovery_authorized(self, record, *, until):
        return self.recovery_allowed

    def evidence_ready(self, record, *, deadline):
        return self.sink_ready

    def store_evidence(self, record, run_id, payload, *, deadline):
        self.stored.append((run_id, payload))
        return sha256(payload).hexdigest() if self.receipt_valid else "0" * 64

    def hold_freeze(self, record, run_id, *, deadline):
        if not self.freeze_valid:
            raise ValueError("synthetic secret")
        self.held = True
        self.run_id = run_id
        return True

    def start_worker(self, record, trusted_digest, run_id, *, deadline):
        assert self.held and trusted_digest == self.pin and run_id == self.run_id
        self.starts += 1
        self.process = Process(self.timeout)
        if self.partial_startup:
            raise RuntimeError("synthetic secret")
        return self.process

    def close_worker_scope(self, record, run_id, *, deadline):
        assert self.held and run_id == self.run_id
        self.scope_closed = self.scope_closable
        return self.scope_closed

    def release_freeze(self, record, run_id, *, deadline):
        assert self.scope_closed and self.gone and self.target and run_id == self.run_id
        if self.release_confirmed:
            self.held = False
        return self.release_confirmed

    def read_result(self, process, *, deadline):
        return replace(worker.Report("PASS", "complete", "VERIFIED", (160006, 160006),
                                     worker.guard.BASELINE, "e" * 64, target_recheck="MATCH",
                                     run_id=self.run_id, backend_pids=(10, 11), approval_sha256=self.pin),
                       **self.report_overrides)

    def backends_gone(self, record, run_id, *, backend_pids, deadline):
        assert self.held and self.scope_closed and run_id == self.run_id
        assert backend_pids in ((), (10, 11))
        return self.gone

    def target_matches(self, record, *, deadline):
        assert self.held
        return self.target


@pytest.fixture
def prepared(scenario, tmp_path):
    p = scenario.inputs
    store = tmp_path / "protected"
    store.mkdir(mode=0o700)
    record = launcher.Record(scenario.packet, p["root"],
                             p["application_isolation"], p["ca"], p["freeze"])
    return Provider(record, p["trusted_approval_sha256"]), store


def invoke(prepared):
    provider, store = prepared
    return launcher.launch(provider.record.packet.decision_id, provider=provider, replay_directory=store)


def test_missing_trust_provider_is_denied(tmp_path):
    assert launcher.launch("decision", provider=None, replay_directory=tmp_path).code == "TRUST_INPUTS_UNAVAILABLE"


@pytest.mark.parametrize("problem, code", [
    ("manifest", "APPROVAL_UNAVAILABLE"), ("forged", "APPROVAL_UNAVAILABLE"),
    ("expired", "APPROVAL_UNAVAILABLE"), ("freeze", "FREEZE_UNVERIFIED"),
    ("executable", "EXECUTABLE_NOT_FROZEN"), ("store", "REPLAY_STORE_UNAVAILABLE"),
    ("recovery", "RECOVERY_AUTHORITY_UNVERIFIED"),
])
def test_trust_requirements_stop_before_worker(prepared, problem, code):
    provider, store = prepared
    if problem == "manifest":
        provider.record = replace(provider.record, packet=replace(provider.record.packet,
                                                                 candidate_manifest_sha256="f" * 64))
        provider.pin = worker.approval_sha256(provider.record.packet)
    elif problem == "forged":
        provider.pin = "f" * 64
    elif problem == "expired":
        packet = replace(provider.record.packet, expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
        provider.record = replace(provider.record, packet=packet)
        provider.pin = worker.approval_sha256(packet)
    elif problem == "freeze":
        provider.freeze_valid = False
    elif problem == "recovery":
        provider.recovery_allowed = False
    elif problem == "executable":
        provider.frozen = False
    else:
        store.chmod(0o755)
    outcome = invoke(prepared)
    assert outcome.code == code and provider.starts == 0
    assert "synthetic secret" not in repr(outcome)


def test_replay_rejected_across_new_provider_instance(prepared):
    provider, store = prepared
    first = invoke(prepared)
    assert first.code == "VERIFIED" and first.teardown == "CONFIRMED" and first.target_recheck == "MATCH"
    assert first.evidence_sha256 == "e" * 64 and first.freeze == "RELEASED"
    assert (store / provider.record.packet.decision_id).read_text().strip() == first.run_id
    restarted = Provider(provider.record, provider.pin)
    assert invoke((restarted, store)).code == "DECISION_ALREADY_USED"
    assert restarted.starts == 0


def test_atomic_concurrent_reuse(prepared):
    provider, store = prepared
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(lambda _: launcher.reserve_once(store, provider.record.packet.decision_id, "b4-" + "a" * 32), range(8)))
    assert results.count(True) == 1


@pytest.mark.parametrize("failed_check", ["gone", "target"])
def test_no_success_without_independent_reconciliation(prepared, failed_check):
    provider, _ = prepared
    setattr(provider, failed_check, False)
    result = invoke(prepared)
    assert result.code == "POSTFLIGHT_UNVERIFIED"
    assert (result.teardown if failed_check == "gone" else result.target_recheck) == "UNCONFIRMED"


def test_timeout_closes_scope_and_reports_uncertain_teardown(prepared):
    provider, _ = prepared
    provider.timeout = True
    provider.gone = False
    result = invoke(prepared)
    assert result.code == "HARD_DEADLINE"
    assert result.teardown == "UNCONFIRMED" and result.target_recheck == "MATCH"
    assert result.containment == "CONFIRMED" and result.freeze == "HELD"
    assert invoke(prepared).code == "DECISION_ALREADY_USED"


@pytest.mark.parametrize("fields", [
    {"evidence_sha256": None}, {"predecessor": None}, {"versions": ()},
    {"versions": (160006, 160007)}, {"versions": (170001, 170001)},
    {"approval_sha256": "0" * 64}, {"run_id": "b4-" + "0" * 32},
])
def test_incomplete_worker_success_is_rejected(prepared, fields):
    provider, _ = prepared
    provider.report_overrides = fields
    assert invoke(prepared).code != "VERIFIED"


def test_failed_backend_reconciliation_retains_freeze(prepared):
    provider, _ = prepared
    provider.gone = False
    result = invoke(prepared)
    assert result.teardown == "UNCONFIRMED"
    assert provider.held


def test_expiry_during_reconciliation_cannot_pass(prepared, monkeypatch):
    provider, _ = prepared
    original = provider.target_matches
    def expire(*args, **kwargs):
        monkeypatch.setattr(launcher, "datetime", type("Expired", (), {
            "now": staticmethod(lambda _: provider.record.packet.expires_at),
        }))
        return original(*args, **kwargs)
    monkeypatch.setattr(provider, "target_matches", expire)
    assert invoke(prepared).code == "APPROVAL_WINDOW_CLOSED"


def test_ambiguous_startup_is_reconciled_without_process_handle(prepared):
    provider, _ = prepared
    provider.partial_startup = True
    result = invoke(prepared)
    assert result.code == "WORKER_FAILED" and result.containment == "CONFIRMED"
    assert result.teardown == "CONFIRMED" and result.freeze == "RELEASED"


def test_failed_containment_keeps_freeze_even_if_no_backend_reported(prepared):
    provider, _ = prepared
    provider.scope_closable = False
    result = invoke(prepared)
    assert result.code == "POSTFLIGHT_UNVERIFIED"
    assert result.containment == result.teardown == "UNCONFIRMED"
    assert result.freeze == "HELD" and provider.held


@pytest.mark.parametrize("code,expected", [("ROLLBACK_FAILED", "ROLLBACK_FAILED"), ("synthetic secret", "FAILED")])
def test_worker_failure_codes_are_allowlisted(prepared, code, expected):
    provider, _ = prepared
    provider.report_overrides = {"status": "FAIL", "code": code}
    result = invoke(prepared)
    assert result.code == "WORKER_FAILED" and result.worker_code == expected
    assert "synthetic secret" not in repr(result)


def test_uncertain_release_never_passes(prepared):
    provider, _ = prepared
    provider.release_confirmed = False
    result = invoke(prepared)
    assert result.code == "POSTFLIGHT_UNVERIFIED" and result.freeze == "UNCONFIRMED"

def test_missing_protected_evidence_sink_stops_before_worker(prepared):
    provider, store = prepared
    provider.sink_ready = False
    result = invoke(prepared)
    assert result.code == "EVIDENCE_STORAGE_UNAVAILABLE"
    assert not provider.starts and not list(store.iterdir())


def test_invalid_storage_receipt_cannot_pass(prepared):
    provider, _ = prepared
    provider.receipt_valid = False
    result = invoke(prepared)
    assert result.code == "EVIDENCE_STORAGE_UNCONFIRMED"
    assert result.teardown == "CONFIRMED" and result.evidence_receipt_sha256 is None


def test_protected_sink_persists_only_bound_observations(prepared):
    provider, _ = prepared
    result = invoke(prepared)
    (run_id, payload), = provider.stored
    record = json.loads(payload)
    assert run_id == record["run_id"] == result.run_id
    assert record["approval_sha256"] == provider.pin
    assert record["observation_code"] == "VERIFIED"
    assert record["evidence_sha256"] == "e" * 64
    assert result.evidence_receipt_sha256 == sha256(payload).hexdigest()
    assert "secret-value" not in payload.decode()


def test_expiry_during_evidence_storage_cannot_pass(prepared, monkeypatch):
    provider, _ = prepared
    original = provider.store_evidence

    def expire(*args, **kwargs):
        monkeypatch.setattr(launcher, "datetime", type("Expired", (), {
            "now": staticmethod(lambda _: provider.record.packet.expires_at),
        }))
        return original(*args, **kwargs)

    monkeypatch.setattr(provider, "store_evidence", expire)
    result = invoke(prepared)
    assert result.code == "APPROVAL_WINDOW_CLOSED"
    assert result.evidence_sha256 is None


def test_storage_failure_preserves_failed_teardown(prepared, monkeypatch):
    provider, _ = prepared
    provider.gone = False

    def unavailable(*args, **kwargs):
        raise RuntimeError("synthetic secret")

    monkeypatch.setattr(provider, "store_evidence", unavailable)
    result = invoke(prepared)
    assert result.code == "POSTFLIGHT_UNVERIFIED"
    assert result.freeze == "HELD" and result.evidence_storage == "UNCONFIRMED"
    assert "synthetic secret" not in repr(result)


def test_unexpected_evidence_path_exception_cannot_preserve_pass(prepared, monkeypatch):
    def unexpected(*args, **kwargs):
        raise RuntimeError("private diagnostic")

    monkeypatch.setattr(launcher, "_store_observation", unexpected)
    result = invoke(prepared)
    assert result.code == "EVIDENCE_STORAGE_UNCONFIRMED"
    assert result.teardown == "CONFIRMED" and result.evidence_sha256 is None
    assert result.evidence_receipt_sha256 is None
    assert "private diagnostic" not in repr(result)
