"""Offline checks of the admission proof and PID 1 deadline contract."""
from datetime import timedelta
from subprocess import CalledProcessError, TimeoutExpired
from time import monotonic
from types import SimpleNamespace

import pytest

from app.database.source_registry_b4_admission import AdmissionProof
from app.database.source_registry_b4_host_control import manager_deadline
from app.database.source_registry_b4_runtime import Cgroup
from tests.database.test_source_registry_preflight import scenario, snapshots  # noqa: F401


def admission_wire(packet, run, digest, deadline):
    return dict(decision_id=packet.decision_id, run_id=run, approval_sha256=digest,
                container_id=packet.approved_target.container_id, database=packet.database,
                endpoint=list(packet.endpoint), tls_identity=packet.tls_server_identity,
                tls_ca_sha256=packet.tls_ca_sha256,
                instance=[160000, (packet.valid_from - timedelta(seconds=1)).isoformat(), 42],
                identities=[packet.migrator_login, packet.observer_login], tcp_paths=[list(packet.endpoint)],
                unix_paths=[], initial_sessions=[], replication=False, freeze_held=True,
                policy_sha256="1" * 64, freeze_sha256=packet.freeze_sha256,
                valid_from=packet.valid_from.isoformat(), expires_at=packet.expires_at.isoformat(),
                stop_by=deadline)


@pytest.mark.parametrize("patch", [
    {"decision_id": "wrong"}, {"run_id": "wrong"}, {"approval_sha256": "2" * 64},
    {"container_id": "2" * 64}, {"database": "ai_soc"}, {"tls_identity": "unapproved"},
    {"identities": ["other", "observer"]}, {"unix_paths": ["/run/postgresql"]},
    {"tcp_paths": [["127.0.0.1", 5433]]}, {"replication": True}, {"freeze_held": False},
    {"initial_sessions": [[42, "unapproved"]]}, {"stop_by": float("inf")},
    {"instance": [150000, "2020-01-01T00:00:00+00:00", 42]},
    {"expires_at": "2020-01-01T00:00:00+00:00"},
])
def test_invalid_admission_claims_are_denied(scenario, patch):
    expected = scenario.inputs
    run, digest = expected["run_id"], expected["trusted_approval_sha256"]
    deadline = monotonic() + 1
    proof = admission_wire(scenario.packet, run, digest, deadline)
    with pytest.raises(PermissionError):
        AdmissionProof.validate({**proof, **patch}, scenario.packet, run, digest, deadline)


@pytest.mark.parametrize("version, fields, accepted", [
    ("249.11-0ubuntu3.23", {}, True),
    ("249.11-0ubuntu3.23", {"RuntimeRandomizedExtraUSec": "5s"}, False),
    ("250", {"RuntimeRandomizedExtraUSec": "0"}, True),
    ("250", {}, False),
    ("248", {}, False),
    ("249", {"RuntimeMaxUSec": "infinity"}, False),
    ("249", {"TimeoutStopUSec": "6s"}, False),
    ("249", {"TimeoutStopUSec": None}, False),
    ("249", {"FinalKillSignal": "15"}, False),
    ("249", {"Restart": "always"}, False),
    ("249", {"KillMode": "process"}, False),
    ("249", {"ExecStop": "nonempty"}, False),
    ("249", {"ExecStopPost": None}, False),
    ("249", {"ActiveState": "activating"}, False),
    ("249", {"ControlGroup": "/other"}, False),
    ("249", {"ActiveEnterTimestampMonotonic": "0"}, False),
])
def test_manager_deadline_checks_effective_runtime_unit(version, fields, accepted):
    began = monotonic() - 1
    properties = dict(Type="exec", ActiveState="active", SubState="running",
                      ControlGroup=Cgroup.name("reviewed"), TimeoutStartUSec="5s", RuntimeMaxUSec="30s",
                      TimeoutStopUSec="5s", TimeoutStopFailureMode="kill", Restart="no",
                      KillMode="control-group", SendSIGKILL="yes", FinalKillSignal="9",
                      InvocationID="a" * 32,
                      ActiveEnterTimestampMonotonic=str(int(began * 1_000_000)))

    def command(args, **kwargs):
        assert kwargs["timeout"] <= 2
        if args[0] == "/usr/bin/busctl":
            assert args[5] == "/org/freedesktop/systemd1/unit/ai_2dsoc_2db4_2dworker_40reviewed_2eservice"
            assert args[-2:] == ["ExecStop", "ExecStopPost"]
            hooks = {"ExecStop": "a(sasbttttuii) 0", "ExecStopPost": "a(sasbttttuii) 0"} | fields
            return SimpleNamespace(stdout="\n".join(hooks[key] for key in args[-2:] if hooks[key] is not None))
        assert args[:3] == ["/usr/bin/systemctl", "--system", "show"]
        if args[-1] == "--property=Version":
            return SimpleNamespace(stdout=f"UserspaceTimestampMonotonic=1\nVersion={version}\n")
        assert args[-1] == "ai-soc-b4-worker@reviewed.service"
        return SimpleNamespace(stdout="\n".join(
            f"{k}={v}" for k, v in (properties | fields).items() if v is not None and k not in {"ExecStop", "ExecStopPost"}))

    assert (manager_deadline("reviewed", began + 36, monotonic() + 1, command=command) is not None) is accepted
    assert manager_deadline("reviewed", began + 34, monotonic() + 1, command=command) is None


@pytest.mark.parametrize("error", [FileNotFoundError(), TimeoutExpired("systemctl", 1),
                                  CalledProcessError(1, "systemctl")])
def test_manager_unavailable_fails_closed(error):
    def command(*args, **kwargs):
        raise error

    assert manager_deadline("reviewed", monotonic() + 40, monotonic() + 1, command=command) is None


def test_manager_change_during_query_fails_closed():
    outputs = iter(("UserspaceTimestampMonotonic=1\nVersion=249.11-0ubuntu3.23", "",
                    "a(sasbttttuii) 0\na(sasbttttuii) 0",
                    "UserspaceTimestampMonotonic=2\nVersion=249.11-0ubuntu3.23"))
    def command(*args, **kwargs):
        return SimpleNamespace(stdout=next(outputs))

    assert manager_deadline("reviewed", monotonic() + 40, monotonic() + 1, command=command) is None


def test_server_instance_proof_is_checked_before_role_or_history_queries(scenario):
    from app.database import source_registry_preflight

    packet, inputs = scenario.packet, scenario.inputs
    stop_by = monotonic() + 1
    raw = admission_wire(packet, inputs["run_id"], inputs["trusted_approval_sha256"], stop_by)
    proof = AdmissionProof.validate(raw, packet, inputs["run_id"], inputs["trusted_approval_sha256"], stop_by)
    assert source_registry_preflight.run(packet, **inputs, admission=proof).code == "SESSION_IDENTITY_MISMATCH"
