"""Offline review regressions for the credential-free fixture runner."""
import json
from pathlib import Path
import runpy
import shlex
import subprocess
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "review-output/b4-systemd249-fixture.py"


@pytest.fixture
def fixture(monkeypatch, tmp_path):
    module = runpy.run_path(str(SCRIPT))
    context = module["execute"].__globals__
    monkeypatch.setitem(context, "EVIDENCE", tmp_path / "evidence.jsonl")
    return SimpleNamespace(**module, context=context)


@pytest.mark.parametrize("name", [
    "b4-fixture-a649861e.service.d", "b4-fixture-.service.d", "b4-.service.d",
    "service.d", "slice.d", "b4fixturea649861e.slice.requires",
    "b4-fixture-a649861e.service.wants",
])
def test_applicable_inherited_configuration_denies_start(fixture, monkeypatch, tmp_path, name):
    monkeypatch.setitem(fixture.context, "protected_ancestry", lambda _: None)
    fixture.check_search_paths([str(tmp_path)])
    (tmp_path / name).mkdir()
    with pytest.raises(RuntimeError, match="applicable"):
        fixture.check_search_paths([str(tmp_path)])


@pytest.mark.parametrize("database, function", [("pwd", "getpwnam"), ("grp", "getgrnam")])
def test_static_nss_collision(fixture, monkeypatch, database, function):
    def absent(*args):
        raise KeyError

    monkeypatch.setattr(fixture.pwd, "getpwnam", absent)
    monkeypatch.setattr(fixture.grp, "getgrnam", absent)
    fixture.check_identity()
    monkeypatch.setattr(getattr(fixture, database), function, lambda _: object())
    with pytest.raises(RuntimeError, match="NSS"):
        fixture.check_identity()


@pytest.mark.parametrize("properties", [
    ["a(sasbttttuii) 0"] * 3,
    ["a(sasbttttuii) 0", "unexpected", "a(sasbttttuii) 0", "a(sasbttttuii) 0"],
])
def test_missing_or_unexpected_hook_denied(fixture, monkeypatch, tmp_path, properties):
    cgroot = tmp_path / "cg"
    scope = cgroot / fixture.SLICE / fixture.UNIT
    scope.mkdir(parents=True)
    (scope / "cgroup.kill").touch()
    (scope / "cgroup.type").write_text("domain\n")
    effective = dict(Description=fixture.DESCRIPTION, Type="exec", ActiveState="active", SubState="running",
                     RuntimeMaxUSec="30s", TimeoutStartUSec="5s", TimeoutStopUSec="5s", TimeoutStopFailureMode="kill",
                     KillMode="control-group", SendSIGKILL="yes", Restart="no", DynamicUser="yes", NoNewPrivileges="yes",
                     User=fixture.IDENTITY, Group=fixture.IDENTITY, Slice=fixture.SLICE, DropInPaths="", FinalKillSignal="9",
                     InvocationID="a" * 32, ControlGroup="/" + str(scope.relative_to(cgroot)))
    monkeypatch.setitem(fixture.context, "CGROOT", cgroot)
    monkeypatch.setitem(fixture.context, "SCOPE", scope)
    monkeypatch.setitem(fixture.context, "show", lambda *args: effective)
    monkeypatch.setitem(fixture.context, "run", lambda *args: "\n".join(["a(sasbttttuii) 0"] * 4))
    assert fixture.verify_effective() == effective
    monkeypatch.setitem(fixture.context, "run", lambda *args: "\n".join(properties))
    with pytest.raises(RuntimeError, match="execution hook"):
        fixture.verify_effective()


@pytest.mark.parametrize("error", [subprocess.TimeoutExpired("systemd-run", 12),
                                  subprocess.CalledProcessError(1, "systemd-run")])
def test_start_ack_lost_leaves_durable_record_no_stop_and_blocks_retry(fixture, monkeypatch, error):
    system = {"Version": "249"}
    calls = []
    monkeypatch.setitem(fixture.context, "precheck", lambda: system)
    monkeypatch.setitem(fixture.context, "controlled_window", lambda *args, **kwargs: 99)
    monkeypatch.setitem(fixture.context, "show", lambda *args: {"LoadState": "not-found"})
    monkeypatch.setitem(fixture.context, "tasks", lambda *args: set())
    monkeypatch.setitem(fixture.context, "empty_scope", lambda: True)

    def failed_start(args, **kwargs):
        calls.append(args)
        assert json.loads(fixture.context["EVIDENCE"].read_text())["stage"] == "START_ATTEMPTED"
        raise error

    monkeypatch.setitem(fixture.context, "run", failed_start)
    with pytest.raises(type(error)):
        fixture.execute(system)
    stages = [json.loads(line)["stage"] for line in fixture.context["EVIDENCE"].read_text().splitlines()]
    assert stages == ["START_ATTEMPTED", "UNCONFIRMED"]
    with pytest.raises(FileExistsError):
        fixture.execute(system)
    assert calls == [fixture.start_command()]


@pytest.mark.parametrize("failure, match", [
    ("unit reuse", "replaced"), ("slice reuse", "cgroup was replaced"),
    ("foreign", "foreign"), ("manager loss", "manager unavailable"),
    ("manager changed", "PID 1 changed"), ("incomplete", "teardown unconfirmed"),
    ("polling", "POLLING_UNCERTAIN"), ("late", "LATE"),
])
def test_teardown_ambiguity_does_not_confirm(fixture, monkeypatch, tmp_path, failure, match):
    invocation = "a" * 32
    live = {22: "5"}
    system = {"Version": "249"}
    child = tmp_path / fixture.UNIT
    cgroot = tmp_path
    monkeypatch.setitem(fixture.context, "SCOPE", child)
    monkeypatch.setitem(fixture.context, "CGROOT", cgroot)
    monkeypatch.setitem(fixture.context, "tasks", lambda _: {77} if failure == "foreign" else set())
    monkeypatch.setitem(fixture.context, "same_process", lambda *args: failure == "incomplete")
    monkeypatch.setitem(fixture.context, "empty_scope", lambda: failure != "incomplete")
    monkeypatch.setitem(fixture.context, "cgroup_identity", lambda _: (1, 7) if failure == "slice reuse" else (1, 3))

    def show(unit, *args):
        if failure == "manager loss":
            raise RuntimeError("manager unavailable")
        if unit is None:
            return {} if failure == "manager changed" else system
        if failure == "unit reuse":
            return {"LoadState": "loaded", "InvocationID": "b" * 32, "ControlGroup": "/" + fixture.UNIT}
        return {"LoadState": "not-found"}

    monkeypatch.setitem(fixture.context, "show", show)
    clocks = iter({"incomplete": [130, 131, 132, 137], "polling": [134, 134.5, 135.01],
                   "late": [135.01, 135.1, 135.2]}.get(failure, [130, 131, 132]))
    monkeypatch.setitem(fixture.context, "monotonic", lambda: next(clocks))
    monkeypatch.setitem(fixture.context, "sleep", lambda _: None)
    with pytest.raises(RuntimeError, match=match):
        fixture.observe_teardown(live, invocation, 100, system, {child: (1, 3)})


def test_command_listing_has_no_stop_and_exact_inline_worker(fixture, monkeypatch, capsys):
    monkeypatch.setattr(fixture.sys, "argv", [str(SCRIPT), "--print-plan"])
    monkeypatch.setitem(fixture.context, "run", lambda *args: pytest.fail("plan attempted a subprocess"))
    fixture.main()
    text = capsys.readouterr().out
    assert text == SCRIPT.with_suffix(".commands.txt").read_text()
    commands = shlex.split(text)
    assert commands[:4] == ["/usr/bin/sudo", "--", "/usr/bin/systemd-run", "--system"]
    assert commands.count("/usr/bin/sudo") == 2
    assert "/usr/bin/systemctl" not in commands
    assert fixture.WORKER in commands
    assert "/run/postgresql" in fixture.WORKER and "/proc/self/fd" in fixture.WORKER
    assert "CREDENTIALS_DIRECTORY" in fixture.WORKER
    compile(fixture.WORKER, "<credential-free-worker>", "exec")


def test_precheck_mode_has_no_start_or_subprocess_side_effect(fixture, monkeypatch, capsys):
    monkeypatch.setattr(fixture.sys, "argv", [str(SCRIPT), "--precheck"])
    monkeypatch.setattr(fixture.os, "geteuid", lambda: 1000)
    monkeypatch.setitem(fixture.context, "precheck", lambda: {"Version": "249"})
    monkeypatch.setitem(fixture.context, "controlled_window", lambda *args, **kwargs: 99)
    monkeypatch.setitem(fixture.context, "execute", lambda *args: pytest.fail("precheck reached execution"))
    monkeypatch.setitem(fixture.context, "run", lambda *args: pytest.fail("precheck dispatched a command"))
    fixture.main()
    assert json.loads(capsys.readouterr().out)["status"] == "READ_ONLY_PRECHECK"
    assert not fixture.context["EVIDENCE"].exists()


def test_missing_custodian_window_denies_execution_before_evidence_or_start(fixture, monkeypatch, tmp_path):
    monkeypatch.setitem(fixture.context, "WINDOW", tmp_path / "unprovisioned")
    monkeypatch.setitem(fixture.context, "protected_ancestry", lambda _: None)
    monkeypatch.setitem(fixture.context, "run", lambda *args: pytest.fail("start without custodian window"))
    with pytest.raises(FileNotFoundError):
        fixture.execute({"Version": "249"})
    assert not fixture.context["EVIDENCE"].exists()


@pytest.fixture
def slice_properties(fixture):
    return {
        "Id": fixture.SLICE, "Names": fixture.SLICE, "LoadState": "loaded", "ActiveState": "inactive",
        "SubState": "dead", "FragmentPath": "", "SourcePath": "", "DropInPaths": "",
        "ControlGroup": "", "Transient": "no", "Perpetual": "no", "DefaultDependencies": "yes",
        "NeedDaemonReload": "no", "Job": "", "InvocationID": "",
        "InactiveExitTimestampMonotonic": "0", "ActiveEnterTimestampMonotonic": "0",
        "Slice": "-.slice", "Requires": "-.slice", "After": "-.slice", "Before": "shutdown.target",
        "Conflicts": "shutdown.target", "SliceOf": "", "Wants": "", "Requisite": "", "BindsTo": "",
        "PartOf": "", "RequiredBy": "", "WantedBy": "", "RequisiteOf": "", "BoundBy": "", "ConsistsOf": "",
        "ConflictedBy": "", "OnFailure": "", "OnFailureOf": "", "OnSuccess": "", "OnSuccessOf": "",
        "Triggers": "", "TriggeredBy": "", "PropagatesStopTo": "", "StopPropagatedFrom": "",
        "PropagatesReloadTo": "", "ReloadPropagatedFrom": "", "RequiresMountsFor": "",
    }


def test_pristine_implicit_slice_does_not_relax_service_collision(fixture, slice_properties, monkeypatch, tmp_path):
    service = {"LoadState": "not-found"}

    def show(name, *keys):
        if name == fixture.UNIT:
            assert keys == ("LoadState",)
            return service
        assert name == fixture.SLICE
        return slice_properties

    monkeypatch.setitem(fixture.context, "show", show)
    monkeypatch.setitem(fixture.context, "CGROOT", tmp_path)
    fixture.check_fixture_units()
    service["LoadState"] = "loaded"
    with pytest.raises(RuntimeError, match="service name collision"):
        fixture.check_fixture_units()


@pytest.mark.parametrize("patch", [
    {"ActiveState": "active"}, {"Transient": "yes"}, {"FragmentPath": "/etc/systemd/system/example.slice"},
    {"SourcePath": "/run/generated"}, {"DropInPaths": "/run/x.conf"}, {"Names": "alias.slice"},
    {"ControlGroup": "/other.slice"}, {"SliceOf": "foreign.service"}, {"RequiredBy": "foreign.service"},
    {"Conflicts": "production.service shutdown.target"}, {"Job": "17"},
    {"InactiveExitTimestampMonotonic": "1"}, {"InvocationID": "b" * 32},
    {"ActiveEnterTimestampMonotonic": "42"}, {"NeedDaemonReload": "yes"}, {"Before": None},
    {"InvocationID": None}, {"Slice": "system.slice"}, {"Slice": None}, {"Unknown": ""},
])
def test_slice_collision_or_unknown_state_is_rejected(fixture, slice_properties, monkeypatch, tmp_path, patch):
    properties = {name: value for name, value in (slice_properties | patch).items() if value is not None}
    monkeypatch.setitem(fixture.context, "CGROOT", tmp_path)
    monkeypatch.setitem(fixture.context, "show", lambda name, *_: (
        {"LoadState": "not-found"} if name == fixture.UNIT else properties))
    with pytest.raises(RuntimeError, match="pristine implicit"):
        fixture.check_fixture_units()


def test_slice_rejects_cgroup_even_if_pid1_reports_no_members(fixture, slice_properties, monkeypatch, tmp_path):
    monkeypatch.setitem(fixture.context, "CGROOT", tmp_path)
    monkeypatch.setitem(fixture.context, "show", lambda name, *_: (
        {"LoadState": "not-found"} if name == fixture.UNIT else slice_properties))
    path = tmp_path / fixture.SLICE
    path.mkdir()
    (path / "cgroup.procs").write_text("101\n")
    with pytest.raises(RuntimeError, match="cgroup collision"):
        fixture.check_fixture_units()


def test_show_preserves_observed_empty_invocation_and_reports_all_mismatches(
        fixture, slice_properties, monkeypatch, tmp_path):
    properties = {**slice_properties, "ActiveState": "active", "Slice": "system.slice"}
    properties.pop("Job")
    monkeypatch.setitem(fixture.context, "CGROOT", tmp_path)

    def output(args):
        if args[-1] == fixture.UNIT:
            return "LoadState=not-found"
        assert args[-1] == fixture.SLICE and "--all" in args
        return "\n".join(f"{name}={value}" for name, value in properties.items())

    monkeypatch.setitem(fixture.context, "run", output)
    assert fixture.show(fixture.SLICE, "InvocationID")["InvocationID"] == ""
    with pytest.raises(RuntimeError) as exc:
        fixture.check_fixture_units()
    assert "ActiveState: expected 'inactive', observed 'active'" in str(exc.value)
    assert "Slice: expected '-.slice', observed 'system.slice'" in str(exc.value)
    assert "Job: missing (expected '')" in str(exc.value)
    assert "InvocationID:" not in str(exc.value)
