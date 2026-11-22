#!/usr/bin/env python3
"""One-shot host fixture. Run as the ordinary operator, only after explicit approval."""
import errno
import grp
from hashlib import sha256
import json
import os
import pwd
import stat
from pathlib import Path
import re
import subprocess
import sys
from time import monotonic, sleep, time

UNIT = "b4-fixture-a649861e.service"
SLICE = "b4fixturea649861e.slice"
DESCRIPTION = "B4 credential-free fixture a649861e"
IDENTITY = "b4fixturea649861e"
WINDOW = Path("/run/b4-fixture-a649861e.window.json")
EVIDENCE = Path(__file__).parent / "b4-systemd249-fixture.evidence.jsonl"
PATHS = (
    "/run/docker.sock", "/var/run/docker.sock", "/run/user", "/run/ai-soc-b4",
    "/etc/ai-soc-b4", "/etc/ai-soc-b4-authority", "/var/lib/ai-soc-b4",
    "/var/lib/ai-soc-b4-authority", "/var/lib/ai-soc-b4-host-control",
    "/var/ossec", "/etc/wazuh-indexer", "/etc/wazuh-dashboard",
    "/var/lib/wazuh-indexer", "/var/lib/wazuh-dashboard",
    "/run/postgresql", "/var/run/postgresql", "/tmp/.s.PGSQL.5432",
)
MANAGER_KEYS = ("Version", "UserspaceTimestampMonotonic", "UnitPath")
CGROOT = Path("/sys/fs/cgroup")
SCOPE = CGROOT / SLICE / UNIT
SYSTEMCTL = ["/usr/bin/systemctl", "--system", "--no-pager"]
SUDO = ["/usr/bin/sudo", "--"]
PROPERTIES = {
    "Type": "exec", "Slice": SLICE, "Description": DESCRIPTION,
    "DynamicUser": "yes", "User": IDENTITY, "Group": IDENTITY, "NoNewPrivileges": "yes", "PrivateTmp": "yes",
    "PrivateDevices": "yes", "ProtectSystem": "strict", "ProtectHome": "yes",
    "ProtectControlGroups": "yes", "ProtectKernelTunables": "yes",
    "ProtectKernelModules": "yes", "ProtectKernelLogs": "yes",
    "RestrictNamespaces": "yes", "RestrictSUIDSGID": "yes",
    "CapabilityBoundingSet": "", "RestrictAddressFamilies": "AF_UNIX AF_INET",
    "SystemCallFilter": "~socket socketpair connect", "SystemCallErrorNumber": "EPERM",
    "IPAddressDeny": "any", "KillMode": "control-group", "RuntimeMaxSec": "30s",
    "TimeoutStartSec": "5s", "TimeoutStopSec": "5s", "TimeoutStopFailureMode": "kill",
    "SendSIGKILL": "yes", "FinalKillSignal": "SIGKILL", "Restart": "no",
    "TasksMax": "8", "MemoryMax": "64M", "LimitNOFILE": "32", "LimitCORE": "0",
    "StandardInput": "null", "StandardOutput": "journal", "StandardError": "journal", "UMask": "0077",
    "InaccessiblePaths": " ".join("-" + name for name in PATHS),
}
WORKER = r'''
import errno, json, os, signal, socket, stat, time
from pathlib import Path
expected = "0::/b4fixturea649861e.slice/b4-fixture-a649861e.service"
def emit(role, **extra):
    cg = Path("/proc/self/cgroup").read_text().strip()
    if cg != expected:
        raise RuntimeError("fixture scope mismatch")
    pid = os.getpid()
    stamp = Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()[19]
    print(json.dumps(dict(role=role, pid=pid, start_ticks=stamp, cgroup=cg, **extra)), flush=True)
def park():
    while True:
        signal.pause()
signal.signal(signal.SIGTERM, signal.SIG_IGN)
blocked = []
for family in (socket.AF_INET, socket.AF_INET6, socket.AF_UNIX):
    try:
        with socket.socket(family, socket.SOCK_STREAM):
            raise RuntimeError("fixture socket creation unexpectedly allowed")
    except OSError as exc:
        if exc.errno not in (errno.EAFNOSUPPORT, errno.EPERM, errno.EACCES):
            raise
        blocked.append(int(family))
descriptors = []
for name in os.listdir("/proc/self/fd"):
    fd = int(name)
    try:
        mode = os.fstat(fd).st_mode
    except OSError as exc:
        if exc.errno != errno.EBADF:
            raise
        continue
    if fd > 2 or (fd in (1, 2) and not stat.S_ISSOCK(mode)):
        raise RuntimeError("unexpected inherited fixture descriptor")
    descriptors.append(fd)
if sorted(descriptors) != [0, 1, 2] or os.readlink("/proc/self/fd/0") != "/dev/null":
    raise RuntimeError("unexpected fixture standard descriptors")
if (os.geteuid() == 0 or os.geteuid() == 136 or 147 in [os.getegid(), *os.getgroups()]
        or any(key == "CREDENTIALS_DIRECTORY" or
               key.startswith(("PG", "DOCKER_", "WAZUH_", "LD_", "BASH_ENV"))
               or key in {"DATABASE_URL", "TEST_DATABASE_URL", "AI_SOC_MIGRATION_DATABASE_URL"}
               for key in os.environ)
        or os.path.lexists("/run/credentials/b4-fixture-a649861e.service")):
    raise RuntimeError("unexpected fixture credential or identity")
paths = __PROTECTED_PATHS__
denied = {}
for name in paths:
    try:
        mode = os.lstat(name).st_mode
    except FileNotFoundError:
        denied[name] = "absent in fixture namespace"
    except PermissionError:
        denied[name] = "inaccessible"
    else:
        if (any(os.access(name, right) for right in (os.R_OK, os.W_OK, os.X_OK))
                or stat.S_ISSOCK(mode) or stat.S_ISLNK(mode)):
            raise RuntimeError("fixture protected path exposed")
        denied[name] = "inaccessible"
emit("worker", blocked_families=blocked, protected_paths=denied, descriptors=sorted(descriptors))
for role in ("broker-stub", "controller-stub"):
    helper = os.fork()
    if helper == 0:
        emit(role)
        os._exit(0)
    _, status = os.waitpid(helper, 0)
    if status != 0:
        raise RuntimeError("fixture helper failed")
if os.fork() == 0:
    emit("child")
    if os.fork() == 0:
        emit("grandchild")
        park()
    park()
park()
'''.replace("__PROTECTED_PATHS__", repr(PATHS))


def run(args, *, timeout=5):
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout,
                            env={"PATH": "/usr/bin", "LC_ALL": "C"}, check=True)
    return result.stdout.strip()


def show(unit=None, *names):
    lines = run([*SYSTEMCTL, "show", "--all", *(f"-p{x}" for x in names),
                 *([unit] if unit else [])])
    values = dict(line.split("=", 1) for line in lines.splitlines())
    if len(values) != len(lines.splitlines()):
        raise RuntimeError("duplicate PID 1 property")
    return values


def cgroup_identity(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISDIR(info.st_mode):
        raise RuntimeError("unexpected cgroup path type")
    return info.st_dev, info.st_ino


def tasks(path):
    if cgroup_identity(path) is None:
        return set()
    files = list(path.rglob("cgroup.procs"))
    if not files:
        raise RuntimeError("missing cgroup process inventory")
    return {int(pid) for file in files for pid in file.read_text().split()}


def empty_scope():
    try:
        return "populated 0" in (SCOPE / "cgroup.events").read_text().splitlines() and not tasks(SCOPE)
    except FileNotFoundError:
        return cgroup_identity(SCOPE) is None


def same_process(pid, timestamp):
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19] == timestamp
    except FileNotFoundError:
        return False


def start_command():
    return [*SUDO, "/usr/bin/systemd-run", "--system", "--no-ask-password", f"--unit={UNIT}",
            f"--description={DESCRIPTION}", f"--slice={SLICE}", "--collect",
            *(f"--property={key}={value}" for key, value in PROPERTIES.items()
              if key not in {"Slice", "Description"}),
            "--", "/usr/bin/python3", "-I", "-B", "-c", WORKER]


def protected_ancestry(path):
    for parent in (path, *path.parents):
        try:
            info = parent.stat()
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError("unprotected systemd search ancestry")


def check_search_paths(paths):
    if not paths or len(paths) > 64:
        raise RuntimeError("unknown effective unit search paths")
    for value in paths:
        directory = Path(value)
        if not directory.is_absolute() or ".." in directory.parts:
            raise RuntimeError("invalid unit search path")
        protected_ancestry(directory.resolve())
        protected_ancestry(directory)
        for unit in (UNIT, SLICE):
            kind = unit.rsplit(".", 1)[1]
            stem = unit.rsplit(".", 1)[0]
            prefixes = [stem[:index + 1] + "." + kind for index, char in enumerate(stem) if char == "-"]
            names = (unit, *(unit + suffix for suffix in (".d", ".wants", ".requires", ".upholds")),
                     *(prefix + ".d" for prefix in prefixes), kind + ".d")
            for name in names:
                try:
                    (directory / name).lstat()
                except FileNotFoundError:
                    continue
                raise RuntimeError("applicable fixture unit configuration exists")


def check_identity():
    for lookup in (pwd.getpwnam, grp.getgrnam):
        try:
            lookup(IDENTITY)
        except KeyError:
            continue
        raise RuntimeError("fixture identity already resolves through NSS")


def check_fixture_units():
    if show(UNIT, "LoadState") != {"LoadState": "not-found"}:
        raise RuntimeError("fixture service name collision")
    # systemd 249 loads slices even when there is no unit fragment.
    expected = {
        "Id": SLICE, "Names": SLICE, "LoadState": "loaded", "ActiveState": "inactive",
        "SubState": "dead", "FragmentPath": "", "SourcePath": "", "DropInPaths": "",
        "ControlGroup": "", "Transient": "no", "Perpetual": "no", "DefaultDependencies": "yes",
        "NeedDaemonReload": "no", "Job": "", "InvocationID": "",
        "InactiveExitTimestampMonotonic": "0", "ActiveEnterTimestampMonotonic": "0",
        "Slice": "-.slice", "Requires": "-.slice", "After": "-.slice", "Before": "shutdown.target",
        "Conflicts": "shutdown.target",
    }
    expected.update(dict.fromkeys((
        "SliceOf", "Wants", "Requisite", "BindsTo", "PartOf", "RequiredBy", "WantedBy",
        "RequisiteOf", "BoundBy", "ConsistsOf", "ConflictedBy", "OnFailure", "OnFailureOf",
        "OnSuccess", "OnSuccessOf", "Triggers", "TriggeredBy", "PropagatesStopTo",
        "StopPropagatedFrom", "PropagatesReloadTo", "ReloadPropagatedFrom", "RequiresMountsFor",
    ), ""))
    observed = show(SLICE, *expected)
    differences = [
        f"{name}: expected {expected[name]!r}, observed {observed[name]!r}"
        if name in observed else f"{name}: missing (expected {expected[name]!r})"
        for name in expected if name not in observed or observed[name] != expected[name]
    ]
    differences.extend(f"{name}: unexpected property" for name in sorted(observed.keys() - expected.keys()))
    if differences:
        raise RuntimeError("fixture slice is not a pristine implicit unit: " + "; ".join(differences))
    if cgroup_identity(CGROOT / SLICE) is not None:
        raise RuntimeError("fixture cgroup collision")


def precheck():
    system = show(None, *MANAGER_KEYS)
    pid1 = Path("/proc/1/status").read_text().splitlines()
    if (set(system) != set(MANAGER_KEYS) or os.uname().nodename != "mail.godcompl3x.com"
            or not re.fullmatch(r"249(?:[. ~+-].*)?", system["Version"])
            or not re.fullmatch(r"[1-9][0-9]{0,19}", system["UserspaceTimestampMonotonic"])
            or Path("/proc/1/comm").read_text().strip() != "systemd"
            or next(line for line in pid1 if line.startswith("Uid:")).split()[1:] != ["0"] * 4
            or Path("/proc/self/uid_map").read_text().split() != ["0", "0", "4294967295"]
            or not (CGROOT / "cgroup.controllers").is_file()
            or "rw" not in run(["/usr/bin/findmnt", "-T", str(CGROOT), "-n", "-o", "OPTIONS"]).split(",")):
        raise RuntimeError("requires exact real host, root PID 1 and writable unified hierarchy")
    check_search_paths(system["UnitPath"].split())
    check_identity()
    for prerequisite in ("sysinit.target", "basic.target", "systemd-journald.socket"):
        if show(prerequisite, "ActiveState") != {"ActiveState": "active"}:
            raise RuntimeError("required systemd dependency is not already active")
    check_fixture_units()
    return system


def controlled_window(system, *, minimum=0):
    protected_ancestry(WINDOW.parent)
    fd = os.open(WINDOW, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or info.st_mode & 0o022 or not 0 < info.st_size <= 4096):
            raise RuntimeError("unprotected custodian window")
        record = json.loads(stream.read(4097))
    until = record.pop("expires_unix", None)
    expected = dict(unit=UNIT, slice=SLICE, host="mail.godcompl3x.com",
                    manager_epoch=system["UserspaceTimestampMonotonic"],
                    runner_sha256=sha256(Path(__file__).read_bytes()).hexdigest(),
                    unit_management_frozen=True, nss_frozen=True, foreign_admission_denied=True)
    remaining = until - time() if type(until) is int else 0
    if record != expected or not minimum < remaining <= 300:
        raise RuntimeError("custodian window unavailable or inconsistent")
    return until


def append_evidence(stream, stage, **fields):
    stream.write(json.dumps(dict(stage=stage, monotonic=monotonic(), **fields), sort_keys=True) + "\n")
    stream.flush()
    os.fsync(stream.fileno())


def binding(effective, invocation):
    return (effective.get("InvocationID") == invocation and
            effective.get("ControlGroup") == "/" + str(SCOPE.relative_to(CGROOT)))


def reconcile(stream=None):
    """Record observable state after an ambiguous start. Never stop or resume."""
    prior = []
    result = {}
    try:
        fd = os.open(EVIDENCE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 65536):
                raise ValueError("unsafe fixture evidence file")
            prior = [json.loads(line) for line in source.read(65537).splitlines()]
    except (OSError, ValueError) as exc:
        result["evidence_error"] = type(exc).__name__
    try:
        state = show(UNIT, "LoadState", "ActiveState", "InvocationID", "ControlGroup")
        result["unit"] = state
        active = next((entry["effective"] for entry in prior if entry["stage"] == "INVOCATION"), None)
        members = next((entry["records"] for entry in prior if entry["stage"] == "MEMBERSHIP"), {})
        result["recorded_invocation_matches"] = bool(active and binding(state, active["InvocationID"]))
        result["recorded_processes_alive"] = [
            item["pid"] for item in members.values() if same_process(item["pid"], item["start_ticks"])
        ]
        result["slice_tasks"] = sorted(tasks(CGROOT / SLICE))
        result["scope_empty"] = empty_scope()
    except (KeyError, TypeError, OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        result["observation_error"] = type(exc).__name__
    if stream is not None:
        append_evidence(stream, "UNCONFIRMED", **result)
    print(json.dumps(dict(reconciliation="READ_ONLY", **result)), flush=True)


def verify_effective():
    expected = dict(Description=DESCRIPTION, Type="exec", ActiveState="active", SubState="running",
                    RuntimeMaxUSec="30s", TimeoutStartUSec="5s", TimeoutStopUSec="5s",
                    TimeoutStopFailureMode="kill", KillMode="control-group", SendSIGKILL="yes",
                    Restart="no", DynamicUser="yes", NoNewPrivileges="yes", User=IDENTITY,
                    Group=IDENTITY, Slice=SLICE)
    effective = show(UNIT, *expected, "InvocationID", "MainPID", "ControlGroup", "FinalKillSignal",
                     "ActiveEnterTimestampMonotonic", "RuntimeRandomizedExtraUSec", "DropInPaths")
    invocation = effective.get("InvocationID", "")
    if (any(effective.get(key) != value for key, value in expected.items())
            or effective.get("DropInPaths") != "" or effective.get("FinalKillSignal") not in {"9", "SIGKILL"}
            or effective.get("RuntimeRandomizedExtraUSec", "0") not in {"0", "0us"}
            or not re.fullmatch(r"[0-9a-f]{32}", invocation) or invocation == "0" * 32
            or not binding(effective, invocation) or not (SCOPE / "cgroup.kill").is_file()
            or (SCOPE / "cgroup.type").read_text().strip() != "domain"):
        raise RuntimeError("fixture effective properties mismatch")
    label = "".join(ch if ch.isalnum() else f"_{ord(ch):02x}" for ch in UNIT)
    hooks = run(["/usr/bin/busctl", "--system", "--no-pager", "get-property",
                 "org.freedesktop.systemd1", f"/org/freedesktop/systemd1/unit/{label}",
                 "org.freedesktop.systemd1.Service", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost"])
    if hooks.splitlines() != ["a(sasbttttuii) 0"] * 4:
        raise RuntimeError("unexpected or missing fixture execution hook properties")
    return effective


def identities(records, effective):
    live = {item["pid"]: item["start_ticks"] for role, item in records.items() if not role.endswith("-stub")}
    if (int(effective["MainPID"]) != records["worker"]["pid"] or len(live) != 3
            or records["worker"].get("descriptors") != [0, 1, 2]
            or tasks(CGROOT / SLICE) != set(live) or tasks(SCOPE) != set(live)
            or any(item["cgroup"] != "0::" + effective["ControlGroup"] for item in records.values())
            or any(not same_process(pid, stamp) for pid, stamp in live.items())):
        raise RuntimeError("fixture process membership mismatch")
    return live


def observe_teardown(live, invocation, active, system, cgroups):
    last_live = monotonic()
    while (sample_started := monotonic()) < active + 36:
        # A stale name or a foreign process never authorizes recovery actions.
        state = show(UNIT, "LoadState", "ActiveState", "InvocationID", "ControlGroup")
        if state.get("LoadState") != "not-found" and not binding(state, invocation):
            raise RuntimeError("fixture invocation disappeared or was replaced")
        for path, original in cgroups.items():
            current = cgroup_identity(path)
            if current is not None and current != original:
                raise RuntimeError("fixture cgroup was replaced")
        remaining = {pid for pid, stamp in live.items() if same_process(pid, stamp)}
        present = tasks(CGROOT / SLICE)
        if not present <= remaining:
            raise RuntimeError("foreign fixture-slice process")
        if remaining:
            last_live = sample_started
        elif empty_scope():
            observed = monotonic()
            if state.get("LoadState") != "not-found" and state.get("ActiveState") not in {"failed", "inactive"}:
                sleep(0.02)
                continue
            if show(None, *MANAGER_KEYS) != system:
                raise RuntimeError("PID 1 changed during fixture")
            if any(path.is_dir() and path != SCOPE for path in (CGROOT / SLICE).glob("*")):
                raise RuntimeError("foreign fixture-slice cgroup")
            if observed > active + 35:
                code = "LATE" if last_live >= active + 35 else "POLLING_UNCERTAIN"
                raise RuntimeError(f"teardown timing {code}")
            return dict(last_live_s=last_live - active, first_empty_s=observed - active,
                        scope_absent=not SCOPE.exists(), residual_slice=(CGROOT / SLICE).exists())
        sleep(0.02)
    raise RuntimeError("fixture teardown unconfirmed")


def execute(system):
    until = controlled_window(system, minimum=60)
    fd = os.open(EVIDENCE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "w") as stream:
        append_evidence(stream, "START_ATTEMPTED", unit=UNIT, slice=SLICE, manager=system, window_expires=until)
        parent = os.open(EVIDENCE.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        try:
            if precheck() != system or controlled_window(system, minimum=45) != until:
                raise RuntimeError("pre-start evidence changed")
            run(start_command(), timeout=12)
            effective = verify_effective()
            invocation = effective["InvocationID"]
            append_evidence(stream, "INVOCATION", effective=effective)
            for _ in range(10):
                log = run([*SUDO, "/usr/bin/journalctl", "--no-pager", "-o", "cat",
                           f"_SYSTEMD_INVOCATION_ID={invocation}", f"_SYSTEMD_UNIT={UNIT}"])
                items = [json.loads(line) for line in log.splitlines()]
                records = {item["role"]: item for item in items}
                if len(items) != len(records):
                    raise RuntimeError("duplicate fixture process evidence")
                if set(records) == {"worker", "child", "grandchild", "broker-stub", "controller-stub"}:
                    break
                sleep(0.1)
            else:
                raise RuntimeError("fixture process evidence missing")
            active = int(effective["ActiveEnterTimestampMonotonic"]) / 1_000_000
            if not 0 < active <= monotonic() < active + 30:
                raise RuntimeError("invalid PID 1 activation time")
            cgroups = {path: cgroup_identity(path) for path in (SCOPE, CGROOT / SLICE)}
            if None in cgroups.values():
                raise RuntimeError("fixture cgroup identity unavailable")
            live = identities(records, effective)
            append_evidence(stream, "MEMBERSHIP", records=records,
                            cgroups={str(path): identity for path, identity in cgroups.items()})
            result = observe_teardown(live, invocation, active, system, cgroups)
            if controlled_window(system) != until:
                raise RuntimeError("custodian window changed")
            append_evidence(stream, "CONFIRMED", **result)
            print(json.dumps(dict(effective=effective, records=records, **result)), flush=True)
        except BaseException:
            try:
                reconcile(stream)
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                print("UNCONFIRMED: unable to durably record reconciliation", file=sys.stderr)
            raise


def main():
    if sys.argv[1:] == ["--print-plan"]:
        import shlex
        print(shlex.join(start_command()))
        print(f"/usr/bin/sudo -- /usr/bin/journalctl --no-pager -o cat "
              f"'_SYSTEMD_INVOCATION_ID=<verified-invocation>' _SYSTEMD_UNIT={UNIT}")
        return
    if len(sys.argv) != 2 or os.geteuid() == 0:
        raise SystemExit("Use the ordinary operator and exactly one mode.")
    if sys.argv[1] == "--reconcile":
        reconcile()
        raise SystemExit("Read-only recovery evidence. A new run is prohibited.")
    if sys.argv[1] not in {"--precheck", "--execute"}:
        raise SystemExit("Unsupported fixture mode.")
    system = precheck()
    if sys.argv[1] == "--precheck":
        print(json.dumps(dict(precheck=system, custodian_window_expires=controlled_window(system, minimum=60),
                              status="READ_ONLY_PRECHECK")))
        return
    execute(system)


if __name__ == "__main__":
    main()
