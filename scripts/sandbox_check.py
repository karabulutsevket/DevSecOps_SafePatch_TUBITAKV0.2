"""Week 8 sandbox check (ROADMAP.md): the sandbox's settings read from inside a running container,
and hostile builds run through the real runner.

1. Settings: one container started with the runner's own command (`runner.sandboxed`) reports its
   user, capabilities, no-new-privileges, seccomp, network interfaces, cgroup limits, mounts,
   ulimits and environment.
2. Hostile builds: the SQL lab with a hostile test class (samples/hostile) as a test suite, verified
   by runner.execute in the Docker sandbox:
   - hostile: network, writes outside the workspace, privileges, mount/chroot/namespaces, process
     count, memory, /tmp and file size; it passes only if every attempt fails;
   - tamper: tracked files replaced by a link to a host path and by a named pipe; refused, quickly;
   - link: the build output directory turned into a link to a host directory; refused;
   - hang: a test that never ends; stopped at the descriptor's limit, its container removed.
   Their descriptors are not synthetic labs, so the runner refuses to build them natively.
3. Control: the hostile suite once more in a container without the isolating flags (network,
   read-only root, user, capabilities, no-new-privileges; resource limits kept). It must fail
   there, or passing in the sandbox would prove nothing. Its attempts stay harmless: a TCP
   connection to a public resolver, a name lookup, marker files inside the throwaway container.

Writes EVIDENCE_DIR/sandbox/check.json. Needs Docker in WSL and SANDBOX_MAVEN_CACHE
(scripts/prepare_sandbox.py).
"""
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import uuid

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from safepatch import runner
from safepatch.common import VerifyRequest, evidence
from safepatch.project import ProjectSpec, synthetic_descriptor
from safepatch.repository import registry

SAMPLES = ROOT / "samples/hostile"
# case -> (behaviour selector, witness selector, test time limit): the hostile class replaces one suite.
CASES = {"hostile": ("demo.HostileTest", "demo.SecurityTest", 240), "tamper": ("demo.BehaviorTest", "demo.TamperTest", 240),
         "link": ("demo.LinkTest", "demo.SecurityTest", 240), "hang": ("demo.HangTest", "demo.SecurityTest", 30)}
PROBE = r"""
echo "uid=$(id -u)"
echo "gid=$(id -g)"
grep -E '^(CapEff|CapBnd|NoNewPrivs|Seccomp):' /proc/self/status | tr -d ' \t' | tr ':' '='
echo "interfaces=$(ls /sys/class/net | tr '\n' ' ' | sed 's/ $//')"
for f in memory.max memory.swap.max cpu.max pids.max; do echo "$f=$(cat /sys/fs/cgroup/$f)"; done
for d in / /m2 /workspace /tmp /jvmtmp; do if touch "$d/.probe" 2>/dev/null; then rm -f "$d/.probe"; echo "write:$d=yes"; else echo "write:$d=no"; fi; done
cp /bin/true /tmp/.probe-exec && chmod +x /tmp/.probe-exec && { /tmp/.probe-exec 2>/dev/null && echo "exec:/tmp=yes" || echo "exec:/tmp=no"; }; rm -f /tmp/.probe-exec
echo "ulimit:nofile=$(ulimit -n)"
echo "ulimit:core=$(ulimit -c)"
echo "ulimit:fsize_kib=$(ulimit -f)"
echo "workspace_size_kib=$(df -k /workspace | awk 'NR==2 {print $2}')"
echo "tmp_size_kib=$(df -k /tmp | awk 'NR==2 {print $2}')"
echo "docker_socket=$(test -e /var/run/docker.sock && echo present || echo absent)"
echo "environment=$(env | cut -d= -f1 | sort | tr '\n' ' ' | sed 's/ $//')"
"""


def settings():
    """What a running sandbox container reports about itself, one `name=value` per line. Its
    workspace is a folder where the runner stages real ones."""
    path = work_dir() + "/probe-" + uuid.uuid4().hex[:8]
    subprocess.run(runner.wsl("mkdir", "-p", path), check=True, capture_output=True, timeout=60)
    try:
        result = subprocess.run(runner.sandboxed(["bash", "-c", PROBE], ROOT / ".runtime", "safepatch-probe-" + uuid.uuid4().hex[:8], mount=path),
                                capture_output=True, text=True, timeout=300)
    finally:
        subprocess.run(runner.wsl("rm", "-rf", path), capture_output=True, timeout=60)
    facts = dict(line.partition("=")[::2] for line in result.stdout.splitlines() if "=" in line)
    return {"exit_code": result.returncode, "facts": facts}


def work_dir():
    return runner.Stage(ROOT / ".runtime" / "probe").path.rsplit("/", 1)[0]


def work_filesystem():
    """The WSL filesystem holding the sandbox workspaces (Stage): its mount point and size. The
    workspace is mounted read-write, so this is all a build can fill."""
    work = work_dir()
    result = subprocess.run(runner.wsl("sh", "-c", f"mkdir -p {work} && findmnt -n -b -o TARGET,SIZE -T {work} && df -k --output=avail {work} | tail -1"),
                            capture_output=True, text=True, timeout=60)
    lines = result.stdout.split()
    return {"work": work, "mount": lines[0] if lines else None, "size_bytes": int(lines[1]) if len(lines) > 1 else None,
            "available_kib": int(lines[2]) if len(lines) > 2 else None}


def seed_module():
    spec = importlib.util.spec_from_file_location("seed_script", ROOT / "scripts/seed.py")
    seed = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(seed)
    return seed


def prepare(folder):
    """One repository (the SQL lab plus the hostile classes) and a descriptor per case; returns
    the projects folder to use as PROJECTS_DIR."""
    seed = seed_module()
    repo = Path(folder) / "repos" / "hostile"
    files = {**seed.expected_files("sql", 1), **{"src/test/java/demo/" + p.name: p.read_bytes() for p in sorted(SAMPLES.glob("*.java"))}}
    for name, data in files.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_bytes(data)
    git = lambda *a: subprocess.check_output(["git", "-c", "user.name=SafePatch", "-c", "user.email=synthetic@localhost", "-c", "core.autocrlf=false", *a], cwd=repo).decode().strip()
    git("init", "-q")
    git("add", ".")
    git("commit", "-qm", "SafePatch sandbox check: SQL lab with hostile tests")
    projects = Path(folder) / "projects"
    projects.mkdir(parents=True, exist_ok=True)
    for case, (behavior, witness, seconds) in CASES.items():
        data = synthetic_descriptor("hostile-" + case, {"kind": "sql", "split": "development", "commit": git("rev-parse", "HEAD"), "project": "safepatch-hostile"}, repo.resolve())
        data["tests"]["behavior"]["selectors"] = [behavior]
        data["tests"]["security"]["selectors"] = [witness]
        data["limits"] = {"build_seconds": 240, "test_seconds": seconds}
        # Not a synthetic lab: the runner builds it in the sandbox only.
        data["labels"]["source"] = "safepatch-hostile"
        ProjectSpec.model_validate(data)
        (projects / f"hostile-{case}.yml").write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8", newline="\n")
    return projects


# Flags that isolate (as opposed to resource limits), removed for the control run.
ISOLATING = {("--network", "none"), ("--cap-drop", "ALL"), ("--security-opt", "no-new-privileges")}


def weakened(argv):
    """The sandbox command without its isolating flags, run as root."""
    out, skip = [], False
    for flag, value in zip(argv, argv[1:] + [None]):
        if skip:
            skip = False
        elif (flag, value) in ISOLATING:
            skip = True
        elif flag == "--read-only":
            continue
        elif flag == "--user":
            out += ["--user", "0:0"]
            skip = True
        else:
            out.append(flag)
    return out


def control():
    """The hostile suite with the isolating flags removed: which of its tests fail."""
    from safepatch.project import SuiteSelection
    from safepatch.repository import project
    case_id = "hostile-hostile"
    commit = registry()[1][case_id]["commit"]
    spec = project(case_id, commit)
    workspace = runner.runtime("runner-work") / ("control-" + uuid.uuid4().hex[:8])
    runner.checkout(case_id, commit, workspace)
    stage = runner.Stage(workspace)
    original = runner.sandboxed
    try:
        stage.push()
        build = runner.maven(workspace, list(spec.build.package_goals), time.time() + 600, sandbox="docker", stage=stage)
        runner.sandboxed = lambda *a, **k: weakened(original(*a, **k))
        try:
            result = runner.tests(workspace, SuiteSelection(selectors=["demo.HostileTest"]), time.time() + 600, 240, "docker", "17", spec.build, stage)
        finally:
            # The control ran as root: give what it wrote back to the runner's user before removing it.
            subprocess.run(runner.sandboxed(["chown", "-R", "1000:1000", "/workspace"], workspace, "safepatch-chown-" + uuid.uuid4().hex[:8], mount=stage.path),
                           capture_output=True, timeout=300)
    finally:
        runner.sandboxed = original
        stage.remove()
        shutil.rmtree(workspace, ignore_errors=True)
    return {"build_exit_code": build["exit_code"], "tests": result.get("tests"), "failures": result.get("failures"), "errors": result.get("errors"),
            "failed": sorted(d["name"] for d in result.get("details", []))}


def containers():
    result = subprocess.run(runner.wsl("docker", "ps", "-a", "--filter", "name=safepatch-", "--format", "{{.Names}}"), capture_output=True, text=True, timeout=60)
    return result.stdout.split()


def run_case(case):
    """The runner's verification of one hostile case: its result, or the refusal it raised."""
    case_id = "hostile-" + case
    started = time.time()
    row = {"case": case}
    try:
        result = runner.execute(VerifyRequest(job_id=uuid.uuid4().hex, case_id=case_id, base_commit=registry()[1][case_id]["commit"],
                                              attempt=0, deadline=time.time() + 900, scanner="builtin"))
        row.update(outcome="completed", behavior={k: result["behavior"].get(k) for k in ("passed", "tests", "failures", "errors", "details")},
                   build=result["build"], runner_profile=result["runner_profile"])
    except Exception as exc:
        row.update(outcome="refused", error=type(exc).__name__, reason=str(exc)[:300])
    row["seconds"] = round(time.time() - started, 1)
    time.sleep(2)
    row["containers_left"] = containers()
    return row


def expected(rows, facts, weak, disk):
    """Each check and whether it held."""
    by = {r["case"]: r for r in rows}
    hostile = by["hostile"].get("behavior") or {}
    return {
        "user_1000_no_capabilities": facts.get("uid") == "1000" and facts.get("CapEff") == "0000000000000000" and facts.get("CapBnd") == "0000000000000000",
        "no_new_privileges_and_seccomp": facts.get("NoNewPrivs") == "1" and facts.get("Seccomp") == "2",
        "loopback_only": facts.get("interfaces") == "lo",
        "memory_2g_no_swap": facts.get("memory.max") == str(2 * 2**30) and facts.get("memory.swap.max") == "0",
        "cpu_2_pids_1024": facts.get("cpu.max") == "200000 100000" and facts.get("pids.max") == "1024",
        "read_only_root_and_cache": facts.get("write:/") == "no" and facts.get("write:/m2") == "no" and facts.get("write:/workspace") == "yes",
        "tmp_noexec": facts.get("exec:/tmp") == "no",
        "no_docker_socket": facts.get("docker_socket") == "absent",
        "hostile_build_contained": by["hostile"]["outcome"] == "completed" and hostile.get("passed") is True and hostile.get("tests") == 10,
        "tampering_refused_quickly": by["tamper"].get("reason") == "tracked_file_changed_during_execution" and by["tamper"]["seconds"] < 300,
        "link_refused": by["link"].get("reason") == "sandbox_stage_link_refused",
        "hang_stopped": by["hang"].get("error") == "TimeoutError" and by["hang"]["seconds"] < 120,
        "no_container_left": not any(r["containers_left"] for r in rows),
        # Without isolation the suite must fail where isolation is what it tests.
        "control_fails_without_isolation": {"onlyTheLoopbackInterface", "noWritesOutsideTheWorkspace", "notRootAndWithoutPrivileges"} <= set(weak["failed"]),
        # The workspaces live on their own, size-limited filesystem (docs/SANDBOX.md).
        "workspace_disk_bounded": disk["mount"] == disk["work"] and facts.get("workspace_size_kib", "").isdigit()
                                  and int(facts["workspace_size_kib"]) * 1024 <= disk["size_bytes"],
    }


def main():
    out = evidence("sandbox")
    if (out / "check.json").exists():
        raise SystemExit("Use a fresh EVIDENCE_DIR; evidence is never overwritten")
    out.mkdir(parents=True, exist_ok=True)
    os.environ["RUNNER_SANDBOX"] = "docker"
    folder = ROOT / ".runtime" / "sandbox-check"
    if folder.exists():
        shutil.rmtree(folder, onerror=seed_module().writable)
    os.environ["PROJECTS_DIR"] = str(prepare(folder))
    probe = settings()
    print(json.dumps(probe["facts"], indent=1), flush=True)
    rows = []
    for case in CASES:
        rows.append(run_case(case))
        print(json.dumps({k: rows[-1].get(k) for k in ("case", "outcome", "error", "reason", "seconds", "containers_left")}), flush=True)
    weak = control()
    disk = work_filesystem()
    print(json.dumps({"control": weak, "work_filesystem": disk}), flush=True)
    checks = expected(rows, probe["facts"], weak, disk)
    git = lambda *a: subprocess.run(["git", *a], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    (out / "check.json").write_text(json.dumps({"schema": 1, "git_commit": git("rev-parse", "HEAD"), "git_dirty": bool(git("status", "--porcelain", "--untracked-files=no")),
                                                "image": runner.SANDBOX_IMAGE, "ulimits": runner.SANDBOX_ULIMITS,
                                                "python": platform.python_version(), "settings": probe, "cases": rows, "control": weak, "work_filesystem": disk, "checks": checks,
                                                "all_held": all(checks.values())}, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(checks, indent=1), "\nall held:", all(checks.values()), "written:", out / "check.json")


if __name__ == "__main__":
    main()
