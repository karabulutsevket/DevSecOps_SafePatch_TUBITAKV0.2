"""Docker sandbox (roadmap weeks 5–6): project code is built and tested with no network,
a read-only root, no capabilities and a non-root user; real projects never build natively."""
import base64
import os
from pathlib import Path
import subprocess
import time
import shutil
import stat
import sys
import types
import uuid

import pytest

from safepatch import runner
from safepatch.common import SOURCE, VerifyRequest
from safepatch.policy import PolicyError

CACHE = "/home/test/.safepatch/m2"


def spec(source):
    return types.SimpleNamespace(labels={"source": source} if source else {})


@pytest.mark.parametrize("mode,source,expected", [
    ("native", "safepatch-synthetic", "native"), ("docker", "safepatch-synthetic", "docker"), ("docker", None, "docker"),
])
def test_sandbox_mode(monkeypatch, mode, source, expected):
    monkeypatch.setenv("RUNNER_SANDBOX", mode)
    monkeypatch.setenv("SAFEPATCH_PROFILE", "lab")
    assert runner.sandbox_mode(spec(source)) == expected


@pytest.mark.parametrize("profile", [None, "product", "evaluation", "demo"])
def test_native_builds_are_for_the_lab_profile_only(monkeypatch, profile):
    # Week 8: outside the lab (development) profile even the owned synthetic labs build in the sandbox.
    monkeypatch.setenv("RUNNER_SANDBOX", "native")
    if profile:
        monkeypatch.setenv("SAFEPATCH_PROFILE", profile)
    else:
        monkeypatch.delenv("SAFEPATCH_PROFILE", raising=False)
    with pytest.raises(PolicyError, match="native_runner_outside_lab_profile"):
        runner.sandbox_mode(spec("safepatch-synthetic"))
    monkeypatch.setenv("RUNNER_SANDBOX", "docker")
    assert runner.sandbox_mode(spec("safepatch-synthetic")) == "docker"


@pytest.mark.parametrize("mode,profile,usable", [("native", "lab", True), ("native", None, False), ("docker", None, True)])
def test_health_says_whether_the_runner_can_build_at_all(monkeypatch, mode, profile, usable):
    monkeypatch.setenv("RUNNER_SANDBOX", mode)
    if profile:
        monkeypatch.setenv("SAFEPATCH_PROFILE", profile)
    else:
        monkeypatch.delenv("SAFEPATCH_PROFILE", raising=False)
    status = runner.health()
    assert (status["native_allowed"], status["usable"]) == (profile == "lab", usable)


@pytest.mark.parametrize("mode", ["native", None])
def test_a_real_project_never_builds_natively(monkeypatch, mode):
    if mode:
        monkeypatch.setenv("RUNNER_SANDBOX", mode)
    else:
        monkeypatch.delenv("RUNNER_SANDBOX", raising=False)
    with pytest.raises(PolicyError, match="sandbox_required_for_real_projects"):
        runner.sandbox_mode(spec(None))
    monkeypatch.setenv("SAFEPATCH_PROFILE", "lab")
    with pytest.raises(PolicyError, match="sandbox_required_for_real_projects"):
        runner.sandbox_mode(spec(None))
    monkeypatch.setenv("RUNNER_SANDBOX", "podman")
    with pytest.raises(PolicyError, match="unknown_runner_sandbox"):
        runner.sandbox_mode(spec("safepatch-synthetic"))


def test_the_container_command_carries_every_restriction(monkeypatch, tmp_path):
    monkeypatch.setenv("SANDBOX_MAVEN_CACHE", CACHE)
    monkeypatch.setattr(runner, "wsl_path", lambda path: "/mnt/c/ws")
    argv = runner.sandboxed(["mvn", "-o", "test"], tmp_path, "safepatch-x")
    assert argv[:5] == ["wsl", "-d", "Debian", "--exec", "docker"]
    joined = " ".join(argv)
    for flag in ("--network none", "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges", "--pids-limit 1024",
                 "--memory 2g --memory-swap 2g", "--cpus 2", "--user 1000:1000",
                 "--ulimit nofile=8192:8192", "--ulimit core=0", f"--ulimit fsize={2**30}", "--tmpfs /tmp:rw,size=1g", "--tmpfs /jvmtmp:rw,size=512m", "--rm", "--name safepatch-x",
                 f"-v {CACHE}:/m2:ro", "-v /mnt/c/ws:/workspace", "--entrypoint mvn"):
        assert flag in joined, flag
    assert argv[-3:] == [runner.SANDBOX_IMAGE, "-o", "test"] and "@sha256:" in runner.SANDBOX_IMAGE


@pytest.mark.parametrize("cache", [None, "", "relative/m2", "C:\\m2"])
def test_the_container_needs_an_absolute_wsl_cache(monkeypatch, tmp_path, cache):
    if cache is None:
        monkeypatch.delenv("SANDBOX_MAVEN_CACHE", raising=False)
    else:
        monkeypatch.setenv("SANDBOX_MAVEN_CACHE", cache)
    with pytest.raises(RuntimeError, match="sandbox_maven_cache_missing"):
        runner.sandboxed(["mvn"], tmp_path, "x")


def test_maven_in_the_sandbox_is_offline_and_secret_free(monkeypatch, tmp_path):
    monkeypatch.setenv("SANDBOX_MAVEN_CACHE", CACHE)
    monkeypatch.setattr(runner, "wsl_path", lambda path: "/mnt/c/ws")
    seen = {}
    monkeypatch.setattr(runner, "run", lambda argv, cwd, timeout, extra=None: seen.update(argv=argv, extra=extra) or {"exit_code": 0, "duration_seconds": 1, "output": ""})
    runner.maven(tmp_path, ["test"], time.time() + 60, sandbox="docker")
    mvn = seen["argv"][seen["argv"].index(runner.SANDBOX_IMAGE) + 1:]
    assert "-o" in mvn and "-Dmaven.repo.local=/tmp/m2" in mvn and "-Dmaven.repo.local.tail=/m2" in mvn and mvn[-1] == "test"
    # The test JVM's temp dir is not /tmp, so a witness aimed at /tmp can tell a fix apart (VUL4J-79).
    assert [f for f in mvn if f.startswith("-DargLine=")] == ["-DargLine=-Xmx512m -Dfile.encoding=UTF-8 -Djava.io.tmpdir=/jvmtmp"]
    assert seen["extra"] is None
    for kwargs in ({"online": True}, {"extra": {"SONAR_TOKEN": "x"}}):
        with pytest.raises(PolicyError, match="sandbox_runs_offline_without_secrets"):
            runner.maven(tmp_path, ["test"], time.time() + 60, sandbox="docker", **kwargs)


def test_a_timed_out_container_is_killed(monkeypatch, tmp_path):
    monkeypatch.setenv("SANDBOX_MAVEN_CACHE", CACHE)
    monkeypatch.setattr(runner, "wsl_path", lambda path: "/mnt/c/ws")
    def timeout(*args, **kwargs):
        raise TimeoutError("child_timeout")
    killed = []
    monkeypatch.setattr(runner, "run", timeout)
    monkeypatch.setattr(runner.subprocess, "run", lambda argv, **kwargs: killed.append(argv))
    with pytest.raises(TimeoutError):
        runner.maven(tmp_path, ["test"], time.time() + 60, sandbox="docker")
    assert killed and killed[0][-3:-1] == ["docker", "kill"] and killed[0][-1].startswith("safepatch-")


def test_sonar_needs_network_so_it_never_runs_in_the_sandbox(monkeypatch):
    from safepatch.repository import registry
    monkeypatch.setenv("RUNNER_SANDBOX", "docker")
    monkeypatch.setattr(runner, "checkout", lambda *a: pytest.fail("refused before any checkout or build"))
    request = VerifyRequest(job_id="a" * 32, case_id="sql-01", base_commit=registry()[1]["sql-01"]["commit"], attempt=0,
                            deadline=time.time() + 60, scanner="sonarqube+semgrep")
    with pytest.raises(PolicyError, match="sonar_scan_needs_network_not_sandboxed"):
        runner.execute(request)


@pytest.mark.parametrize("failing", [None, "checkout", "outcome"])
def test_the_runner_removes_its_checkout_whatever_the_job_did(monkeypatch, tmp_path, failing):
    # A large project's checkout is 0.2+ GB per attempt; the main experiment left 2,700 behind (28 Oct 2026).
    monkeypatch.setenv("DATA_ROOT", str(tmp_path))
    monkeypatch.setattr(runner, "baseline", lambda *a: ({"spec": spec("safepatch-synthetic")}, {}))
    monkeypatch.setattr(runner, "sandbox_mode", lambda _: "native")
    seen = []

    def checkout(case_id, commit, workspace):
        pack = workspace / ".git" / "objects" / "pack" / "pack-1.pack"
        pack.parent.mkdir(parents=True)
        pack.write_bytes(b"PACK")
        os.chmod(pack, stat.S_IREAD)   # read-only, as Git may leave pack files on Windows
        seen.append(workspace)
        if failing == "checkout":
            raise RuntimeError("git_failed")

    def outcome(req, spec_, workspace, *rest):
        assert (workspace / ".git" / "objects" / "pack" / "pack-1.pack").is_file()
        if failing == "outcome":
            raise TimeoutError("child_timeout")
        return {"passed": False}
    monkeypatch.setattr(runner, "checkout", checkout)
    monkeypatch.setattr(runner, "outcome", outcome)
    request = VerifyRequest(job_id="a" * 32, case_id="sql-01", base_commit="b" * 40, attempt=0, deadline=time.time() + 60)
    if failing:
        with pytest.raises((RuntimeError, TimeoutError)):
            runner.execute(request)
    else:
        assert runner.execute(request) == {"passed": False}
    assert seen and not seen[0].exists() and list((tmp_path / "runner-work").iterdir()) == []


def test_a_file_that_cannot_be_removed_does_not_fail_the_job(monkeypatch, tmp_path):
    (tmp_path / "keep").mkdir()
    (tmp_path / "keep" / "locked.jar").write_bytes(b"PK")
    real = os.unlink

    def locked(path, *args, **kwargs):
        if str(path).endswith("locked.jar"):
            raise PermissionError("in use by another process")
        return real(path, *args, **kwargs)
    monkeypatch.setattr(runner.os, "unlink", locked)
    mode = stat.S_IMODE(os.stat(tmp_path / "keep").st_mode)
    runner.discard(tmp_path / "keep")
    runner.discard(tmp_path / "never-created")
    # The folder keeps its permissions (on Linux, write-only would make it unreadable; CI 30 Oct 2026).
    assert stat.S_IMODE(os.stat(tmp_path / "keep").st_mode) == mode
    assert (tmp_path / "keep" / "locked.jar").is_file()


docker = pytest.mark.skipif(os.environ.get("RUN_DOCKER_INTEGRATION") != "1" or not os.environ.get("SANDBOX_MAVEN_CACHE"),
                            reason="Run scripts/prepare_sandbox.py, then RUN_DOCKER_INTEGRATION=1 with SANDBOX_MAVEN_CACHE set")


@pytest.mark.integration
@docker
def test_findsecbugs_analyses_inside_the_sandbox(monkeypatch):
    # SpotBugs runs in the JDK 17 image with the tools mounted read-only; classes and classpath are the sandbox build's.
    from mock_patches import correct_patch
    from safepatch.repository import baseline, registry
    if not (runner.tools_dir() / "downloads" / runner.FINDSECBUGS_PLUGIN[0]).is_file():
        pytest.skip("Run scripts/prepare_findsecbugs.py first")
    monkeypatch.setenv("RUNNER_SANDBOX", "docker")
    commit = registry()[1]["sql-01"]["commit"]
    def verify(patch=None):
        return runner.execute(VerifyRequest(job_id=uuid.uuid4().hex, case_id="sql-01", base_commit=commit, attempt=1 if patch else 0,
                                            deadline=time.time() + 600, scanner="findsecbugs", patch=patch, target_file=SOURCE if patch else None))
    initial = verify()
    assert initial["baseline_valid"] and {f["rule_id"] for s in initial["scans"] for f in s["findings"]} >= {"SQL_INJECTION_JDBC"}
    _, files = baseline("sql-01", commit)
    assert verify(correct_patch("sql", files))["passed"]


@pytest.mark.integration
@docker
@pytest.mark.parametrize("kind", ["sql", "path", "command"])
def test_real_cases_build_and_verify_inside_the_sandbox(monkeypatch, kind):
    from mock_patches import correct_patch
    from safepatch.repository import baseline, registry
    monkeypatch.setenv("RUNNER_SANDBOX", "docker")
    case_id = kind + "-01"
    commit = registry()[1][case_id]["commit"]
    def verify(patch=None):
        return runner.execute(VerifyRequest(job_id=uuid.uuid4().hex, case_id=case_id, base_commit=commit, attempt=1 if patch else 0,
                                            deadline=time.time() + 600, scanner="builtin", patch=patch, target_file=SOURCE if patch else None))
    initial = verify()
    assert initial["baseline_valid"] and initial["runner_profile"] == "docker:" + runner.SANDBOX_IMAGE
    _, files = baseline(case_id, commit)
    fixed = verify(correct_patch(kind, files))
    assert fixed["passed"] and base64.b64decode(fixed["artifact_b64"])[:2] == b"PK"


@pytest.mark.integration
@docker
def test_the_sandbox_has_no_network(tmp_path):
    probe = "exec 3<>/dev/tcp/1.1.1.1/53 2>/dev/null && echo NETWORK_OPEN || echo NETWORK_BLOCKED"
    result = subprocess.run(runner.sandboxed(["bash", "-c", probe], Path(tmp_path), "safepatch-test-" + uuid.uuid4().hex[:8]),
                            capture_output=True, text=True, timeout=300)
    assert "NETWORK_BLOCKED" in result.stdout and "NETWORK_OPEN" not in result.stdout


def test_the_descriptor_java_version_picks_the_image(monkeypatch, tmp_path):
    monkeypatch.setenv("SANDBOX_MAVEN_CACHE", CACHE)
    monkeypatch.setattr(runner, "wsl_path", lambda path: "/mnt/c/ws")
    assert runner.sandboxed(["mvn"], tmp_path, "x", java="8")[-1] == runner.SANDBOX_IMAGES["8"]
    assert "eclipse-temurin-8@sha256:" in runner.SANDBOX_IMAGES["8"] and runner.profile("docker", "8") == "docker:" + runner.SANDBOX_IMAGES["8"]
    with pytest.raises(PolicyError, match="no_sandbox_image_for_java_11"):
        runner.sandboxed(["mvn"], tmp_path, "x", java="11")
    monkeypatch.setenv("SANDBOX_IMAGE_11", "maven:custom-11")
    assert runner.sandboxed(["mvn"], tmp_path, "x", java="11")[-1] == "maven:custom-11"
    monkeypatch.setenv("SANDBOX_IMAGE", "maven:custom-17")   # the old override still means JDK 17 only
    assert runner.sandbox_image("17") == "maven:custom-17" and runner.sandbox_image("8") == runner.SANDBOX_IMAGES["8"]


def known_spec(witness=True):
    known = [types.SimpleNamespace(id="VUL4J-79", file="src/main/java/A.java", line=1152, cwe="CWE-22", source="vul4j:VUL4J-79")]
    return types.SimpleNamespace(scan=types.SimpleNamespace(known=known), tests=types.SimpleNamespace(security=object() if witness else None))


@pytest.mark.parametrize("profile", [None, "product", "demo"])
def test_known_findings_are_only_for_lab_and_evaluation(monkeypatch, profile):
    if profile:
        monkeypatch.setenv("SAFEPATCH_PROFILE", profile)
    else:
        monkeypatch.delenv("SAFEPATCH_PROFILE", raising=False)
    with pytest.raises(PolicyError, match="known_findings_only_in_lab_profile"):
        runner.known_findings(known_spec(), "c" * 40, False)


def test_known_findings_come_from_the_answer_key_and_a_patch_is_judged_by_the_witness(monkeypatch):
    monkeypatch.setenv("SAFEPATCH_PROFILE", "evaluation")
    [report] = runner.known_findings(known_spec(), "c" * 40, False)
    [finding] = report["findings"]
    assert finding["rule_id"] == "known:VUL4J-79" and finding["cwe"] == "CWE-22" and finding["line"] == 1152 and report["status"] == "ok"
    assert runner.known_findings(known_spec(), "c" * 40, True)[0]["findings"] == []
    with pytest.raises(PolicyError, match="known_findings_need_answer_key_and_witness"):
        runner.known_findings(known_spec(witness=False), "c" * 40, False)


def test_known_mode_is_refused_before_any_checkout_in_the_product_profile(monkeypatch):
    from safepatch.repository import registry
    monkeypatch.delenv("SAFEPATCH_PROFILE", raising=False)
    # The product profile builds only in the sandbox (week 8); the known-mode check comes next.
    monkeypatch.setenv("RUNNER_SANDBOX", "docker")
    monkeypatch.setattr(runner, "checkout", lambda *a: pytest.fail("refused before any checkout or build"))
    request = VerifyRequest(job_id="a" * 32, case_id="sql-01", base_commit=registry()[1]["sql-01"]["commit"], attempt=0,
                            deadline=time.time() + 60, scanner="known")
    with pytest.raises(PolicyError, match="known_findings_only_in_lab_profile"):
        runner.execute(request)


def test_tests_of_a_module_select_it_and_read_its_reports(monkeypatch, tmp_path):
    from safepatch.project import Build, SuiteSelection
    reports = tmp_path / "util/target/surefire-reports"
    seen = {}
    def fake(workspace, args, deadline, **kwargs):
        seen["args"] = args
        reports.mkdir(parents=True)
        (reports / "TEST-x.xml").write_text('<testsuite tests="2" errors="0" failures="0" skipped="0"><testcase name="a"/><testcase name="b"/></testsuite>', encoding="utf-8")
        return {"exit_code": 0, "duration_seconds": 1, "output": ""}
    monkeypatch.setattr(runner, "maven", fake)
    result = runner.tests(tmp_path, SuiteSelection(selectors=["x.YTest"]), time.time() + 60, build=Build(module="util"))
    assert seen["args"] == ["-pl", "util", "-Dtest=x.YTest", "test"] and result["passed"] and result["tests"] == 2


def test_the_builds_plugin_skips_apply_to_the_test_runs(monkeypatch, tmp_path):
    # rdf4j: animal-sniffer is skipped in the package step and must be in the test step too.
    from safepatch.project import Build, SuiteSelection
    seen = {}
    monkeypatch.setattr(runner, "maven", lambda workspace, args, deadline, **kwargs: seen.update(args=args) or {"exit_code": 1, "duration_seconds": 1, "output": ""})
    build = Build(package_goals=["-DskipTests", "-Danimal.sniffer.skip=true", "package"], module="util")
    runner.tests(tmp_path, SuiteSelection(selectors=["x.YTest"]), time.time() + 60, build=build)
    assert seen["args"] == ["-pl", "util", "-Danimal.sniffer.skip=true", "-Dtest=x.YTest", "test"]


def staged_repo(tmp_path):
    """A committed git workspace as the runner leaves it before a build: an executable script, a
    package named target, an export-ignore attribute, a candidate SafePatch wrote with LF line
    endings where the checkout converts to CRLF, an uncommitted edit, an untracked hidden test
    and leftover build output."""
    def git(*args):
        subprocess.run(["git", "-C", str(ws), "-c", "core.autocrlf=false", *args], check=True, capture_output=True)

    ws = tmp_path / "ws-1"
    files = {".gitattributes": "docs/** export-ignore\n*.txt text eol=crlf\n", "src/run.sh": "echo hi\n",
             "src/A.java": "class A {}\n", "src/target/T.java": "class T {}\n", "docs/notes.md": "kept\n",
             "src/Candidate.txt": "fixed\nline\n", "src/Edited.java": "class Edited {}\n"}
    for name, content in files.items():
        (ws / name).parent.mkdir(parents=True, exist_ok=True)
        (ws / name).write_text(content, encoding="utf-8", newline="\n")
    git("init", "-q")
    git("add", ".")
    git("update-index", "--chmod=+x", "src/run.sh")
    git("-c", "user.name=t", "-c", "user.email=t@localhost", "commit", "-qm", "base")
    (ws / "src/Edited.java").write_text("class Edited { int x; }\n", encoding="utf-8")
    (ws / "src/test").mkdir()
    (ws / "src/test/HiddenTest.java").write_text("class HiddenTest {}\n", encoding="utf-8")
    for out in ("target/classes", "util/target/x"):
        (ws / out).mkdir(parents=True)
        (ws / out / "B.class").write_bytes(b"\0")
    return ws


def bounded(self, script, **kwargs):
    """Stands in for WSL where the work folder is its own mount (scripts/prepare_sandbox.py --bound-work-gb)."""
    assert script == "mountpoint -q /home/test/.safepatch/work", script
    return subprocess.CompletedProcess(script, 0, b"", b"")


def test_a_workspace_is_never_staged_on_an_unbounded_filesystem(monkeypatch, tmp_path):
    # Week 8: on the WSL root a build could fill the Windows drive behind it.
    monkeypatch.setenv("SANDBOX_MAVEN_CACHE", CACHE)
    scripts = []
    stage = runner.Stage(staged_repo(tmp_path))
    monkeypatch.setattr(runner.Stage, "shell", lambda self, script, **kw: scripts.append(script) or subprocess.CompletedProcess(script, 1, b"", b""))
    monkeypatch.setattr(runner.subprocess, "Popen", lambda *a, **k: pytest.fail("nothing is copied"))
    with pytest.raises(RuntimeError, match="sandbox_work_not_bounded"):
        stage.push()
    assert scripts == ["mountpoint -q /home/test/.safepatch/work"]


def test_a_stage_carries_the_working_tree_with_git_modes_and_without_build_output(monkeypatch, tmp_path):
    import io, tarfile
    monkeypatch.setenv("SANDBOX_MAVEN_CACHE", CACHE)
    sent, real = {}, subprocess.Popen

    class Pipe(io.BytesIO):
        def close(self):
            sent["tar"] = self.getvalue()

    class Process:
        """Stands in for the WSL tar process; git still runs for real."""

        def __new__(cls, argv, **kwargs):
            return super().__new__(cls) if argv[0] == "wsl" else real(argv, **kwargs)

        def __init__(self, argv, **kwargs):
            sent["argv"], self.stdin, self.returncode = argv, Pipe(), 0

        def wait(self, timeout=None):
            return 0

    workspace = staged_repo(tmp_path)
    monkeypatch.setattr(runner.subprocess, "Popen", Process)
    monkeypatch.setattr(runner.Stage, "shell", bounded)
    stage = runner.Stage(workspace)
    assert stage.path == "/home/test/.safepatch/work/ws-1"
    stage.push()
    archive = tarfile.open(fileobj=io.BytesIO(sent["tar"]))
    files = {m.name: m for m in archive.getmembers() if m.isfile()}
    assert files["src/run.sh"].mode == 0o755 and files["src/A.java"].mode == 0o644
    for name, member in files.items():
        assert archive.extractfile(member).read() == (workspace / name).read_bytes(), name
    assert set(files) == {".gitattributes", "src/run.sh", "src/A.java", "src/target/T.java", "docs/notes.md",
                          "src/Candidate.txt", "src/Edited.java", "src/test/HiddenTest.java"}
    assert "tar -x -C /home/test/.safepatch/work/ws-1" in sent["argv"][-1]


def test_a_deleted_tracked_file_is_refused(monkeypatch, tmp_path):
    monkeypatch.setenv("SANDBOX_MAVEN_CACHE", CACHE)
    monkeypatch.setattr(runner.Stage, "shell", bounded)
    workspace = staged_repo(tmp_path)
    (workspace / "src/A.java").unlink()
    with pytest.raises(RuntimeError, match="sandbox_stage_deleted_file"):
        runner.Stage(workspace).push()


def tar_of(entries):
    import io, tarfile
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, target in entries:
            info = tarfile.TarInfo(name)
            if target is None:
                info.size = 3
                archive.addfile(info, io.BytesIO(b"<x>"))
            else:
                info.type, info.linkname = tarfile.SYMTYPE, target
                archive.addfile(info)
    return buffer.getvalue()


def test_pulling_takes_only_the_requested_path(monkeypatch, tmp_path):
    monkeypatch.setenv("SANDBOX_MAVEN_CACHE", CACHE)
    stage = runner.Stage(tmp_path / "ws-2")
    output = tar_of([("target/surefire-reports/TEST-a.xml", None), ("src/A.java", None)])
    monkeypatch.setattr(stage, "shell", lambda script, **kw: subprocess.CompletedProcess(script, 0, output, b""))
    stage.pull("target/surefire-reports")
    assert (tmp_path / "ws-2/target/surefire-reports/TEST-a.xml").read_bytes() == b"<x>"
    assert not (tmp_path / "ws-2/src").exists()


@pytest.mark.parametrize("entries", [[("target/surefire-reports/x", "/etc/passwd")], [("target/surefire-reports/x", "../../../outside")]])
def test_pulled_output_cannot_point_outside_the_workspace(monkeypatch, tmp_path, entries):
    monkeypatch.setenv("SANDBOX_MAVEN_CACHE", CACHE)
    stage = runner.Stage(tmp_path / "ws-3")
    monkeypatch.setattr(stage, "shell", lambda script, **kw: subprocess.CompletedProcess(script, 0, tar_of(entries), b""))
    with pytest.raises(RuntimeError, match="sandbox_stage_output_refused"):
        stage.pull("target/surefire-reports")


def test_changed_files_are_hashed_only_while_still_regular_files(monkeypatch, tmp_path):
    monkeypatch.setenv("SANDBOX_MAVEN_CACHE", CACHE)
    stage = runner.Stage(tmp_path / "ws-4")
    pushed = {"./src/A.java": "a", "./pom.xml": "b", "./src/B.java": "c", "./src/C.java": "d"}
    manifest = "".join(f"{value * 64}  {name}\n" for name, value in pushed.items()).encode()
    hashed = []

    def shell(script, **kwargs):
        if script.startswith("cat "):
            return subprocess.CompletedProcess(script, 0, manifest, b"")
        if "find . -type f" in script:
            # pom.xml became a link or a pipe, C.java was replaced the same way, build output appeared.
            return subprocess.CompletedProcess(script, 0, b"./src/A.java\0./src/B.java\0./target/x.class\0", b"")
        hashed.append(kwargs["input"])
        return subprocess.CompletedProcess(script, 0, f"{'a' * 64}  ./src/A.java\n{'e' * 64}  ./src/B.java\n".encode(), b"")
    monkeypatch.setattr(stage, "shell", shell)
    assert stage.changed() == ["pom.xml", "src/B.java", "src/C.java"]
    # Only pushed files that are still regular files are read; a link or a pipe never is.
    assert hashed == [b"./src/A.java\0./src/B.java"]


def test_checksum_lines_with_escaped_names_are_read_back():
    output = b"a" * 64 + b"  ./plain.txt\n" + b"\\" + b"b" * 64 + b"  ./two\\nlines\\\\x\n"
    assert runner.sums(output) == {b"./plain.txt": b"a" * 64, b"./two\nlines\\x": b"b" * 64}


@pytest.mark.parametrize("operation", ["pull", "clear"])
def test_a_path_through_a_link_is_refused_before_anything_is_read_or_removed(monkeypatch, tmp_path, operation):
    monkeypatch.setenv("SANDBOX_MAVEN_CACHE", CACHE)
    stage = runner.Stage(tmp_path / "ws-6")
    scripts = []
    monkeypatch.setattr(stage, "shell", lambda script, **kw: scripts.append(script) or subprocess.CompletedProcess(script, 3, b"", b""))
    with pytest.raises(RuntimeError, match="sandbox_stage_link_refused"):
        getattr(stage, operation)("target/surefire-reports")
    check, _, command = scripts[0].partition(" || exit 3; ")
    assert '"$(realpath -m -- target/surefire-reports)" = "$(pwd -P)/"target/surefire-reports' in check
    assert command.startswith("rm -rf -- " if operation == "clear" else "if [ -e ")


posix_shell = pytest.mark.skipif(os.name != "posix" or not shutil.which("realpath"), reason="runs the stage's shell commands locally (Linux)")


@posix_shell
def test_a_build_cannot_lead_the_runner_through_links_or_pipes(monkeypatch, tmp_path):
    """The stage's own shell commands, run locally on what a hostile build leaves behind."""
    monkeypatch.setenv("SANDBOX_MAVEN_CACHE", CACHE)
    monkeypatch.setenv("SANDBOX_WORK", str(tmp_path / "work"))
    monkeypatch.setattr(runner, "wsl", lambda *argv: list(argv))
    stage = runner.Stage(tmp_path / "ws-7")
    root = Path(stage.path)
    outside = tmp_path / "host"
    (outside / "surefire-reports").mkdir(parents=True)
    (outside / "surefire-reports" / "TEST-secret.xml").write_text("<host/>")
    (outside / "secret.txt").write_text("host file")
    for name in ("src/A.java", "src/B.java", "pom.xml"):
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(name)
    subprocess.run(["sh", "-c", f"cd {root} && find . -type f -print0 | xargs -0 sha256sum > {root}.sha256"], check=True)
    (root / "src/A.java").unlink()
    (root / "src/A.java").symlink_to(outside / "secret.txt")
    (root / "pom.xml").unlink()
    os.mkfifo(root / "pom.xml")
    (root / "target").symlink_to(outside)
    started = time.time()
    assert stage.changed() == ["pom.xml", "src/A.java"] and time.time() - started < 30
    for operation in (stage.pull, stage.clear):
        with pytest.raises(RuntimeError, match="sandbox_stage_link_refused"):
            operation("target/surefire-reports")
    assert (outside / "surefire-reports" / "TEST-secret.xml").exists()
    assert not (tmp_path / "ws-7" / "target").exists()


@pytest.mark.parametrize("work", ["relative/work", "/home/x/work dir", "/home/x/$(id)"])
def test_the_stage_location_must_be_a_plain_absolute_path(monkeypatch, tmp_path, work):
    monkeypatch.setenv("SANDBOX_MAVEN_CACHE", CACHE)
    monkeypatch.setenv("SANDBOX_WORK", work)
    with pytest.raises(RuntimeError, match="sandbox_work_path_invalid"):
        runner.Stage(tmp_path / "ws-5")


# Week 8: the sandbox's settings read from a running container, and hostile builds through the
# real runner (scripts/sandbox_check.py, samples/hostile).
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import sandbox_check


@pytest.fixture(scope="module")
def hostile_projects(tmp_path_factory):
    return sandbox_check.prepare(tmp_path_factory.mktemp("hostile"))


def test_hostile_cases_never_build_natively(monkeypatch, hostile_projects):
    from safepatch.repository import project, registry
    monkeypatch.setenv("PROJECTS_DIR", str(hostile_projects))
    monkeypatch.setenv("RUNNER_SANDBOX", "native")
    monkeypatch.setenv("SAFEPATCH_PROFILE", "lab")
    for case in sandbox_check.CASES:
        case_id = "hostile-" + case
        with pytest.raises(PolicyError, match="sandbox_required_for_real_projects"):
            runner.sandbox_mode(project(case_id, registry()[1][case_id]["commit"]))


def test_the_control_run_drops_only_the_isolating_flags(monkeypatch, tmp_path):
    monkeypatch.setenv("SANDBOX_MAVEN_CACHE", CACHE)
    monkeypatch.setattr(runner, "wsl_path", lambda path: "/mnt/c/ws")
    weak = " ".join(sandbox_check.weakened(runner.sandboxed(["mvn", "test"], tmp_path, "safepatch-x")))
    for gone in ("--network none", "--read-only", "--cap-drop ALL", "no-new-privileges", "--user 1000:1000"):
        assert gone not in weak, gone
    for kept in ("--user 0:0", "--memory 2g --memory-swap 2g", "--pids-limit 1024", "--ulimit nofile=8192:8192", f"-v {CACHE}:/m2:ro"):
        assert kept in weak, kept


@pytest.fixture
def hostile(monkeypatch, hostile_projects):
    monkeypatch.setenv("PROJECTS_DIR", str(hostile_projects))
    monkeypatch.setenv("RUNNER_SANDBOX", "docker")
    return sandbox_check


@pytest.mark.integration
@docker
def test_the_settings_hold_inside_a_running_container():
    facts = sandbox_check.settings()["facts"]
    disk = sandbox_check.work_filesystem()
    # The staged workspace is its own filesystem, and the container sees only that one.
    assert disk["mount"] == disk["work"] and int(facts["workspace_size_kib"]) * 1024 <= disk["size_bytes"]
    assert (facts["uid"], facts["gid"], facts["CapEff"], facts["CapBnd"], facts["NoNewPrivs"], facts["Seccomp"]) == ("1000", "1000", "0" * 16, "0" * 16, "1", "2")
    assert facts["interfaces"] == "lo" and facts["docker_socket"] == "absent"
    assert (facts["memory.max"], facts["memory.swap.max"], facts["cpu.max"], facts["pids.max"]) == (str(2 * 2**30), "0", "200000 100000", "1024")
    assert (facts["write:/"], facts["write:/m2"], facts["write:/workspace"], facts["exec:/tmp"]) == ("no", "no", "yes", "no")
    assert (facts["ulimit:nofile"], facts["ulimit:core"], facts["ulimit:fsize_kib"]) == ("8192", "0", str(2**20))
    # Nothing secret reaches the build: only the image's own variables, HOME and MAVEN_OPTS.
    assert not any(word in facts["environment"] for word in ("TOKEN", "SECRET", "KEY", "PASSWORD"))


@pytest.mark.integration
@docker
def test_a_hostile_build_is_contained(hostile):
    row = hostile.run_case("hostile")
    assert row["outcome"] == "completed" and row["behavior"]["passed"] and row["behavior"]["tests"] == 10, row
    assert row["containers_left"] == []


@pytest.mark.integration
@docker
def test_the_hostile_suite_fails_without_isolation(hostile):
    # Without this, a passing hostile suite would prove nothing.
    weak = hostile.control()
    assert {"onlyTheLoopbackInterface", "noWritesOutsideTheWorkspace", "notRootAndWithoutPrivileges"} <= set(weak["failed"]), weak


@pytest.mark.integration
@docker
@pytest.mark.parametrize("case,error,reason", [("tamper", "PolicyError", "tracked_file_changed_during_execution"),
                                               ("link", "RuntimeError", "sandbox_stage_link_refused"),
                                               ("hang", "TimeoutError", "child_timeout")])
def test_a_hostile_build_is_refused_or_stopped(hostile, case, error, reason):
    row = hostile.run_case(case)
    assert (row["outcome"], row["error"], row["reason"]) == ("refused", error, reason), row
    assert row["seconds"] < 300 and row["containers_left"] == []
