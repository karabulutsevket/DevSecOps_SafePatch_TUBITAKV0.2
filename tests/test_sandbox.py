"""Docker sandbox (roadmap weeks 5–6): project code is built and tested with no network,
a read-only root, no capabilities and a non-root user; real projects never build natively."""
import base64
import os
from pathlib import Path
import subprocess
import time
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
    assert runner.sandbox_mode(spec(source)) == expected


@pytest.mark.parametrize("mode", ["native", None])
def test_a_real_project_never_builds_natively(monkeypatch, mode):
    if mode:
        monkeypatch.setenv("RUNNER_SANDBOX", mode)
    else:
        monkeypatch.delenv("RUNNER_SANDBOX", raising=False)
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
                 "--memory 2g", "--cpus 2", "--user 1000:1000", "--tmpfs /tmp:rw,size=1g", "--tmpfs /jvmtmp:rw,size=512m", "--rm", "--name safepatch-x",
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


def test_changed_files_are_read_from_the_checksum_report(monkeypatch, tmp_path):
    monkeypatch.setenv("SANDBOX_MAVEN_CACHE", CACHE)
    stage = runner.Stage(tmp_path / "ws-4")
    report = "./src/A.java: FAILED\n./pom.xml: FAILED open or read\n"
    monkeypatch.setattr(stage, "shell", lambda script, **kw: subprocess.CompletedProcess(script, 0, report, ""))
    assert stage.changed() == ["src/A.java", "pom.xml"]


@pytest.mark.parametrize("work", ["relative/work", "/home/x/work dir", "/home/x/$(id)"])
def test_the_stage_location_must_be_a_plain_absolute_path(monkeypatch, tmp_path, work):
    monkeypatch.setenv("SANDBOX_MAVEN_CACHE", CACHE)
    monkeypatch.setenv("SANDBOX_WORK", work)
    with pytest.raises(RuntimeError, match="sandbox_work_path_invalid"):
        runner.Stage(tmp_path / "ws-5")
