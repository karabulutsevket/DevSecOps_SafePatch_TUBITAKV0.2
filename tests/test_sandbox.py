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
                 "--memory 2g", "--cpus 2", "--user 1000:1000", "--tmpfs /tmp:rw,size=1g", "--rm", "--name safepatch-x",
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
