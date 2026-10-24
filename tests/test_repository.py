import subprocess
import types

import pytest
import yaml

from safepatch.policy import PolicyError
from safepatch.repository import allowed_files, baseline, checkout, commit_candidate, registry, tracked_changes

SERVICE = "src/main/java/org/x/Service.java"
LOGO = b"\x89PNG\x00\xff\xfe"


def git(repo, *args):
    command = ["git", "-c", "user.name=Test", "-c", "user.email=test@localhost", "-c", "core.autocrlf=false", "-c", "commit.gpgsign=false", *args]
    return subprocess.check_output(command, cwd=repo).decode().strip()


@pytest.fixture
def real_like(tmp_path, monkeypatch):
    """A small repository shaped like a real project: packages, tests, a binary file, history."""
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    (repo / "pom.xml").write_text("<project/>\n", encoding="utf-8", newline="\n")
    for path in (SERVICE, "src/main/java/org/x/Helper.java", "src/main/java/org/y/Other.java", "src/test/java/org/x/ServiceTest.java"):
        file = repo / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(f"class {file.stem} {{}}\n", encoding="utf-8", newline="\n")
    (repo / "src/main/resources").mkdir(parents=True)
    (repo / "src/main/resources/logo.png").write_bytes(LOGO)
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "first")
    (repo / SERVICE).write_text('class Service { String v = "vulnerable"; }\n', encoding="utf-8", newline="\n")
    git(repo, "commit", "-qam", "second")
    commit = git(repo, "rev-parse", "HEAD")
    projects = tmp_path / "projects"
    projects.mkdir()
    descriptor = {"schema": "safepatch-project/1", "id": "real-like", "scope": "lab", "repository": {"path": str(repo), "commit": commit},
                  "java": "17", "tests": {"behavior": {"selectors": ["org.x.ServiceTest"]}},
                  "editable": ["src/main/java/**/*.java"], "scan": {"paths": ["src/main/java"]}}
    (projects / "real-like.yml").write_text(yaml.safe_dump(descriptor), encoding="utf-8", newline="\n")
    monkeypatch.setenv("PROJECTS_DIR", str(projects))
    return repo, commit


def test_registry_view_comes_from_descriptors(real_like):
    _, commit = real_like
    assert registry()[1] == {"real-like": {"commit": commit, "project": "lab", "kind": None, "split": None}}


def test_baseline_reads_text_lazily_and_refuses_binary_as_text(real_like):
    _, commit = real_like
    case, files = baseline("real-like", commit)
    assert case["kind"] is None and case["spec"].scope == "lab"
    assert files[SERVICE] == 'class Service { String v = "vulnerable"; }\n'
    assert "src/main/resources/logo.png" in files
    with pytest.raises(PolicyError, match="baseline_not_text"):
        files["src/main/resources/logo.png"]
    assert files.raw("src/main/resources/logo.png") == LOGO


def test_unregistered_project_or_commit_is_refused(real_like):
    _, commit = real_like
    with pytest.raises(PolicyError, match="unregistered"):
        baseline("real-like", "0" * 40)
    with pytest.raises(PolicyError, match="unregistered"):
        baseline("unknown", commit)


def test_candidate_is_a_reproducible_child_of_the_real_history(real_like, tmp_path):
    _, commit = real_like
    edit = types.SimpleNamespace(path=SERVICE, content='class Service { String v = "fixed"; }\n')
    heads = []
    for name in ("runner", "verifier"):
        workspace = tmp_path / name
        checkout("real-like", commit, workspace)
        assert (workspace / "src/main/resources/logo.png").read_bytes() == LOGO
        heads.append(commit_candidate(workspace, commit, [edit], "diff"))
        assert git(workspace, "rev-parse", "HEAD^") == commit
        assert git(workspace, "remote") == ""
        assert tracked_changes(workspace) == []
    assert heads[0] == heads[1]
    (workspace / "pom.xml").write_text("<changed/>\n", encoding="utf-8", newline="\n")
    assert tracked_changes(workspace) == ["pom.xml"]


@pytest.mark.parametrize("target", ["src/test/java/org/x/ServiceTest.java", "pom.xml", "src/main/java/org/x/Missing.java", "../x.java", None])
def test_only_the_editable_finding_file_is_allowed(real_like, target):
    _, commit = real_like
    case, files = baseline("real-like", commit)
    assert allowed_files(case["spec"], files, SERVICE) == {SERVICE}
    assert allowed_files(case["spec"], files, target) == set()
