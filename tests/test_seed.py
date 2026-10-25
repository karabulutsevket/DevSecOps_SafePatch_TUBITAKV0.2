"""The seeder rebuilds stale synthetic repositories and never deletes anything else."""
import importlib.util
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load_seed():
    spec = importlib.util.spec_from_file_location("seed_script", ROOT / "scripts/seed.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def commit_all(repo, author, subject):
    subprocess.check_call(["git", "-c", "user.name=" + author, "-c", "user.email=x@localhost", "-c", "core.hooksPath=/dev/null", "commit", "-qam", subject], cwd=repo)


def test_stale_repository_is_rebuilt_to_the_samples(tmp_path, monkeypatch):
    seed = load_seed()
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    first = seed.seed(tmp_path / "repos")
    repo = tmp_path / "repos/path-01"
    (repo / "src/test/java/demo/SecurityTest.java").write_text("class WeakerWitness {}\n")
    commit_all(repo, seed.AUTHOR, "Synthetic vulnerable baseline path-01")
    assert seed.seed(tmp_path / "repos") == first
    assert (repo / "src/test/java/demo/SecurityTest.java").read_bytes() == (ROOT / "samples/tests/path/SecurityTest.java").read_bytes()


@pytest.mark.parametrize("git_repo", [True, False])
def test_a_foreign_directory_is_never_deleted(tmp_path, monkeypatch, git_repo):
    seed = load_seed()
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    repo = tmp_path / "repos/sql-01"
    repo.mkdir(parents=True)
    (repo / "keep.txt").write_text("mine")
    if git_repo:
        subprocess.check_call(["git", "init", "-q"], cwd=repo)
        subprocess.check_call(["git", "add", "."], cwd=repo)
        commit_all(repo, "Someone Else", "Synthetic vulnerable baseline sql-01")
    with pytest.raises(RuntimeError, match="not a SafePatch synthetic repository"):
        seed.seed(tmp_path / "repos")
    assert (repo / "keep.txt").read_text() == "mine"
