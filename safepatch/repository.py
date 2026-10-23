import json
import os
from pathlib import Path, PurePosixPath
import subprocess

from safepatch.common import ROOT, digest, setting
from safepatch.policy import PolicyError


def registry():
    root = Path(setting("REPO_ROOT", str(ROOT / ".runtime/repos-v3")))
    return root, json.loads((root / "manifest.json").read_text(encoding="utf-8"))


def baseline(case_id, commit):
    root, cases = registry()
    if case_id not in cases or commit != cases[case_id]["commit"]:
        raise PolicyError("unregistered_repository_or_commit")
    repo = root / case_id
    # Trust only the already registered synthetic repository for this invocation.
    # This supports a read-only mount owned by a different container UID; no global Git config.
    command = ["git", "-c", "safe.directory=" + repo.resolve().as_posix(), "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false"]
    files = {}
    for path, expected in cases[case_id]["files"].items():
        pure = PurePosixPath(path)
        if pure.is_absolute() or ".." in pure.parts or "\\" in path or ":" in path:
            raise PolicyError("unsafe_registry_path")
        data = subprocess.check_output(command + ["show", f"{commit}:{path}"], cwd=repo, timeout=10)
        mode = subprocess.check_output(command + ["ls-tree", commit, "--", path], cwd=repo, timeout=10).decode().split()[0]
        if mode != "100644" or digest(data) != expected:
            raise PolicyError("baseline_integrity_or_symlink")
        files[path] = data.decode("utf-8")
    return cases[case_id], files


def materialize(files, workspace):
    workspace.mkdir(parents=True, exist_ok=False)
    for name, content in files.items():
        target = workspace / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="\n")


def review_commit(workspace, base_commit, diff, case_id, original):
    # Reconstruct the exact root commit with deterministic metadata, then add a real child.
    patched = (workspace / "src/main/java/demo/DemoService.java").read_text(encoding="utf-8")
    env = {**os.environ, "GIT_AUTHOR_DATE": "2026-09-11T00:00:00Z", "GIT_COMMITTER_DATE": "2026-09-11T00:00:00Z"}
    def git(*args):
        return subprocess.check_output(["git", "-c", "core.autocrlf=false", "-c", "core.hooksPath=/dev/null", "-c", "user.name=BiGG Synthetic", "-c", "user.email=synthetic@localhost", *args], cwd=workspace, env=env, timeout=15).decode().strip()
    git("init", "-q")
    git("checkout", "-qb", "candidate")
    for name, content in original.items():
        (workspace / name).write_text(content, encoding="utf-8", newline="\n")
    git("add", "src", "pom.xml", ".gitignore")
    git("commit", "-qm", f"Synthetic vulnerable baseline {case_id}")
    if git("rev-parse", "HEAD") != base_commit:
        raise PolicyError("reconstructed_base_commit_mismatch")
    (workspace / "src/main/java/demo/DemoService.java").write_text(patched, encoding="utf-8", newline="\n")
    git("add", "src", "pom.xml", ".gitignore")
    git("commit", "-qm", f"Verified candidate from {base_commit}; patch {digest(diff)}")
    return git("rev-parse", "HEAD")
