"""Registered projects: trusted descriptors, Git-pinned baselines and candidate commits.

The descriptor (safepatch/project.py) is administrator configuration. Repository
content is untrusted data, read from the pinned commit; it never decides policy.
"""
from collections.abc import Mapping
import os
from pathlib import Path
import subprocess

from safepatch.common import ROOT, digest, safe_path, setting
from safepatch.policy import PolicyError
from safepatch.project import load_registry

# Fixed identity and dates make the candidate commit reproducible: the runner and the
# independent verifier must derive the same commit hash from the same patch.
CANDIDATE_ENV = {"GIT_AUTHOR_NAME": "SafePatch", "GIT_AUTHOR_EMAIL": "safepatch@localhost",
                 "GIT_COMMITTER_NAME": "SafePatch", "GIT_COMMITTER_EMAIL": "safepatch@localhost",
                 "GIT_AUTHOR_DATE": "2026-09-11T00:00:00Z", "GIT_COMMITTER_DATE": "2026-09-11T00:00:00Z"}


def run_git(repo, *args, env=None, timeout=60):
    """Git without hooks, fsmonitor, signing or line-ending conversion; trusts only `repo`."""
    command = ["git", "-c", "safe.directory=" + Path(repo).resolve().as_posix(), "-c", "core.hooksPath=/dev/null",
               "-c", "core.fsmonitor=false", "-c", "core.autocrlf=false", "-c", "commit.gpgsign=false", *args]
    result = subprocess.run(command, cwd=repo, env=env, timeout=timeout, capture_output=True)
    if result.returncode:
        raise RuntimeError("git_failed:" + args[0] + ":" + result.stderr.decode(errors="replace")[:200])
    return result.stdout


def projects_dir():
    return Path(setting("PROJECTS_DIR", str(ROOT / ".runtime/projects")))


def projects():
    return load_registry(projects_dir())


def registry():
    """Compatibility view for scripts and the case list: id -> commit, scope and lab labels."""
    return projects_dir(), {k: {"commit": s.repository.commit, "project": s.scope, "kind": s.labels.get("kind"), "split": s.labels.get("split")}
                            for k, s in projects().items()}


def project(case_id, commit):
    spec = projects().get(case_id)
    if spec is None or commit != spec.repository.commit:
        raise PolicyError("unregistered_repository_or_commit")
    return spec


class GitFiles(Mapping):
    """Tracked files of the pinned commit, read lazily. Only regular UTF-8 text is readable."""

    def __init__(self, repo, commit):
        self.repo, self.commit, self._text = Path(repo), commit, {}
        self._modes = {}
        for entry in run_git(self.repo, "ls-tree", "-r", "-z", commit).split(b"\0"):
            if entry:
                meta, name = entry.split(b"\t", 1)
                path = name.decode("utf-8", errors="replace")
                if safe_path(path):
                    self._modes[path] = meta.split()[0].decode()

    def raw(self, path):
        if path not in self._modes:
            raise KeyError(path)
        return run_git(self.repo, "show", f"{self.commit}:{path}")

    def __getitem__(self, path):
        if path not in self._text:
            if self._modes.get(path, "100644") != "100644":
                raise PolicyError("baseline_not_regular_file")
            try:
                self._text[path] = self.raw(path).decode("utf-8")
            except UnicodeDecodeError:
                raise PolicyError("baseline_not_text") from None
        return self._text[path]

    def __contains__(self, path):
        # Mapping's default would read (and may reject) the file just to test membership.
        return path in self._modes

    def __iter__(self):
        return iter(self._modes)

    def __len__(self):
        return len(self._modes)


def baseline(case_id, commit):
    """(case info, lazily read tracked files) for a registered project at its pinned commit."""
    spec = project(case_id, commit)
    repo = Path(spec.repository.path)
    try:
        run_git(repo, "cat-file", "-e", commit + "^{commit}", timeout=10)
    except RuntimeError:
        raise PolicyError("registered_commit_missing") from None
    case = {"kind": spec.labels.get("kind"), "split": spec.labels.get("split"), "project": spec.scope, "commit": commit, "spec": spec}
    return case, GitFiles(repo, commit)


def allowed_files(spec, files, target):
    """The finding's file, if the descriptor makes it editable (decision 5, 25 Oct 2026)."""
    return {target} if target and target in files and spec.is_editable(target) else set()


def checkout(case_id, commit, workspace):
    """Fresh working copy of the pinned commit; binary files and file modes are kept."""
    spec = project(case_id, commit)
    source = Path(spec.repository.path).resolve()
    workspace = Path(workspace)
    workspace.parent.mkdir(parents=True, exist_ok=True)
    run_git(workspace.parent, "-c", "safe.directory=" + source.as_posix(), "clone", "--quiet", "--no-hardlinks", "--no-checkout", str(source), str(workspace), timeout=300)
    run_git(workspace, "remote", "remove", "origin")
    run_git(workspace, "checkout", "--quiet", "--detach", commit, timeout=300)
    if run_git(workspace, "rev-parse", "HEAD").decode().strip() != commit:
        raise PolicyError("checkout_commit_mismatch")
    return spec


def commit_candidate(workspace, base_commit, edits, diff):
    """Write the patched files and commit them as a reproducible child of the real base commit."""
    for edit in edits:
        (Path(workspace) / edit.path).write_text(edit.content, encoding="utf-8", newline="\n")
    run_git(workspace, "add", "--", *[edit.path for edit in edits])
    run_git(workspace, "commit", "--quiet", "--no-verify", "-m", f"SafePatch candidate from {base_commit}; patch {digest(diff)}", env={**os.environ, **CANDIDATE_ENV})
    return run_git(workspace, "rev-parse", "HEAD").decode().strip()


def tracked_changes(workspace):
    """Tracked files that differ from HEAD; a build or test run must not change any."""
    status = run_git(workspace, "status", "--porcelain=v1", "-z", "--untracked-files=no").decode(errors="replace")
    return [entry[3:] for entry in status.split("\0") if entry]
