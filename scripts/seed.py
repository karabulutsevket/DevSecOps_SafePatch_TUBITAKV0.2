"""Create ONLY owned synthetic repositories, with fixed author/date and no remotes."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from safepatch.project import ProjectSpec, synthetic_descriptor
SOURCE = "src/main/java/demo/DemoService.java"
AUTHOR = "BiGG Synthetic"
ENV = {**os.environ, "GIT_AUTHOR_DATE": "2026-09-11T00:00:00Z", "GIT_COMMITTER_DATE": "2026-09-11T00:00:00Z"}


def git(repo, *args):
    return subprocess.check_output(["git", "-c", "core.autocrlf=false", "-c", "core.hooksPath=/dev/null", *args], cwd=repo, env=ENV)


def expected_files(kind, number):
    """Every file of one synthetic case repository, as bytes: the seed's whole input."""
    case = f"{kind}-{number:02}"
    template = ROOT / "samples/template"
    files = {p.relative_to(template).as_posix(): p.read_bytes() for p in sorted(template.rglob("*")) if p.is_file()}
    source = (ROOT / f"samples/sources/{kind}.java").read_text(encoding="utf-8")
    source = source.replace("// Deliberately", f"// Case {case}.\n// Deliberately")
    if number == 2 and kind == "sql":
        source = source.replace("String sql", "String query").replace("executeQuery(sql)", "executeQuery(query)")
    if number == 3 and kind == "path":
        source = source.replace("target", "requested")
    if number == 2 and kind == "command":
        source = source.replace("command", "invocation")
    files[SOURCE] = source.encode("utf-8")
    for file in sorted((ROOT / f"samples/tests/{kind}").glob("*.java")):
        files["src/test/java/demo/" + file.name] = file.read_bytes()
    return files


def committed(repo, case):
    """Files at HEAD of an existing repository seeded by us; refuse anything else."""
    try:
        author, subject = git(repo, "log", "-1", "--format=%an%n%s").decode().splitlines()[:2]
    except (subprocess.CalledProcessError, ValueError):
        author = subject = None
    if (author, subject) != (AUTHOR, f"Synthetic vulnerable baseline {case}"):
        raise RuntimeError(f"{repo} exists and is not a SafePatch synthetic repository; move it away first")
    names = git(repo, "ls-tree", "-r", "--name-only", "HEAD").decode().splitlines()
    return {name: git(repo, "show", "HEAD:" + name) for name in names}


def writable(func, path, _):
    os.chmod(path, stat.S_IWRITE)   # Git marks pack files read-only on Windows
    func(path)


def seed(destination=None):
    destination = Path(destination or os.environ.get("REPO_ROOT") or ROOT / ".runtime/repos-v3")
    destination.mkdir(parents=True, exist_ok=True)
    manifest = {}
    for kind in ("sql", "path", "command"):
        for number in (1, 2, 3):
            case = f"{kind}-{number:02}"
            repo = destination / case
            expected = expected_files(kind, number)
            # Samples changed since this repository was seeded (e.g. a stronger witness): rebuild it.
            if repo.exists() and committed(repo, case) != expected:
                shutil.rmtree(repo, onexc=writable)
            if not repo.exists():
                for name, data in expected.items():
                    (repo / name).parent.mkdir(parents=True, exist_ok=True)
                    (repo / name).write_bytes(data)
                git(repo, "init", "-q")
                git(repo, "add", ".")
                git(repo, "-c", f"user.name={AUTHOR}", "-c", "user.email=synthetic@localhost", "commit", "-qm", f"Synthetic vulnerable baseline {case}")
            commit = git(repo, "rev-parse", "HEAD").decode().strip()
            tracked = git(repo, "ls-tree", "-r", "--name-only", commit).decode().splitlines()
            checksums = {p: hashlib.sha256(git(repo, "show", f"{commit}:{p}")).hexdigest() for p in tracked}
            manifest[case] = {"kind": kind, "split": "development" if number == 1 else "evaluation", "commit": commit, "files": checksums, "allowed": [SOURCE]}
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    # Project descriptors (safepatch-project/1) used by the pipeline (safepatch/repository.py).
    projects = Path(os.environ.get("PROJECTS_DIR") or destination.parent / "projects")
    projects.mkdir(parents=True, exist_ok=True)
    for case, entry in manifest.items():
        descriptor = synthetic_descriptor(case, entry, (destination / case).resolve())
        ProjectSpec.model_validate(descriptor)
        text = yaml.safe_dump(descriptor, sort_keys=False, allow_unicode=True)
        (projects / f"{case}.yml").write_text(text, encoding="utf-8", newline="\n")
    return manifest


if __name__ == "__main__":
    print(json.dumps(seed(), indent=2))
