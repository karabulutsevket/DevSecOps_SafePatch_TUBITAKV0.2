"""Create ONLY owned synthetic repositories, with fixed author/date and no remotes."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "src/main/java/demo/DemoService.java"


def seed(destination=None):
    destination = Path(destination or ROOT / ".runtime/repos-v3")
    destination.mkdir(parents=True, exist_ok=True)
    manifest = {}
    env = {**os.environ, "GIT_AUTHOR_DATE": "2026-09-11T00:00:00Z", "GIT_COMMITTER_DATE": "2026-09-11T00:00:00Z"}
    for kind in ("sql", "path", "command"):
        for number in (1, 2, 3):
            case = f"{kind}-{number:02}"
            repo = destination / case
            if not repo.exists():
                shutil.copytree(ROOT / "samples/template", repo)
                source = (ROOT / f"samples/sources/{kind}.java").read_text(encoding="utf-8")
                source = source.replace("// Deliberately", f"// Case {case}.\n// Deliberately")
                if number == 2 and kind == "sql":
                    source = source.replace("String sql", "String query").replace("executeQuery(sql)", "executeQuery(query)")
                if number == 3 and kind == "path":
                    source = source.replace("target", "requested")
                if number == 2 and kind == "command":
                    source = source.replace("command", "invocation")
                (repo / SOURCE).write_text(source, encoding="utf-8", newline="\n")
                tests = repo / "src/test/java/demo"
                tests.mkdir(parents=True)
                for file in (ROOT / f"samples/tests/{kind}").glob("*.java"):
                    shutil.copyfile(file, tests / file.name)
                def git(*args):
                    return subprocess.check_output(["git", "-c", "core.autocrlf=false", "-c", "core.hooksPath=/dev/null", *args], cwd=repo, env=env).decode().strip()
                git("init", "-q")
                git("add", ".")
                git("-c", "user.name=BiGG Synthetic", "-c", "user.email=synthetic@localhost", "commit", "-qm", f"Synthetic vulnerable baseline {case}")
            commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo).decode().strip()
            tracked = subprocess.check_output(["git", "ls-tree", "-r", "--name-only", commit], cwd=repo).decode().splitlines()
            checksums = {p: hashlib.sha256(subprocess.check_output(["git", "show", f"{commit}:{p}"], cwd=repo)).hexdigest() for p in tracked}
            manifest[case] = {"kind": kind, "split": "development" if number == 1 else "evaluation", "commit": commit, "files": checksums, "allowed": [SOURCE]}
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


if __name__ == "__main__":
    print(json.dumps(seed(), indent=2))
