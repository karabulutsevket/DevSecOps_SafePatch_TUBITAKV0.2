"""Prepare the first Vul4J evaluation case (L3 only; ROADMAP.md week 6, started in week 5).

VUL4J-79: zeroturnaround/zt-zip (Apache-2.0), CVE-2018-1002201, CWE-22 "Zip Slip".
Vul4J (tuhh-softsec/Vul4J, GPL-3.0) is only the case list; no code of it is used. Nothing here
enters samples/, the L2 packs, the product or Git: everything is written under .runtime/l3.

1. Derived repository .runtime/l3/repos/vul4j-79 (bare): the vulnerable parent commit plus the
   proof-of-vulnerability test and its two archives from the fix commit, as one root commit
   with a fixed identity and date, so its hash is reproducible.
2. Descriptor .runtime/l3/projects/vul4j-79.yml: JDK 8 sandbox, behaviour = every test except
   the witness, witness = the PoV test, findings from the answer key (known-finding mode).
3. --prefetch (internet, once; ~10-20 MB): downloads the Maven plugins and dependencies into the
   sandbox cache in a container that has the network but otherwise the sandbox's limits. It
   compiles and packages; it runs no project test.

Run with: PROJECTS_DIR=.runtime/l3/projects SAFEPATCH_PROFILE=evaluation RUNNER_SANDBOX=docker
"""
import argparse
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from safepatch.project import ProjectSpec
from safepatch.runner import sandboxed, wsl

UPSTREAM_URL = "https://github.com/zeroturnaround/zt-zip.git"
PARENT = "d1c40776d2ff18550d95db2609d3d154692dea93"   # vulnerable
FIX = "759b72f33bc8f4d69f84f09fcb7f010ad45d6fff"      # human fix, used only to verify the case
DERIVED = "57c32d5d78d13bdc8b3198436261d0edae1fd0da"  # reproducible: fixed tree, identity, date and message
POV = ("src/test/java/org/zeroturnaround/zip/DirectoryTraversalMaliciousTest.java",
       "src/test/resources/zip-malicious-traversal.zip", "src/test/resources/zip-malicious-traversal-backslashes.zip")
TARGET = "src/main/java/org/zeroturnaround/zip/ZipUtil.java"
WITNESS = "org.zeroturnaround.zip.DirectoryTraversalMaliciousTest"
# Needs an executable temp dir; the sandbox mounts every temp dir noexec and stays so.
EXCLUDED = ("org.zeroturnaround.zip.FilePermissionsTest#testPreserveExecuteFlag",)
# The four sinks the human fix guards, as (line in the parent, expected code). The PoV test
# exercises only the first two (unpack and BackslashUnpacker); see docs/OLCUM_VUL4J.md.
SINKS = ((1152, "File file = new File(outputDir, name);"), (1220, "File destFile = new File(parentDirectory, dirs[dirs.length - 1]);"),
         (1225, "File destFile = new File(outputDir, name);"), (1260, "File file = new File(outputDir, name);"))
IDENTITY = {"GIT_AUTHOR_NAME": "SafePatch L3", "GIT_AUTHOR_EMAIL": "l3@localhost", "GIT_AUTHOR_DATE": "2026-10-25T00:00:00Z",
            "GIT_COMMITTER_NAME": "SafePatch L3", "GIT_COMMITTER_EMAIL": "l3@localhost", "GIT_COMMITTER_DATE": "2026-10-25T00:00:00Z"}
MESSAGE = f"VUL4J-79 evaluation baseline: zt-zip {PARENT} plus the PoV test from {FIX}\n"
L3 = ROOT / ".runtime/l3"


def git(repo, *args, env=None, data=None):
    return subprocess.run(["git", "-c", "core.autocrlf=false", "-c", "core.hooksPath=/dev/null", *args], cwd=repo, env=env,
                          input=data, capture_output=True, check=True).stdout


def writable(func, path, _):
    os.chmod(path, stat.S_IWRITE)
    func(path)


def upstream_clone(path):
    if not path.exists():
        print("cloning", UPSTREAM_URL, flush=True)
        path.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--quiet", "--no-checkout", UPSTREAM_URL, str(path)], check=True)
    for commit in (PARENT, FIX):
        git(path, "cat-file", "-e", commit + "^{commit}")
    return path


def check_answer_key(upstream):
    lines = git(upstream, "show", f"{PARENT}:{TARGET}").decode("utf-8").splitlines()
    for number, code in SINKS:
        if lines[number - 1].strip() != code:
            raise SystemExit(f"answer key out of date: line {number} is {lines[number - 1].strip()!r}")
    present = set(git(upstream, "ls-tree", "-r", "--name-only", PARENT).decode().splitlines())
    if present & set(POV):
        raise SystemExit("the parent already has the PoV files")


def derive(upstream, repo):
    """One root commit: the parent's tree with the PoV files added. Upstream history is pruned."""
    if repo.exists():
        shutil.rmtree(repo, onerror=writable)
    repo.parent.mkdir(parents=True, exist_ok=True)
    git(repo.parent, "init", "--quiet", "--bare", "--initial-branch=main", repo.name)
    git(repo, "fetch", "--quiet", "--no-tags", str(upstream.resolve()), FIX)
    with tempfile.TemporaryDirectory(dir=L3) as scratch:
        env = {**os.environ, **IDENTITY, "GIT_INDEX_FILE": str(Path(scratch) / "index")}
        git(repo, "read-tree", PARENT, env=env)
        for path in POV:
            mode, _, blob = git(repo, "ls-tree", FIX, "--", path).decode().split("\t")[0].split()
            git(repo, "update-index", "--add", "--cacheinfo", f"{mode},{blob},{path}", env=env)
        tree = git(repo, "write-tree", env=env).decode().strip()
        commit = git(repo, "commit-tree", tree, env=env, data=MESSAGE.encode()).decode().strip()
    git(repo, "update-ref", "refs/heads/main", commit)
    (repo / "FETCH_HEAD").unlink(missing_ok=True)
    git(repo, "reflog", "expire", "--expire=now", "--all")
    git(repo, "gc", "--quiet", "--prune=now")
    if commit != DERIVED:
        raise SystemExit(f"derived commit {commit} differs from {DERIVED}")
    return commit


def descriptor(repo, commit):
    known = [{"id": f"VUL4J-79.{i}", "file": TARGET, "line": line, "cwe": "CWE-22", "source": "vul4j:VUL4J-79 (CVE-2018-1002201)"}
             for i, (line, _) in enumerate(SINKS, 1)]
    data = {"schema": "safepatch-project/1", "id": "vul4j-79", "scope": "l3-vul4j-zt-zip",
            "repository": {"path": str(repo), "commit": commit}, "java": "8",
            "build": {"tool": "maven", "artifact": "target/zt-zip-1.13-SNAPSHOT.jar",
                      # source, javadoc and gpg are release steps bound in the project's pom
                      "package_goals": ["-DskipTests", "-Dmaven.javadoc.skip=true", "-Dmaven.source.skip=true", "-Dgpg.skip=true", "package"]},
            "tests": {"behavior": {"selectors": ["!" + s for s in (WITNESS, *EXCLUDED)]}, "security": {"selectors": [WITNESS]}},
            "editable": ["src/main/java/**/*.java"], "scan": {"paths": ["src/main/java"], "known": known},
            "limits": {"build_seconds": 600, "test_seconds": 900},
            "labels": {"kind": "path", "split": "evaluation", "source": "vul4j", "case": "VUL4J-79", "cve": "CVE-2018-1002201", "license": "Apache-2.0"}}
    ProjectSpec.model_validate(data)
    path = L3 / "projects/vul4j-79.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return data, path


def online(argv):
    """The sandbox command with the network on and the cache writable; nothing else changes."""
    argv = list(argv)
    network = argv.index("--network")
    assert argv[network + 1] == "none"
    argv[network + 1] = "bridge"
    [cache] = [i for i, value in enumerate(argv) if value.endswith(":/m2:ro")]
    argv[cache] = argv[cache][:-3]
    return argv


# Surefire resolves its JUnit provider only when a test is selected, so a project of our own with
# one empty JUnit 4 test (same junit version, Surefire left at Maven's default like zt-zip's pom)
# resolves it. No zt-zip test runs while the network is on.
PROBE_POM = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>safepatch.prefetch</groupId>
  <artifactId>junit4-provider-probe</artifactId>
  <version>1</version>
  <properties>
    <maven.compiler.source>8</maven.compiler.source>
    <maven.compiler.target>8</maven.compiler.target>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  </properties>
  <dependencies>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.12</version><scope>test</scope></dependency>
  </dependencies>
</project>
"""
PROBE_TEST = "public class ProbeTest {\n  @org.junit.Test public void empty() {}\n}\n"


def maven_online(work, goals, java):
    flags = ["-B", "-ntp", "-Dstyle.color=never", "-Dmaven.repo.local=/m2"]
    name = "safepatch-prefetch-" + uuid.uuid4().hex[:8]
    result = subprocess.run(online(sandboxed(["mvn", *flags, *goals], work, name, java)), capture_output=True, text=True, timeout=1800)
    print("\n".join(line for line in result.stdout.splitlines() if "BUILD" in line or "Tests run:" in line), flush=True)
    if result.returncode:
        raise SystemExit("prefetch failed:\n" + result.stdout[-3000:] + result.stderr[-1000:])


def prefetch(repo, commit, spec):
    """Resolve what an offline build and test run need: zt-zip is compiled and packaged (its
    tests compiled, not run), then the probe project resolves the Surefire JUnit 4 provider."""
    with tempfile.TemporaryDirectory(dir=L3) as workspace:
        work = Path(workspace) / "ws"
        git(L3, "clone", "--quiet", "--no-checkout", str(repo), str(work))
        git(work, "checkout", "--quiet", "--detach", commit)
        maven_online(work, spec["build"]["package_goals"], spec["java"])
        probe = Path(workspace) / "probe"
        (probe / "src/test/java").mkdir(parents=True)
        (probe / "pom.xml").write_text(PROBE_POM, encoding="utf-8")
        (probe / "src/test/java/ProbeTest.java").write_text(PROBE_TEST, encoding="utf-8")
        maven_online(probe, ["test"], spec["java"])


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--upstream", type=Path, default=L3 / "repos/zt-zip-upstream")
    parser.add_argument("--prefetch", action="store_true", help="download Maven dependencies into SANDBOX_MAVEN_CACHE (internet)")
    args = parser.parse_args()
    upstream = upstream_clone(args.upstream)
    check_answer_key(upstream)
    repo = L3 / "repos/vul4j-79"
    commit = derive(upstream, repo)
    spec, path = descriptor(repo, commit)
    print("commit:", commit)
    print("descriptor:", path)
    if args.prefetch:
        if not os.environ.get("SANDBOX_MAVEN_CACHE"):
            home = subprocess.run(wsl("sh", "-c", 'printf %s "$HOME"'), capture_output=True, text=True).stdout.strip()
            os.environ["SANDBOX_MAVEN_CACHE"] = home + "/.safepatch/m2"
        prefetch(repo, commit, spec)
    print("run with:")
    print(f"  $env:PROJECTS_DIR = '{path.parent}'")
    print("  $env:SAFEPATCH_PROFILE = 'evaluation'; $env:RUNNER_SANDBOX = 'docker'")


if __name__ == "__main__":
    main()
