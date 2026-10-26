"""Prepare further Vul4J evaluation cases (L3 only; ROADMAP.md week 6).

Like prepare_vul4j.py (VUL4J-79), per case in CASES:
1. Derived repository .runtime/l3/repos/<case> (bare): the vulnerable parent commit, files
   the fix added that the tests need (archives), and SafePatch's own witness test from
   l3/witness/<case>, as one root commit with a fixed identity and date.
2. Descriptor .runtime/l3/projects/<case>.yml (sandbox, known findings, witness, behaviour =
   every other test).
3. --prefetch (internet): Maven dependencies in a container with the network on; the
   project's test classes are compiled, never run. Surefire's JUnit provider is resolved by
   a probe project of our own pinned to the project's Surefire and JUnit versions.
The upstream clone (`git fetch --depth 2` of the fix) must exist in .runtime/l3/repos.
"""
import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from safepatch.project import ProjectSpec
from safepatch.runner import wsl
from prepare_vul4j import IDENTITY, L3, PROBE_TEST, git, maven_online, writable

CASES = {
    "vul4j-41": {
        "upstream": "plexus-archiver-upstream", "url": "https://github.com/codehaus-plexus/plexus-archiver.git",
        "parent": "97c0d97504632a2a80b7d847bccdd9b37d27aea1", "fix": "58bc24e465c0842981692adbf6d75680298989de",
        "from_fix": ["src/test/zips/zip-slip.zip"], "witness": "org.codehaus.plexus.archiver.SafePatchZipSlipWitnessTest",
        "target": "src/main/java/org/codehaus/plexus/archiver/AbstractUnArchiver.java",
        "sinks": ["final File f = FileUtils.resolveFile( dir, entryName );"], "cwe": "CWE-22", "kind": "path",
        "java": "8", "artifact": "target/plexus-archiver-3.6.0-SNAPSHOT.jar", "cve": "CVE-2018-1002200", "license": "Apache-2.0",
        "scope": "l3-plexus-archiver", "derived": "75078789042d2cd09685c8acc6a05f279e8a9441",
        # The repository's symbolic links become plain files in a checkout on Windows (no symlink
        # privilege), and the /mnt/c workspace keeps no permissions: these fail on any revision.
        "not_here": ["org.codehaus.plexus.archiver.SymlinkTest", "org.codehaus.plexus.archiver.zip.ZipArchiverTest#testSymlinkFileSet",
                     "org.codehaus.plexus.archiver.zip.ZipArchiverTest#testSymlinkZip", "org.codehaus.plexus.archiver.zip.ZipArchiverTest#testOveriddenPermissions",
                     # Skipped, and a skip fails a suite: module tests need JDK 9+, the other is @Ignore upstream.
                     "org.codehaus.plexus.archiver.jar.JarToolModularJarArchiverTest", "org.codehaus.plexus.archiver.zip.ConcurrentJarCreatorTest"],
    },
    "vul4j-43": {
        "upstream": "rdf4j-upstream", "url": "https://github.com/eclipse-rdf4j/rdf4j.git",
        "parent": "f63510ba14910fee4a5489f584fd2fd2da5b42e5", "fix": "df15a4d7a8f2789c043b27c9eafe1b30316cfa79",
        "from_fix": [], "witness": "org.eclipse.rdf4j.common.io.SafePatchZipSlipWitnessTest", "module": "util",
        "target": "util/src/main/java/org/eclipse/rdf4j/common/io/ZipUtil.java",
        "sinks": ["File outFile = new File(destDir, entry.getName());"], "cwe": "CWE-22", "kind": "path",
        "java": "8", "artifact": "util/target/rdf4j-util-2.5-SNAPSHOT.jar", "cve": "CVE-2018-20227", "license": "BSD-3-Clause",
        "scope": "l3-rdf4j", "skips": ["-Djapicmp.skip=true", "-Dformatter.skip=true"], "derived": "7bff111bc5256f8d290597476e89cb9b610c8089",
    },
}
# Surefire's default test class names. An exclusion alone ("!X") makes Surefire load every class
# in the test output, fixtures included (plexus-archiver ships compiled test classes as data).
DEFAULT_TESTS = ["Test*", "*Test", "*Tests", "*TestCase"]
# Build checks that are release or style steps, not compilation (Vul4J's command options).
SKIPS = ["-Denforcer.skip=true", "-Drat.skip=true", "-Danimal.sniffer.skip=true", "-Dcheckstyle.skip=true",
         "-Dmaven.javadoc.skip=true", "-Dmaven.source.skip=true", "-Dgpg.skip=true"]


def derive(case, spec):
    upstream, repo = L3 / "repos" / spec["upstream"], L3 / "repos" / case
    for commit in (spec["parent"], spec["fix"]):
        git(upstream, "cat-file", "-e", commit + "^{commit}")
    present = set(git(upstream, "ls-tree", "-r", "--name-only", spec["parent"]).decode().splitlines())
    owned = ROOT / "l3/witness" / case
    files = {p.relative_to(owned).as_posix(): p for p in sorted(owned.rglob("*")) if p.is_file()}
    if present & (set(files) | set(spec["from_fix"])):
        raise SystemExit(f"{case}: the parent already has a file this case adds")
    if repo.exists():
        shutil.rmtree(repo, onerror=writable)
    repo.parent.mkdir(parents=True, exist_ok=True)
    git(repo.parent, "init", "--quiet", "--bare", "--initial-branch=main", repo.name)
    git(repo, "fetch", "--quiet", "--no-tags", str(upstream.resolve()), spec["fix"])
    with tempfile.TemporaryDirectory(dir=L3) as scratch:
        env = {**os.environ, **IDENTITY, "GIT_INDEX_FILE": str(Path(scratch) / "index")}
        git(repo, "read-tree", spec["parent"], env=env)
        for path in spec["from_fix"]:
            mode, _, blob = git(repo, "ls-tree", spec["fix"], "--", path).decode().split("\t")[0].split()
            git(repo, "update-index", "--add", "--cacheinfo", f"{mode},{blob},{path}", env=env)
        for path, source in files.items():
            blob = git(repo, "hash-object", "-w", "--stdin", data=source.read_bytes()).decode().strip()
            git(repo, "update-index", "--add", "--cacheinfo", f"100644,{blob},{path}", env=env)
        tree = git(repo, "write-tree", env=env).decode().strip()
        message = f"{case.upper()} evaluation baseline: {spec['parent']} plus test archives from {spec['fix']} and the SafePatch witness\n"
        commit = git(repo, "commit-tree", tree, env=env, data=message.encode()).decode().strip()
    git(repo, "update-ref", "refs/heads/main", commit)
    (repo / "FETCH_HEAD").unlink(missing_ok=True)
    git(repo, "reflog", "expire", "--expire=now", "--all")
    git(repo, "gc", "--quiet", "--prune=now")
    if spec["derived"] and commit != spec["derived"]:
        raise SystemExit(f"{case}: derived commit {commit} differs from {spec['derived']}")
    return repo, commit


def descriptor(case, spec, repo, commit):
    text = git(L3 / "repos" / spec["upstream"], "show", f"{spec['parent']}:{spec['target']}").decode("utf-8")
    lines = [i for i, line in enumerate(text.splitlines(), 1) if line.strip() in spec["sinks"]]
    if len(lines) != len(spec["sinks"]):
        raise SystemExit(f"{case}: answer key out of date ({lines})")
    known = [{"id": f"{case.upper()}.{n}", "file": spec["target"], "line": line, "cwe": spec["cwe"], "source": f"vul4j:{case.upper()} ({spec['cve']})"}
             for n, line in enumerate(lines, 1)]
    module = spec.get("module")
    prefix = module + "/" if module else ""
    build = {"tool": "maven", "artifact": spec["artifact"], "package_goals": ["-DskipTests", *SKIPS, *spec.get("skips", []), "package"],
             **({"module": module} if module else {})}
    data = {"schema": "safepatch-project/1", "id": case, "scope": spec["scope"], "repository": {"path": str(repo), "commit": commit},
            "java": spec["java"], "build": build,
            "tests": {"behavior": {"selectors": [*DEFAULT_TESTS, "!" + spec["witness"], *("!" + t for t in spec.get("not_here", []))]}, "security": {"selectors": [spec["witness"]], "markers": ["PATH_TRAVERSAL_REGRESSION"]}},
            "editable": [prefix + "src/main/java/**/*.java"], "scan": {"paths": [prefix + "src/main/java"], "known": known},
            "limits": {"build_seconds": 900, "test_seconds": 900},
            "labels": {"kind": spec["kind"], "split": "evaluation", "source": "vul4j", "case": case.upper(), "cve": spec["cve"], "license": spec["license"]}}
    ProjectSpec.model_validate(data)
    path = L3 / "projects" / f"{case}.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return data, path


def versions(effective):
    """Surefire and JUnit versions from an effective POM."""
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    root = ET.parse(effective).getroot()
    surefire = next(p.findtext("m:version", namespaces=ns) for p in root.iterfind(".//m:build/m:plugins/m:plugin", ns)
                    if p.findtext("m:artifactId", namespaces=ns) == "maven-surefire-plugin")
    junit = next(d.findtext("m:version", namespaces=ns) for d in root.iterfind(".//m:dependencies/m:dependency", ns)
                 if d.findtext("m:artifactId", namespaces=ns) == "junit")
    return surefire, junit


PROBE = """<project xmlns="http://maven.apache.org/POM/4.0.0">
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
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>{junit}</version><scope>test</scope></dependency>
  </dependencies>
  <build><plugins><plugin><groupId>org.apache.maven.plugins</groupId><artifactId>maven-surefire-plugin</artifactId><version>{surefire}</version></plugin></plugins></build>
</project>
"""


def prefetch(repo, commit, data):
    with tempfile.TemporaryDirectory(dir=L3) as workspace:
        work = Path(workspace) / "ws"
        git(L3, "clone", "--quiet", "--no-checkout", str(repo), str(work))
        git(work, "checkout", "--quiet", "--detach", commit)
        reactor = ProjectSpec.model_validate(data).build.reactor()
        maven_online(work, [*reactor, *data["build"]["package_goals"]], data["java"])   # compiles the tests, runs none
        maven_online(work, [*reactor, "help:effective-pom", "-Doutput=/workspace/effective-pom.xml"], data["java"])
        surefire, junit = versions(work / "effective-pom.xml")
        print("surefire", surefire, "junit", junit, flush=True)
        probe = Path(workspace) / "probe"
        (probe / "src/test/java").mkdir(parents=True)
        (probe / "pom.xml").write_text(PROBE.format(junit=junit, surefire=surefire), encoding="utf-8")
        (probe / "src/test/java/ProbeTest.java").write_text(PROBE_TEST, encoding="utf-8")
        maven_online(probe, ["test"], data["java"])


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("cases", nargs="+", choices=sorted(CASES))
    parser.add_argument("--prefetch", action="store_true", help="download Maven dependencies into SANDBOX_MAVEN_CACHE (internet)")
    args = parser.parse_args()
    if args.prefetch and not os.environ.get("SANDBOX_MAVEN_CACHE"):
        home = subprocess.run(wsl("sh", "-c", 'printf %s "$HOME"'), capture_output=True, text=True).stdout.strip()
        os.environ["SANDBOX_MAVEN_CACHE"] = home + "/.safepatch/m2"
    for case in args.cases:
        spec = CASES[case]
        repo, commit = derive(case, spec)
        data, path = descriptor(case, spec, repo, commit)
        print(case, "commit:", commit, "descriptor:", path, flush=True)
        if args.prefetch:
            prefetch(repo, commit, data)


if __name__ == "__main__":
    main()
