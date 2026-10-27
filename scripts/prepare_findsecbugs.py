"""Prepare SpotBugs + FindSecBugs for the FindSecBugs adapter (ROADMAP.md week 7). Internet, once.

1. Downloads the pinned SpotBugs distribution and FindSecBugs plugin from Maven Central into
   .runtime/tools (not in Git), checks each against its pinned SHA-256 and unpacks SpotBugs.
2. Resolves maven-dependency-plugin into a fresh local repository, reports its size, and copies
   it into the offline Maven cache (MAVEN_CACHE): the adapter asks it for a project's classpath.
   Refuses to copy more than 20 MB (the approved estimate was 5-15 MB).
Then run scripts/prepare_sandbox.py, so the sandbox's cache gets the plugin too.
Licenses: SpotBugs LGPL-2.1, FindSecBugs LGPL-3.0, maven-dependency-plugin Apache-2.0; they run
as separate tools and are not redistributed (docs/LISANSLAR_VE_KAYNAKLAR.md).
"""
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from safepatch.common import setting

TOOLS = ROOT / ".runtime/tools"
CENTRAL = "https://repo1.maven.org/maven2/"
SPOTBUGS_VERSION = "4.9.8"
FINDSECBUGS_VERSION = "1.14.0"
DEPENDENCY_PLUGIN = "org.apache.maven.plugins:maven-dependency-plugin:3.8.1"
# SpotBugs: Maven Central's published SHA-256. FindSecBugs: Central publishes SHA-1 only
# (6cc9a0bbd3d1ff0920a1113bbcf0ed3782c91d23, checked on the first download); this SHA-256
# was computed from that verified file.
ARTIFACTS = {
    f"spotbugs-{SPOTBUGS_VERSION}.zip": (f"com/github/spotbugs/spotbugs/{SPOTBUGS_VERSION}/spotbugs-{SPOTBUGS_VERSION}.zip",
                                         "e13d476403cf69074f415e35ebcc2f865f7a1ea444c1e659516bc0260e74dfa5"),
    f"findsecbugs-plugin-{FINDSECBUGS_VERSION}.jar": (f"com/h3xstream/findsecbugs/findsecbugs-plugin/{FINDSECBUGS_VERSION}/findsecbugs-plugin-{FINDSECBUGS_VERSION}.jar",
                                                      "6fa340344fa433ff46c2985dab1010e8bc739f9395c983594a5240095e92abc8"),
}
LIMIT = 20 * 1024 * 1024
PROBE = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>safepatch.prefetch</groupId>
  <artifactId>dependency-plugin-probe</artifactId>
  <version>1</version>
</project>
"""


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def download(name, path, expected):
    target = TOOLS / "downloads" / name
    if not target.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(CENTRAL + path, timeout=300) as response, open(target.with_suffix(".part"), "wb") as out:
            shutil.copyfileobj(response, out)
        target.with_suffix(".part").replace(target)
    actual = sha256(target)
    if actual != expected:
        target.unlink()
        raise SystemExit(f"{name}: SHA-256 {actual} is not the pinned {expected}")
    print(f"{name}: {target.stat().st_size} bytes, SHA-256 ok", flush=True)
    return target


def unpack(archive, folder):
    """SpotBugs' zip into `folder`; every entry must stay inside it."""
    if folder.exists():
        return
    staging = Path(tempfile.mkdtemp(dir=TOOLS))
    with zipfile.ZipFile(archive) as zipped:
        for entry in zipped.namelist():
            if not (staging / entry).resolve().is_relative_to(staging.resolve()):
                raise SystemExit(f"unsafe entry in {archive.name}: {entry}")
        zipped.extractall(staging)
    (staging / f"spotbugs-{SPOTBUGS_VERSION}").replace(folder)
    shutil.rmtree(staging)


def dependency_plugin():
    cache = Path(setting("MAVEN_CACHE", ""))
    if not cache.is_dir():
        raise SystemExit("set MAVEN_CACHE to the offline Maven cache")
    with tempfile.TemporaryDirectory(dir=TOOLS) as scratch:
        repo, probe = Path(scratch) / "repo", Path(scratch) / "probe"
        probe.mkdir()
        (probe / "pom.xml").write_text(PROBE, encoding="utf-8")
        result = subprocess.run(["mvn", "-B", "-ntp", "-Dmaven.repo.local=" + str(repo), "-f", str(probe / "pom.xml"),
                                 DEPENDENCY_PLUGIN + ":build-classpath", "-Dmdep.outputFile=" + str(probe / "cp.txt")],
                                capture_output=True, text=True, timeout=1800, shell=sys.platform == "win32")
        if result.returncode:
            raise SystemExit("resolving the dependency plugin failed:\n" + result.stdout[-2000:])
        files = [p for p in repo.rglob("*") if p.is_file() and p.suffix not in (".lastUpdated",) and p.name != "_remote.repositories"]
        size = sum(p.stat().st_size for p in files)
        print(f"{DEPENDENCY_PLUGIN} and its dependencies: {len(files)} files, {size} bytes", flush=True)
        if size > LIMIT:
            raise SystemExit("more than 20 MB: not copied into the cache; ask before going on")
        added = 0
        for path in files:
            target = cache / path.relative_to(repo)
            if not target.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, target)
                added += 1
        print(f"copied {added} new files into {cache}", flush=True)


def main():
    archive = download(*next((n, *v) for n, v in ARTIFACTS.items() if n.endswith(".zip")))
    unpack(archive, TOOLS / f"spotbugs-{SPOTBUGS_VERSION}")
    download(*next((n, *v) for n, v in ARTIFACTS.items() if n.endswith(".jar")))
    dependency_plugin()
    print("SpotBugs:", TOOLS / f"spotbugs-{SPOTBUGS_VERSION}", "; FindSecBugs:", TOOLS / "downloads" / f"findsecbugs-plugin-{FINDSECBUGS_VERSION}.jar")


if __name__ == "__main__":
    main()
