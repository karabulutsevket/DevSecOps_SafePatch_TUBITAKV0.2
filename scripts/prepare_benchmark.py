"""Prepare OWASP Benchmark evaluation cases (L3 only; ROADMAP.md week 6).

OWASP Benchmark (OWASP-Benchmark/BenchmarkJava, GPL-2.0) is one project, so every case is
evaluation. A case is one test-case servlet; its known finding comes from Benchmark's
expected results. A "false" case simulates a scanner false positive: nothing can be
exploited, so the witness passes on the original code, the baseline is not valid and the
job returns to a human, which is what a safe case asks for. Benchmark ships no exploit
tests: SafePatch's witness (l3/benchmark, WitnessSupport) runs the servlet in-process with
an input that climbs out of its file area and checks the effects.

Steps (sandbox: SANDBOX_MAVEN_CACHE set, Docker running):
  --record   derives a repository with a recorder test and runs it once offline: per sampled
             case the effects of two climbs and the SHA-256 of the answers to two benign
             inputs, each twice. Writes l3/benchmark/recorded.json (digests and effects only).
  (default)  generates the witness, behaviour and hidden tests from the sample and the
             recording (l3/witness/owasp-benchmark, l3/hidden/owasp-benchmark), derives the
             evaluation repository, writes the descriptors and the catalog block. HiddenSupport
             (l3/benchmark/hidden) goes with the hidden tests only, never into that repository.
  --check    runs every generated witness and behaviour test once on the original code and
             writes owasp-benchmark-check.json to EVIDENCE_DIR.
The sample is drawn once with a fixed seed; a sampled case that does not work is excluded
with its reason, never replaced by another draw.
"""
import argparse
import csv
import json
import os
from pathlib import Path
import random
import re
import shutil
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from safepatch import runner
from safepatch.common import evidence, setting
from safepatch.project import ProjectSpec
from prepare_l3 import SKIPS, derive
from prepare_vul4j import L3, git, maven_online

SNAPSHOT = "acc50f20ec449e2b977a7c409fa8175491657cba"
# Reproducible from the snapshot, the sample and recorded.json (the answers are deterministic).
DERIVED = "8bd5841cf9c0a8d0f8ce85c2649c497bc0b70e6e"
UPSTREAM = "benchmark-upstream"
SEED = 20261026
SAMPLE = {"pathtraver": {"true": 10, "false": 5}, "sqli": {"true": 10, "false": 5}, "cmdi": {"true": 10, "false": 5}}
# Per category: the witness call, the hidden attack, two benign answers ({cls}, {name} filled in),
# and the sink the known finding points at.
CATEGORY = {
    "pathtraver": {"cwe": "CWE-22", "kind": "path", "marker": "PATH_TRAVERSAL_REGRESSION",
                   "witness": 'WitnessSupport.traversal({cls}, "{name}")', "attack": 'WitnessSupport.nested({cls}, "{name}")',
                   "benign": 'WitnessSupport.benign({cls}, "{name}", WitnessSupport.BENIGN)', "benign2": 'WitnessSupport.benign({cls}, "{name}", WitnessSupport.DOTS)',
                   "sink": r"java\.io\.File(Input|Output)Stream|java\.io\.File\(|new File\(|java\.nio\.file\.Files\.|FileReader|FileWriter|RandomAccessFile|Paths\.get"},
    "sqli": {"cwe": "CWE-89", "kind": "sql", "marker": "SQL_INJECTION_REGRESSION",
             "witness": 'WitnessSupport.sqlInjection({cls}, "{name}")', "attack": 'WitnessSupport.sqlHidden({cls}, "{name}")',
             "benign": 'WitnessSupport.sqlAnswer({cls}, "{name}", "bar")', "benign2": 'HiddenSupport.sqlAnswer({cls}, "{name}", "User01")',
             "sink": r"executeQuery|executeUpdate|\.execute\(|addBatch|prepareStatement|prepareCall|JDBCtemplate\.|createQuery|createSQLQuery"},
    "cmdi": {"cwe": "CWE-78", "kind": "command", "marker": "COMMAND_INJECTION_REGRESSION",
             "witness": 'WitnessSupport.commandInjection({cls}, "{name}")', "attack": 'WitnessSupport.commandHidden({cls}, "{name}")',
             "benign": 'WitnessSupport.commandAnswer({cls}, "{name}", "safepatch")', "benign2": 'WitnessSupport.commandAnswer({cls}, "{name}", "hello world")',
             "sink": r"\.exec\(|new ProcessBuilder|\.command\(|\.start\(\)"},
}
PACKAGE = "org/owasp/benchmark/safepatch"
SUPPORT = ROOT / "l3/benchmark/src/test/java" / PACKAGE / "WitnessSupport.java"
RECORDED = ROOT / "l3/benchmark/recorded.json"
WITNESS = ROOT / "l3/witness/owasp-benchmark"
HIDDEN = ROOT / "l3/hidden/owasp-benchmark"
# Benchmark formats its sources while building (spotless:apply, ratcheting from origin/master):
# a build must never rewrite the code it verifies, so the formatter is off.
SPOTLESS = ["-Dspotless.skip=true", "-Dspotless.apply.skip=true", "-Dspotless.check.skip=true"]
GOALS = ["-DskipTests", *SKIPS, *SPOTLESS, "package"]
SPEC = {"upstream": UPSTREAM, "parent": SNAPSHOT, "fix": SNAPSHOT, "from_fix": [], "derived": None}


def number(name):
    return name[len("BenchmarkTest"):]


def source_path(name):
    return f"src/main/java/org/owasp/benchmark/testcode/{name}.java"


def sample():
    """{category: [(name, real)]}: a seeded draw per category and label, in name order."""
    rows = [r for r in csv.reader((L3 / "repos" / UPSTREAM / "expectedresults-1.2.csv").open(encoding="utf-8")) if r and not r[0].startswith("#")]
    rng, drawn = random.Random(SEED), {}
    for category, sizes in SAMPLE.items():
        picked = []
        for real, size in sizes.items():
            names = sorted(r[0] for r in rows if r[1] == category and r[2].strip() == real)
            picked += [(name, real == "true") for name in rng.sample(names, size)]
        drawn[category] = sorted(picked)
    return drawn


def java(template, **values):
    for key, value in values.items():
        template = template.replace("{" + key + "}", value)
    return template.encode("utf-8")


RECORDER = """package org.owasp.benchmark.safepatch;

import org.junit.jupiter.api.Test;

/** SafePatch L3 recorder (MIT): effects and benign answers of the original Benchmark code. */
class SafePatchRecorder {

  interface Call {
    String call() throws Exception;
  }

  static String safe(Call call) {
    try {
      return call.call();
    }
    catch (Throwable e) {
      StringBuilder chain = new StringBuilder("error:");
      for (Throwable t = e; t != null; t = t.getCause()) {
        chain.append(' ').append(t.getClass().getName()).append(": ").append(t.getMessage());
      }
      return chain.toString().replace('\\n', ' ');
    }
  }

  static void add(StringBuilder out, String name, String... values) {
    String[] keys = { "visible", "nested", "benign_1", "benign_2", "dots_1", "dots_2" };
    out.append(out.length() == 1 ? "" : ",").append("{\\"case\\":\\"").append(name).append("\\"");
    for (int k = 0; k < keys.length; k++) {
      out.append(",\\"").append(keys[k]).append("\\":\\"").append(values[k].replace("\\\\", "/").replace("\\"", "'")).append("\\"");
    }
    out.append("}");
  }

  @Test
  void record() throws Exception {
    StringBuilder out = new StringBuilder("[");
{blocks}
    java.nio.file.Files.write(java.nio.file.Paths.get("target", "safepatch-record.json"), out.append("]").toString().getBytes("UTF-8"));
  }
}
"""

RECORD_BLOCK = """    add(out, "{name}", safe(() -> {witness}), safe(() -> {attack}), safe(() -> {benign}), safe(() -> {benign}),
        safe(() -> {benign2}), safe(() -> {benign2}));
"""

WITNESS_TEST = """package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 witness for OWASP Benchmark {name} (generated by scripts/prepare_benchmark.py, MIT). */
class SafePatchWitness{n} {

  @Test
  void attackHasNoEffect() throws Exception {
    assertEquals("", {witness}, "{marker}");
  }
}
"""

BEHAVIOR_TEST = """package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 behaviour test for OWASP Benchmark {name} (generated, MIT): a benign input answers as in the original code. */
class SafePatchBehavior{n} {

  @Test
  void benignInputAnswersAsBefore() throws Exception {
    assertEquals("{digest}", {benign}, "BEHAVIOR_REGRESSION");
  }
}
"""

HIDDEN_TEST = """package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 hidden evaluation test for OWASP Benchmark {name} (generated, MIT); the verifier never runs it. */
class SafePatchHidden{n} {
{attack_test}
  @Test
  void anotherBenignInputAnswersAsBefore() throws Exception {
    assertEquals("{dots}", {benign2}, "HIDDEN_BEHAVIOR");
  }
}
"""

ATTACK_TEST = """
  @Test
  void hiddenAttackHasNoEffect() throws Exception {
    assertEquals("", {attack}, "HIDDEN_ATTACK");
  }
"""


def calls(category, name):
    """The category's Java calls for one case."""
    cls = f"org.owasp.benchmark.testcode.{name}.class"
    return {key: CATEGORY[category][key].replace("{cls}", cls).replace("{name}", name) for key in ("witness", "attack", "benign", "benign2")}


def support_files():
    """WitnessSupport and the servlet message bundles javaee-api leaves out (l3/benchmark/src)."""
    base = ROOT / "l3/benchmark"
    return {p.relative_to(base).as_posix(): p.read_bytes() for p in sorted((base / "src").rglob("*")) if p.is_file()}


def hidden_support_files():
    """HiddenSupport (l3/benchmark/hidden): with the hidden tests and the recorder, not the verifier's tests."""
    base = ROOT / "l3/benchmark/hidden"
    return {p.relative_to(base).as_posix(): p.read_bytes() for p in sorted(base.rglob("*")) if p.is_file()}


def sandbox_run(repo, commit, goals, java_version="17", extra=None, outputs=("target/surefire-reports",)):
    """Clone, add `extra` files ({path: bytes}), run Maven offline in the sandbox from a WSL-disk
    stage and bring back `outputs`; returns (workspace, result) and the caller removes the workspace."""
    workspace = Path(tempfile.mkdtemp(dir=L3))
    work = workspace / "ws"
    git(L3, "clone", "--quiet", "--no-checkout", str(repo), str(work))
    git(work, "checkout", "--quiet", "--detach", commit)
    for path, data in (extra or {}).items():
        (work / path).parent.mkdir(parents=True, exist_ok=True)
        (work / path).write_bytes(data)
    stage = runner.Stage(work)
    try:
        stage.push()
        result = runner.maven(work, goals, time.time() + 3600, limit=3600, sandbox="docker", java=java_version, stage=stage)
        for output in outputs:
            stage.pull(output)
    finally:
        stage.remove()
    return workspace, result


def record(drawn):
    blocks = "".join(java(RECORD_BLOCK, name=name, **calls(category, name)).decode() for category, cases in drawn.items() for name, _ in cases)
    recorder = java(RECORDER, blocks=blocks.rstrip("\n"))
    files = {**support_files(), **hidden_support_files(), "src/test/java/" + PACKAGE + "/SafePatchRecorder.java": recorder}
    repo, commit = derive("owasp-benchmark-record", {**SPEC, "message": "OWASP Benchmark recording: SafePatch recorder over the sample\n"}, files)
    workspace, result = sandbox_run(repo, commit, [*SKIPS, *SPOTLESS, "-Dtest=org.owasp.benchmark.safepatch.SafePatchRecorder", "test"],
                                    outputs=("target/safepatch-record.json", "target/surefire-reports"))
    try:
        out = workspace / "ws/target/safepatch-record.json"
        (L3 / "benchmark-record.log").write_text(result["output"], encoding="utf-8")   # Benchmark's own messages, for diagnosis
        if not out.exists():
            log = L3 / "benchmark-record-failure"
            shutil.rmtree(log, ignore_errors=True)
            log.mkdir()
            (log / "maven.log").write_text(result["output"], encoding="utf-8")
            if (workspace / "ws/target/surefire-reports").exists():
                shutil.copytree(workspace / "ws/target/surefire-reports", log / "surefire-reports")
            raise SystemExit(f"recording failed; Maven output and reports in {log}")
        rows = json.loads(out.read_text(encoding="utf-8"))
    finally:
        shutil.rmtree(workspace, ignore_errors=True)
    data = {"snapshot": SNAPSHOT, "seed": SEED, "sample": {c: [[n, real] for n, real in cases] for c, cases in drawn.items()},
            "cases": {r.pop("case"): r for r in rows}}
    RECORDED.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("recorded", len(rows), "cases:", RECORDED)


def verdict(real, row):
    """(usable, reason): what the recording says about a sampled case."""
    if any(v.startswith("error") for v in row.values()):
        return False, "the original code failed under the witness harness: " + row["visible"]
    if row["benign_1"] != row["benign_2"] or row["dots_1"] != row["dots_2"]:
        return False, "the answer to a benign input changes from run to run, so no behaviour test can compare it"
    if real and not row["visible"]:
        return False, "Benchmark marks it vulnerable, but no input shape had an observable effect in the original code"
    if not real and row["visible"]:
        return False, "Benchmark marks it safe, yet an input had an effect in the original code: " + row["visible"]
    return True, None


def generate(recorded):
    """Witness, behaviour and hidden tests from the recording; returns {case: (name, real, usable, reason)}."""
    for folder in (WITNESS, HIDDEN):
        if folder.exists():
            shutil.rmtree(folder)
    cases = {}
    for category, sampled in recorded["sample"].items():
        marker = CATEGORY[category]["marker"]
        for name, real in sampled:
            row = recorded["cases"][name]
            usable, reason = verdict(real, row)
            cases[name] = (category, real, usable, reason)
            if not usable:
                continue
            n = number(name)
            out = WITNESS / "src/test/java" / PACKAGE
            out.mkdir(parents=True, exist_ok=True)
            call = calls(category, name)
            (out / f"SafePatchWitness{n}.java").write_bytes(java(WITNESS_TEST, name=name, n=n, marker=marker, witness=call["witness"]))
            (out / f"SafePatchBehavior{n}.java").write_bytes(java(BEHAVIOR_TEST, name=name, n=n, digest=row["benign_1"], benign=call["benign"]))
            # A hidden security test must fail on the original code to measure anything.
            attack = java(ATTACK_TEST, attack=call["attack"]).decode() if real and row["nested"] else ""
            hidden = HIDDEN / "src/test/java" / PACKAGE
            hidden.mkdir(parents=True, exist_ok=True)
            (hidden / f"SafePatchHidden{n}.java").write_bytes(java(HIDDEN_TEST, name=name, n=n, dots=row["dots_1"], benign2=call["benign2"], attack_test=attack))
    for folder, files in ((WITNESS, support_files()), (HIDDEN, hidden_support_files())):
        for path, data in files.items():
            (folder / path).parent.mkdir(parents=True, exist_ok=True)
            (folder / path).write_bytes(data)
    return cases


def descriptors(cases, repo, commit):
    folder = L3 / "projects"
    folder.mkdir(parents=True, exist_ok=True)
    for old in folder.glob("owasp-benchmark-*.yml"):
        old.unlink()
    for name, (category, real, usable, _) in cases.items():
        if not usable:
            continue
        n, path = number(name), source_path(name)
        text = git(L3 / "repos" / UPSTREAM, "show", f"{SNAPSHOT}:{path}").decode("utf-8")
        line = next(i for i, l in enumerate(text.splitlines(), 1) if re.search(CATEGORY[category]["sink"], l))
        data = {"schema": "safepatch-project/1", "id": f"owasp-benchmark-{n}", "scope": "l3-owasp-benchmark",
                "repository": {"path": str(repo), "commit": commit}, "java": "17",
                "build": {"tool": "maven", "artifact": "target/benchmark.war", "package_goals": GOALS},
                "tests": {"behavior": {"selectors": [f"org.owasp.benchmark.safepatch.SafePatchBehavior{n}"]},
                          "security": {"selectors": [f"org.owasp.benchmark.safepatch.SafePatchWitness{n}"], "markers": [CATEGORY[category]["marker"]]}},
                "editable": [path], "scan": {"paths": [path], "known": [{"id": f"OWASP-BENCHMARK-{n}", "file": path, "line": line, "cwe": CATEGORY[category]["cwe"],
                                                                         "source": f"owasp-benchmark 1.2 expected result: {str(real).lower()}"}]},
                "limits": {"build_seconds": 1800, "test_seconds": 900},
                "labels": {"kind": CATEGORY[category]["kind"], "split": "evaluation", "source": "owasp-benchmark", "case": name,
                           "benchmark_real": str(real).lower(), "license": "GPL-2.0"}}
        ProjectSpec.model_validate(data)
        (folder / f"owasp-benchmark-{n}.yml").write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def catalog_block(cases):
    lines = ["  # BEGIN owasp-benchmark (generated by scripts/prepare_benchmark.py; seeded sample, nothing redrawn)"]
    for name, (category, real, usable, reason) in cases.items():
        n = number(name)
        entry = {"id": f"owasp-benchmark-{n}", "source": "owasp-benchmark", "project": "OWASP-Benchmark/BenchmarkJava", "cwe": CATEGORY[category]["cwe"],
                 "split": "evaluation", "license": "GPL-2.0",
                 "upstream": {"repo": "https://github.com/OWASP-Benchmark/BenchmarkJava", "snapshot": SNAPSHOT, "case": name, "expected": str(real).lower()},
                 "prepare": "scripts/prepare_benchmark.py", "witness": "l3/witness/owasp-benchmark",
                 **({"hidden": {"path": "l3/hidden/owasp-benchmark", "selectors": [f"org.owasp.benchmark.safepatch.SafePatchHidden{n}"]}} if usable else {}),
                 "status": "ready" if usable else "excluded", **({"reason": reason} if reason else {})}
        lines.append("  - " + json.dumps(entry, ensure_ascii=False))
    lines.append("  # END owasp-benchmark")
    path = ROOT / "l3/catalog.yml"
    text = path.read_text(encoding="utf-8")
    block = "\n".join(lines) + "\n"
    found = re.search(r"  # BEGIN owasp-benchmark.*?  # END owasp-benchmark\n", text, re.S)
    path.write_text(text.replace(found.group(0), block) if found else text + block, encoding="utf-8", newline="\n")


def check(recorded):
    """Every generated witness, behaviour and hidden test once on the original code, one build.
    The hidden tests are added to that checkout only, as l3_hidden.py does after acceptance."""
    if evidence("owasp-benchmark-check.json").exists():
        raise SystemExit("Use a fresh EVIDENCE_DIR; evidence is never overwritten")
    descriptors_ = sorted((L3 / "projects").glob("owasp-benchmark-*.yml"))
    specs = [yaml.safe_load(p.read_text(encoding="utf-8")) for p in descriptors_]
    hidden = {p.relative_to(HIDDEN).as_posix(): p.read_bytes() for p in sorted(HIDDEN.rglob("*")) if p.is_file()}
    selectors = [s for spec in specs for s in spec["tests"]["behavior"]["selectors"] + spec["tests"]["security"]["selectors"]]
    selectors += [f"org.owasp.benchmark.safepatch.SafePatchHidden{spec['id'].rsplit('-', 1)[-1]}" for spec in specs]
    repo, commit = Path(specs[0]["repository"]["path"]), specs[0]["repository"]["commit"]
    workspace, result = sandbox_run(repo, commit, [*SKIPS, *SPOTLESS, "-Dtest=" + ",".join(selectors), "test"], extra=hidden)
    try:
        reports = {}
        for report in (workspace / "ws/target/surefire-reports").glob("TEST-*.xml"):
            root = ET.parse(report).getroot()
            reports[root.get("name").rsplit(".", 1)[-1]] = {k: int(root.get(k, 0)) for k in ("tests", "failures", "errors", "skipped")}
    finally:
        shutil.rmtree(workspace, ignore_errors=True)
    rows = []
    for spec in specs:
        n, real = spec["id"].rsplit("-", 1)[-1], spec["labels"]["benchmark_real"] == "true"
        witness, behavior, secret = reports.get(f"SafePatchWitness{n}"), reports.get(f"SafePatchBehavior{n}"), reports.get(f"SafePatchHidden{n}")
        witness_fails = bool(witness) and witness["failures"] == 1 and witness["errors"] == 0
        behavior_passes = bool(behavior) and behavior["tests"] == 1 and behavior["failures"] + behavior["errors"] + behavior["skipped"] == 0
        # On the original code a hidden climb fails (that is why it was kept) and the dotted name passes.
        climbs = int(b"hiddenAttackHasNoEffect" in hidden[f"src/test/java/{PACKAGE}/SafePatchHidden{n}.java"])
        hidden_as_expected = bool(secret) and secret["failures"] == climbs and secret["errors"] + secret["skipped"] == 0
        rows.append({"case": spec["id"], "benchmark_real": real, "witness": witness, "behavior": behavior, "hidden": secret,
                     "as_expected": behavior_passes and witness_fails == real and hidden_as_expected})
    out = evidence("owasp-benchmark-check.json")
    out.write_text(json.dumps({"snapshot": SNAPSHOT, "derived_commit": commit, "seed": recorded["seed"], "exit_code": result["exit_code"],
                               "cases": len(rows), "as_expected": sum(r["as_expected"] for r in rows), "rows": rows}, indent=2) + "\n", encoding="utf-8")
    print("as expected", sum(r["as_expected"] for r in rows), "of", len(rows), "; written:", out)


PROBE5 = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>safepatch.prefetch</groupId>
  <artifactId>junit5-provider-probe</artifactId>
  <version>1</version>
  <properties>
    <maven.compiler.release>8</maven.compiler.release>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  </properties>
  <dependencies>
    <dependency><groupId>org.junit.jupiter</groupId><artifactId>junit-jupiter-api</artifactId><version>5.12.2</version><scope>test</scope></dependency>
    <dependency><groupId>org.junit.jupiter</groupId><artifactId>junit-jupiter-params</artifactId><version>5.12.2</version><scope>test</scope></dependency>
  </dependencies>
  <build><plugins><plugin><groupId>org.apache.maven.plugins</groupId><artifactId>maven-surefire-plugin</artifactId><version>3.6.0</version></plugin></plugins></build>
</project>
"""
PROBE5_TEST = "class ProbeTest {\n  @org.junit.jupiter.api.Test void empty() {}\n}\n"


def prefetch():
    """Benchmark's dependencies (packaging, tests compiled not run), then Surefire's JUnit 5
    provider through a probe project of our own pinned to Benchmark's versions."""
    with tempfile.TemporaryDirectory(dir=L3) as workspace:
        work = Path(workspace) / "ws"
        git(L3, "clone", "--quiet", str(L3 / "repos" / UPSTREAM), str(work))
        maven_online(work, GOALS, "17")
        probe = Path(workspace) / "probe"
        (probe / "src/test/java").mkdir(parents=True)
        (probe / "pom.xml").write_text(PROBE5, encoding="utf-8")
        (probe / "src/test/java/ProbeTest.java").write_text(PROBE5_TEST, encoding="utf-8")
        maven_online(probe, ["test"], "17")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--prefetch", action="store_true", help="download Maven dependencies (internet)")
    parser.add_argument("--record", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    os.environ.setdefault("SANDBOX_MAVEN_CACHE", "/home/mirror/.safepatch/m2")
    if args.prefetch:
        return prefetch()
    if args.record:
        return record(sample())
    recorded = json.loads(RECORDED.read_text(encoding="utf-8"))
    if args.check:
        return check(recorded)
    cases = generate(recorded)
    files = {p.relative_to(WITNESS).as_posix(): p.read_bytes() for p in sorted(WITNESS.rglob("*")) if p.is_file()}
    repo, commit = derive("owasp-benchmark", {**SPEC, "derived": DERIVED, "message":"OWASP Benchmark evaluation cases: snapshot plus SafePatch witnesses for the sample\n"}, files)
    descriptors(cases, repo, commit)
    catalog_block(cases)
    print("commit:", commit, "; usable", sum(c[2] for c in cases.values()), "of", len(cases))


if __name__ == "__main__":
    main()
