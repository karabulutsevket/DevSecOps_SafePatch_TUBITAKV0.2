"""Owned development variants (ROADMAP.md week 6): the synthetic lab's tests over other code shapes.

Seven classes (samples/variants) keep the lab's API and tests (samples/tests/<kind>) but build the
vulnerable construction differently: a StringBuilder, String.format, a helper method, java.io.File,
an argv list. They widen the development side of the L3 set and exercise the structural
signature. Each has a reference fix (samples/variants/fixed) that a check verifies.

`--prepare` writes repositories and descriptors under .runtime/dev-variants (findings from an
answer key, lab profile). `--check` verifies, natively, that each baseline is valid and its
reference fix passes, and writes dev-variants-check.json to EVIDENCE_DIR.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import time
import uuid

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from safepatch import runner
from safepatch.common import SOURCE, Patch, VerifyRequest, digest, evidence, setting
from safepatch.project import ProjectSpec, synthetic_descriptor
from safepatch.repository import baseline, registry

FOLDER = ROOT / ".runtime/dev-variants"
SAMPLES = ROOT / "samples/variants"
# case -> (kind, sink statement, CWE)
CASES = {
    "variant-sql-builder": ("sql", 'query.append(input).append("\'");', "CWE-89"),
    "variant-sql-format": ("sql", 'String sql = String.format("SELECT name FROM accounts WHERE name = \'%s\'", input);', "CWE-89"),
    "variant-sql-helper": ("sql", 'ResultSet rows = statement.executeQuery("SELECT name FROM accounts WHERE name = \'" + name + "\'")) {', "CWE-89"),
    "variant-path-file": ("path", "File target = new File(root, input);", "CWE-22"),
    "variant-path-helper": ("path", 'return Paths.get(System.getProperty("demo.root"), name);', "CWE-22"),
    "variant-command-list": ("command", 'argv.add("echo echo:" + input);', "CWE-78"),
    "variant-command-format": ("command", 'String command = String.format("echo echo:%s", input);', "CWE-78"),
}


def seed_module():
    spec = importlib.util.spec_from_file_location("seed_script", ROOT / "scripts/seed.py")
    seed = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(seed)
    return seed


def source_name(case):
    return case[len("variant-"):] + ".java"


def files(case):
    kind = CASES[case][0]
    template = ROOT / "samples/template"
    out = {p.relative_to(template).as_posix(): p.read_bytes() for p in sorted(template.rglob("*")) if p.is_file()}
    out[SOURCE] = (SAMPLES / source_name(case)).read_bytes()
    for test in sorted((ROOT / "samples/tests" / kind).glob("*.java")):
        out["src/test/java/demo/" + test.name] = test.read_bytes()
    return out


def prepare():
    seed = seed_module()
    if FOLDER.exists():
        shutil.rmtree(FOLDER, onerror=seed.writable)
    for case, (kind, sink, cwe) in CASES.items():
        repo = FOLDER / "repos" / case
        repo.mkdir(parents=True)
        content = files(case)
        for path, data in content.items():
            (repo / path).parent.mkdir(parents=True, exist_ok=True)
            (repo / path).write_bytes(data)
        seed.git(repo, "init", "-q")
        seed.git(repo, "add", ".")
        seed.git(repo, "-c", f"user.name={seed.AUTHOR}", "-c", "user.email=synthetic@localhost", "commit", "-qm", f"Development variant {case}")
        commit = seed.git(repo, "rev-parse", "HEAD").decode().strip()
        data = synthetic_descriptor(case, {"kind": kind, "split": "development", "commit": commit}, repo.resolve())
        lines = [i for i, line in enumerate(content[SOURCE].decode("utf-8").splitlines(), 1) if line.strip() == sink]
        assert len(lines) == 1, case
        data["scan"]["known"] = [{"id": f"{case}.1", "file": SOURCE, "line": lines[0], "cwe": cwe, "source": "safepatch-synthetic answer key"}]
        ProjectSpec.model_validate(data)
        (FOLDER / "projects").mkdir(exist_ok=True)
        (FOLDER / "projects" / f"{case}.yml").write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        print(case, "line", lines[0])
    print(f"$env:PROJECTS_DIR = '{(FOLDER / 'projects').resolve()}'; $env:SAFEPATCH_PROFILE = 'lab'")


def verify(case, content=None):
    commit = registry()[1][case]["commit"]
    patch = None
    if content is not None:
        _, tracked = baseline(case, commit)
        patch = Patch.model_validate({"edits": [{"path": SOURCE, "old_sha256": digest(tracked[SOURCE]), "content": content}], "rationale": "reference fix"})
    result = runner.execute(VerifyRequest(job_id=uuid.uuid4().hex, case_id=case, base_commit=commit, attempt=1 if patch else 0,
                                          deadline=time.time() + 600, scanner="known", patch=patch, target_file=SOURCE if patch else None))
    suites = {s: {k: (result.get(s) or {}).get(k) for k in ("tests", "failures", "errors", "skipped")} for s in ("behavior", "security")}
    return {"passed": result["passed"], "baseline_valid": result.get("baseline_valid"), "code": result["feedback"]["code"], **suites}


def check():
    if setting("SAFEPATCH_PROFILE") != "lab" or Path(setting("PROJECTS_DIR", "")).resolve() != (FOLDER / "projects").resolve():
        raise SystemExit("set SAFEPATCH_PROFILE=lab and PROJECTS_DIR=.runtime/dev-variants/projects")
    out = evidence("dev-variants-check.json")
    if out.exists():
        raise SystemExit("Use a fresh EVIDENCE_DIR; evidence is never overwritten")
    rows = []
    for case in CASES:
        fixed = (SAMPLES / "fixed" / source_name(case)).read_text(encoding="utf-8")
        row = {"case": case, "baseline": verify(case), "reference_fix": verify(case, fixed)}
        row["as_expected"] = bool(row["baseline"]["baseline_valid"] and row["reference_fix"]["passed"])
        rows.append(row)
        print(json.dumps({"case": case, "as_expected": row["as_expected"]}), flush=True)
    out.write_text(json.dumps({"cases": len(rows), "as_expected": sum(r["as_expected"] for r in rows), "rows": rows}, indent=2) + "\n", encoding="utf-8")
    print("as expected", sum(r["as_expected"] for r in rows), "of", len(rows), "; written:", out)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.prepare:
        prepare()
    if args.check:
        check()


if __name__ == "__main__":
    main()
