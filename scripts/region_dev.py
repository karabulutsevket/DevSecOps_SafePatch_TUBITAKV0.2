"""Region-mode development cases (ROADMAP.md week 5): owned code, never evaluation data.

Four large synthetic classes (about 8 KB each, too large for the model's whole-file budget)
put one vulnerable method, or two, among ordinary helper methods (samples/region). Imports are
explicit, so a fix that needs a new type (Path, PreparedStatement) must add an import. The
findings come from an answer key (known-finding mode, lab profile), as for VUL4J-79, whose
region-mode failures these cases are for: fixes are developed and measured here first.

Step 1, `--prepare`: writes repositories and descriptors under .runtime/region-dev. Start the
services with PROJECTS_DIR=.runtime/region-dev/projects and SAFEPATCH_PROFILE=lab (synthetic,
so the runner may build natively). Step 2, run with `--label <name>`: one job per case and seed,
guided+context, memory off, three attempts, experiment jobs. Writes EVIDENCE_DIR/region-dev/<label>/.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from safepatch.common import POLICY, SOURCE, digest, evidence, setting
from safepatch.engine import Engine
from safepatch.project import ProjectSpec, synthetic_descriptor
from safepatch.repository import registry
from safepatch.store import Store
from safepatch.worker1 import REGION_SYSTEM, SYSTEM, WEAKNESS_NOTES
from vul4j_model import attempt_row

FOLDER = ROOT / ".runtime/region-dev"
SAMPLES = ROOT / "samples/region"
# case -> (kind, source, tests, sink statements, CWE)
CASES = {
    "region-path-read": ("path", "path-read.java", "samples/tests/path", ["File target = new File(root, input);"], "CWE-22"),
    "region-path-write": ("path", "path-write.java", "samples/region/path-write-tests", ["File target = new File(root, name);"], "CWE-22"),
    "region-sql": ("sql", "sql.java", "samples/tests/sql", ['String sql = "SELECT name FROM accounts WHERE name = \'" + input + "\'";'], "CWE-89"),
    "region-command": ("command", "command.java", "samples/tests/command", ['String command = "echo echo:" + input;'], "CWE-78"),
}


def seed_module():
    spec = importlib.util.spec_from_file_location("seed_script", ROOT / "scripts/seed.py")
    seed = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(seed)
    return seed


def source(name):
    """The case class with the shared helper methods put around its vulnerable method(s)."""
    filler = (SAMPLES / "Filler.java").read_text(encoding="utf-8")
    part_a, part_b = filler.split("    // ---- part B ----\n")
    part_a = part_a.replace("    // ---- part A ----\n", "")
    return (SAMPLES / name).read_text(encoding="utf-8").replace("//@FILLER_A\n", part_a + "\n").replace("//@FILLER_B\n", part_b)


def files(case):
    kind, name, tests, _, _ = CASES[case]
    template = ROOT / "samples/template"
    out = {p.relative_to(template).as_posix(): p.read_bytes() for p in sorted(template.rglob("*")) if p.is_file()}
    out[SOURCE] = source(name).encode("utf-8")
    for test in sorted((ROOT / tests).glob("*.java")):
        out["src/test/java/demo/" + test.name] = test.read_bytes()
    if kind == "path":
        out["src/test/java/demo/Links.java"] = (ROOT / "samples/tests/path/Links.java").read_bytes()
    return out


def known(case, text):
    kind, _, _, sinks, cwe = CASES[case]
    lines = [i for i, line in enumerate(text.splitlines(), 1) if line.strip() in sinks]
    assert lines, case
    return [{"id": f"{case}.{n}", "file": SOURCE, "line": line, "cwe": cwe, "source": "safepatch-synthetic answer key"} for n, line in enumerate(lines, 1)]


def prepare():
    seed = seed_module()
    if FOLDER.exists():
        shutil.rmtree(FOLDER, onerror=seed.writable)
    for case in CASES:
        repo = FOLDER / "repos" / case
        repo.mkdir(parents=True)
        content = files(case)
        for path, data in content.items():
            (repo / path).parent.mkdir(parents=True, exist_ok=True)
            (repo / path).write_bytes(data)
        seed.git(repo, "init", "-q")
        seed.git(repo, "add", ".")
        seed.git(repo, "-c", f"user.name={seed.AUTHOR}", "-c", "user.email=synthetic@localhost", "commit", "-qm", f"Region-mode development case {case}")
        commit = seed.git(repo, "rev-parse", "HEAD").decode().strip()
        data = synthetic_descriptor(case, {"kind": CASES[case][0], "split": "development", "commit": commit}, repo.resolve())
        data["scan"]["known"] = known(case, content[SOURCE].decode("utf-8"))
        ProjectSpec.model_validate(data)
        (FOLDER / "projects").mkdir(exist_ok=True)
        (FOLDER / "projects" / f"{case}.yml").write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        print(case, len(content[SOURCE]), "chars,", len(data["scan"]["known"]), "finding(s)")
    print(f"$env:PROJECTS_DIR = '{(FOLDER / 'projects').resolve()}'; $env:SAFEPATCH_PROFILE = 'lab'")


def run(store, case, seed):
    now = time.time()
    job = {"id": uuid.uuid4().hex, "case_id": case, "base_commit": registry()[1][case]["commit"], "project": "owned-java-demo",
           "policy_version": POLICY, "scanner": "known", "mode": "real-local-model", "evaluation": True,
           "status": "queued", "owner": "EXPERIMENT-NOT-A-HUMAN", "started_at": now, "deadline": now + 1200, "max_attempts": 3,
           "attempt_count": 0, "attempts": [], "events": [], "approval": None, "memory_mode": "off", "strategy": "guided+context", "seed": seed}
    store.create(job, job["id"])
    start = time.perf_counter()
    Engine(store).run(job["id"])
    return store.get(job["id"]), round(time.perf_counter() - start, 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--label")
    parser.add_argument("--cases", nargs="+", default=list(CASES))
    parser.add_argument("--seeds", type=int, nargs="+", default=[42, 43, 44])
    args = parser.parse_args()
    if args.prepare:
        return prepare()
    if not args.label:
        raise SystemExit("--label is required for a run")
    if setting("SAFEPATCH_PROFILE") != "lab" or Path(setting("PROJECTS_DIR", "")).resolve() != (FOLDER / "projects").resolve():
        raise SystemExit("set SAFEPATCH_PROFILE=lab and PROJECTS_DIR=.runtime/region-dev/projects (and start the services with them)")
    for service, port in (("WORKER1", 8101), ("WORKER2", 8102)):
        os.environ.setdefault(service + "_URL", f"http://127.0.0.1:{port}")
        os.environ[service + "_TOKEN_FILE"] = str(ROOT / ".secrets" / (service.lower() + "_token"))
    out = evidence("region-dev") / args.label
    if (out / "summary.json").exists():
        raise SystemExit("Use a fresh label; evidence is never overwritten")
    out.mkdir(parents=True, exist_ok=True)
    answers = FOLDER / "answers" / args.label
    answers.mkdir(parents=True, exist_ok=True)
    store = Store("sqlite:///" + (answers / "jobs.db").as_posix())
    git = lambda *a: subprocess.run(["git", *a], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    (out / "protocol.json").write_text(json.dumps({
        "schema": 1, "what": "Region-mode development cases with the real local model, native runner, known-finding scanner",
        "label": args.label, "git_commit": git("rev-parse", "HEAD"), "git_dirty": bool(git("status", "--porcelain", "--untracked-files=no")),
        "started_at": time.time(), "cases": {c: registry()[1][c]["commit"] for c in args.cases}, "seeds": args.seeds,
        "strategy": "guided+context", "memory_mode": "off", "max_attempts": 3,
        "system_sha256": digest(SYSTEM), "region_system_sha256": digest(REGION_SYSTEM), "weakness_notes_sha256": digest(json.dumps(WEAKNESS_NOTES, sort_keys=True)),
        "experiment_jobs": "evaluation=true: never approved, never in memory; owner EXPERIMENT-NOT-A-HUMAN"}, indent=2) + "\n", encoding="utf-8")
    rows = []
    for case in args.cases:
        for seed in args.seeds:
            job, seconds = run(store, case, seed)
            for attempt in job["attempts"]:
                (answers / f"{case}-seed{seed}-attempt{attempt['number']}.json").write_text(json.dumps(attempt["proposal"].get("region_patch") or attempt["proposal"].get("patch"), indent=2), encoding="utf-8")
            rows.append({"case": case, "seed": seed, "job": job["id"], "status": job["status"], "reason": job.get("reason"), "wall_seconds": seconds,
                         "attempts": [attempt_row(a) for a in job["attempts"]]})
            print(json.dumps({k: rows[-1][k] for k in ("case", "seed", "status", "reason", "wall_seconds")}), flush=True)
    by_case = {c: sum(r["status"] == "awaiting_review" for r in rows if r["case"] == c) for c in args.cases}
    summary = {"label": args.label, "jobs": len(rows), "verified": sum(by_case.values()), "by_case": by_case, "rows": rows}
    (out / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("verified", summary["verified"], "of", summary["jobs"], by_case, "; written:", out)


if __name__ == "__main__":
    main()
