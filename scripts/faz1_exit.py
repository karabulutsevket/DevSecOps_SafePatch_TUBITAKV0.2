"""Faz 1 exit check (ROADMAP.md week 5): real local model, real Java verification.

(2) In a variant whose source differs, a memory record is chosen by its structural
    signature and the candidate passes verification.
(3) An incompatible record is rejected for the right reason: in `sql-execute` the query
    runs through Statement.execute instead of executeQuery, so the sql-01 record (a
    different sink) must be rejected with "signature.sink".

Step 1, `--prepare`: writes an experiment-only project folder with the nine synthetic
descriptors and the `sql-execute` variant (not a sample: the nine-case experiments keep
their case list). Start the services with PROJECTS_DIR set to the printed folder.
Step 2, run: memory construction on the -01 cases (memory off), SIMULATED approval of
the accepted candidates in a separate database, then the variants with memory off (A)
and guarded (C). The builtin lab scanner is used throughout: the owned Semgrep rule does
not match the execute() variant.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from safepatch.common import POLICY, canonical, digest, evidence, setting
from safepatch.engine import Engine, primary_finding
from safepatch.memory import Memory, context_for
from safepatch.project import synthetic_descriptor
from safepatch.repository import baseline, registry
from safepatch.store import Store
from safepatch.worker1 import SYSTEM, WEAKNESS_NOTES

FOLDER = ROOT / ".runtime" / "faz1"
VARIANT = "sql-execute"
SOURCE = "src/main/java/demo/DemoService.java"
CONSTRUCTION = ["sql-01", "path-01", "command-01"]
VARIANTS = ["sql-02", "sql-03", "path-02", "path-03", "command-02", "command-03", VARIANT]
EXECUTE_QUERY = ("try (Statement statement = conn.createStatement(); ResultSet rows = statement.executeQuery(sql)) {\n"
                 "                while (rows.next()) names.add(rows.getString(1));\n            }")
EXECUTE = ("try (Statement statement = conn.createStatement()) {\n                statement.execute(sql);\n"
           "                try (ResultSet rows = statement.getResultSet()) {\n"
           "                    while (rows.next()) names.add(rows.getString(1));\n                }\n            }")


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def prepare():
    """Nine synthetic descriptors plus the execute() variant, in an experiment-only folder."""
    spec = importlib.util.spec_from_file_location("seed_script", ROOT / "scripts/seed.py")
    seed = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(seed)
    seed.seed()
    shutil.rmtree(FOLDER, ignore_errors=True)
    projects, repo = FOLDER / "projects", FOLDER / "repos" / VARIANT
    shutil.copytree(seed.ROOT / ".runtime/projects", projects)
    files = seed.expected_files("sql", 1)
    source = files[SOURCE].decode()
    assert source.count(EXECUTE_QUERY) == 1
    files[SOURCE] = source.replace(EXECUTE_QUERY, EXECUTE).replace("// Case sql-01.", f"// Case {VARIANT}.").encode()
    for name, data in files.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_bytes(data)
    git = lambda *a: subprocess.check_output(["git", "-c", "core.autocrlf=false", "-c", "user.name=BiGG Synthetic", "-c", "user.email=synthetic@localhost", *a], cwd=repo).decode().strip()
    git("init", "-q")
    git("add", ".")
    git("commit", "-qm", f"Synthetic vulnerable baseline {VARIANT}")
    descriptor = synthetic_descriptor(VARIANT, {"kind": "sql", "split": "evaluation", "commit": git("rev-parse", "HEAD")}, repo.resolve())
    import yaml
    (projects / f"{VARIANT}.yml").write_text(yaml.safe_dump(descriptor, sort_keys=False), encoding="utf-8", newline="\n")
    print(projects.resolve())


def run(store, case_id, arm, phase, seed=42):
    now = time.time()
    job = {"id": uuid.uuid4().hex, "case_id": case_id, "base_commit": registry()[1][case_id]["commit"], "project": "owned-java-demo",
           "policy_version": POLICY, "scanner": "builtin", "mode": "real-local-model", "evaluation": phase != "memory-construction",
           "status": "queued", "owner": "EXPERIMENT-NOT-A-HUMAN", "started_at": now, "deadline": now + 1200, "max_attempts": 3,
           "attempt_count": 0, "attempts": [], "events": [], "approval": None, "memory_mode": arm, "strategy": "guided+context", "seed": seed}
    store.create(job, job["id"])
    start = time.perf_counter()
    Engine(store).run(job["id"])
    job = store.get(job["id"])
    job.update(phase=phase, wall_seconds=round(time.perf_counter() - start, 3))
    return job


def row(job):
    lookup = job.get("memory_lookup") or {}
    return {"id": job["id"], "case_id": job["case_id"], "phase": job["phase"], "arm": job["memory_mode"], "status": job["status"],
            "accepted": job["status"] == "awaiting_review", "reason": job.get("reason"), "attempts": job["attempt_count"],
            "wall_seconds": job["wall_seconds"], "memory_use": lookup.get("use"), "memory_selected": lookup.get("selected_id"),
            "considered": [{k: c.get(k) for k in ("id", "use", "rank", "differences")} for c in lookup.get("considered", [])],
            "warnings_sent": len(lookup.get("warnings_sent", [])),
            "failures": "|".join((a.get("failure") or {}).get("category", "passed" if (a.get("verification") or {}).get("passed") else a.get("stopped") or "-") for a in job["attempts"])}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--port-base", type=int, default=8100)
    args = parser.parse_args()
    if args.prepare:
        return prepare()
    if VARIANT not in registry()[1]:
        raise SystemExit("Run --prepare and start the services with PROJECTS_DIR set to its folder")
    output = evidence("faz1")
    if (output / "summary.json").exists():
        raise SystemExit("Use a fresh EVIDENCE_DIR; evidence is never overwritten")
    for service, offset in (("WORKER1", 1), ("WORKER2", 2)):
        os.environ[service + "_URL"] = f"http://127.0.0.1:{args.port_base + offset}"
        os.environ[service + "_TOKEN_FILE"] = str(ROOT / ".secrets" / (service.lower() + "_token"))
    store = Store("sqlite:///" + str(ROOT / ".runtime" / ("faz1-" + uuid.uuid4().hex + ".db")))
    git = lambda *a: subprocess.run(["git", *a], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    started = time.time()
    write(output / "protocol.json", {
        "schema": 1, "question": "Faz 1 exit conditions 2 and 3 (ROADMAP.md week 5)", "started_at": started,
        "git_commit": git("rev-parse", "HEAD"), "git_dirty": bool(git("status", "--porcelain", "--", "safepatch", "scripts")),
        "model": setting("OLLAMA_MODEL", "qwen2.5-coder:7b-instruct-q4_K_M"), "system_prompt_sha256": digest(SYSTEM),
        "weakness_notes_sha256": digest(canonical(WEAKNESS_NOTES)), "strategy": "guided+context", "max_attempts": 3, "seed": 42,
        "scanner": "builtin lab scanner (the owned Semgrep rule does not match the execute() variant)",
        "construction": CONSTRUCTION, "variants": VARIANTS, "arms": {"off": "A: no memory", "guarded": "C: week-4/5 applicability, ranking and failure warnings"},
        "variant_note": f"{VARIANT}: sql-01 with Statement.execute()+getResultSet() instead of executeQuery(); same tests; experiment-only, not a sample",
        "human_approval": "SIMULATED: accepted construction candidates are approved by SIMULATED-EXPERIMENT-REVIEWER in a separate database",
        "failure_memory": "construction jobs may record failures; evaluation jobs never write memory", "python": platform.python_version()})
    construction, rows = [], []
    for case_id in CONSTRUCTION:
        job = run(store, case_id, "off", "memory-construction")
        write(output / "jobs" / (job["id"] + ".json"), job)
        construction.append(row(job))
        print(json.dumps({"construction": construction[-1]["case_id"], "accepted": construction[-1]["accepted"]}), flush=True)
        if job["status"] == "awaiting_review":
            # Simulated review in a separate experiment database; never a customer approval.
            c = job["candidate"]
            approval = {"decision": "approve", "candidate_commit": c["commit"], "artifact_sha256": c["artifact_sha256"],
                        "policy_version": c["policy_version"], "reviewer": "SIMULATED-EXPERIMENT-REVIEWER", "approved_at": time.time(), "expires_at": time.time() + 86400}
            job = store.mutate(job["id"], lambda j: j.update(status="approved", approval=approval))
            case, files = baseline(job["case_id"], job["base_commit"])
            finding = primary_finding(job)
            Memory(store).promote(job, context_for(case, files, finding), files[finding["file"]], "SIMULATED-EXPERIMENT-REVIEWER",
                                  "Experiment-only construction from a real verified local-model patch")
    pool = Memory(store).all()
    write(output / "construction.json", construction)
    write(output / "memory-pool.json", pool)
    arms = ["off", "guarded"]
    for index, case_id in enumerate(VARIANTS):
        for arm in arms[index % 2:] + arms[:index % 2]:
            job = run(store, case_id, arm, "variant")
            write(output / "jobs" / (job["id"] + ".json"), job)
            rows.append(row(job))
            write(output / "runs.json", rows)
            print(json.dumps({k: rows[-1][k] for k in ("case_id", "arm", "accepted", "memory_use", "reason")}), flush=True)
    sources = {r["id"]: r["context"]["source_sha256"] for r in pool}
    guarded = [r for r in rows if r["arm"] == "guarded"]
    condition2 = [{"case_id": r["case_id"], "record": r["memory_selected"], "accepted": r["accepted"]} for r in guarded
                  if r["case_id"] != VARIANT and r["memory_use"] == "example" and r["memory_selected"] in sources]
    sql01 = next((r["id"] for r in pool if r["source_job"] == next((c["id"] for c in construction if c["case_id"] == "sql-01"), None)), None)
    execute = next((r for r in guarded if r["case_id"] == VARIANT), None)
    rejection = next((c for c in (execute or {}).get("considered", []) if c["id"] == sql01), None)
    write(output / "summary.json", {
        "scope": "synthetic Faz 1 exit check; not an independent benchmark", "n": len(rows), "elapsed_seconds": round(time.time() - started, 3),
        "construction": [{k: c[k] for k in ("case_id", "accepted", "failures")} for c in construction], "memory_records": len(pool),
        "arms": {arm: {"accepted": sum(r["accepted"] for r in rows if r["arm"] == arm), "n": sum(r["arm"] == arm for r in rows)} for arm in arms},
        "condition_2": {"met": any(c["accepted"] for c in condition2), "examples": condition2},
        "condition_3": {"met": bool(rejection and rejection["use"] is None and "signature.sink" in rejection["differences"]), "rejection": rejection},
        "human_approval": "SIMULATED", "customer_validation": "not performed"})


if __name__ == "__main__":
    main()
