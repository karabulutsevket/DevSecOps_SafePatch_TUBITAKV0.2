"""Faz 2 exit check, scanner independence (ROADMAP.md week 8 exit): real local model, real Java verification.

A memory record learned from a Semgrep finding must be chosen for the FindSecBugs finding of
the same weakness, and the candidate must pass verification, the FindSecBugs rescan included.

1. Construction: sql-01 with scanner `semgrep` (SafePatch's own rule), memory off. An accepted
   candidate is approved by SIMULATED-EXPERIMENT-REVIEWER in a separate experiment database and
   promoted to memory; never a customer approval.
2. Use: sql-01, sql-02 and sql-03 with scanner `findsecbugs` (rule SQL_INJECTION_JDBC), memory
   guarded. Memory matches on the CWE family and the structural signature read from the code;
   the scanner's rule id is kept for traceability only (safepatch/memory.py).
The condition is met when a use job selects the construction record and is accepted.

Needs worker1 (Ollama), worker2 and the runner started with PROJECTS_DIR=.runtime/projects (the
synthetic lab), SEMGREP_WSL and the FindSecBugs tools (scripts/prepare_findsecbugs.py).
Writes EVIDENCE_DIR/faz2/: protocol.json, jobs/, memory-pool.json, runs.json, summary.json.
"""
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from safepatch.common import POLICY, canonical, digest, evidence, setting
from safepatch.engine import Engine, primary_finding
from safepatch.memory import Memory, context_for
from safepatch.repository import baseline, registry
from safepatch.store import Store
from safepatch.worker1 import SYSTEM, WEAKNESS_NOTES

CONSTRUCTION = "sql-01"
USES = ("sql-01", "sql-02", "sql-03")
REVIEWER = "SIMULATED-EXPERIMENT-REVIEWER"


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def run(store, case_id, scanner, memory_mode, phase, seed=42):
    now = time.time()
    job = {"id": uuid.uuid4().hex, "case_id": case_id, "base_commit": registry()[1][case_id]["commit"], "project": "owned-java-demo",
           "policy_version": POLICY, "scanner": scanner, "mode": "real-local-model", "evaluation": phase != "memory-construction",
           "status": "queued", "owner": "EXPERIMENT-NOT-A-HUMAN", "started_at": now, "deadline": now + 1200, "max_attempts": 3,
           "attempt_count": 0, "attempts": [], "events": [], "approval": None, "memory_mode": memory_mode, "strategy": "guided+context", "seed": seed}
    store.create(job, job["id"])
    start = time.perf_counter()
    Engine(store).run(job["id"])
    job = store.get(job["id"])
    job.update(phase=phase, wall_seconds=round(time.perf_counter() - start, 3))
    return job


def row(job):
    lookup = job.get("memory_lookup") or {}
    finding = primary_finding(job) if job.get("findings") or job.get("baseline") else {}
    last = next((a for a in reversed(job["attempts"]) if a.get("verification")), {})
    return {"id": job["id"], "case_id": job["case_id"], "phase": job["phase"], "scanner": job["scanner"], "memory_mode": job["memory_mode"],
            "finding_rule": finding.get("rule_id"), "finding_cwe": finding.get("cwe"), "finding_line": finding.get("line"),
            "status": job["status"], "accepted": job["status"] == "awaiting_review", "reason": job.get("reason"), "attempts": job["attempt_count"],
            "wall_seconds": job["wall_seconds"], "memory_use": lookup.get("use"), "memory_selected": lookup.get("selected_id"),
            "considered": [{k: c.get(k) for k in ("id", "use", "rank", "differences")} for c in lookup.get("considered", [])],
            "rescan_tools": sorted({s.get("tool") for s in (last.get("verification") or {}).get("scans", [])}),
            "rescan_remaining": [f["rule_id"] for s in (last.get("verification") or {}).get("scans", []) for f in s.get("findings", [])]}


def main():
    if not all(case in registry()[1] for case in USES):
        raise SystemExit("start the services with PROJECTS_DIR=.runtime/projects and set it here too")
    output = evidence("faz2")
    if (output / "summary.json").exists():
        raise SystemExit("Use a fresh EVIDENCE_DIR; evidence is never overwritten")
    for service, port in (("WORKER1", 8101), ("WORKER2", 8102)):
        os.environ.setdefault(service + "_URL", f"http://127.0.0.1:{port}")
        os.environ[service + "_TOKEN_FILE"] = str(ROOT / ".secrets" / (service.lower() + "_token"))
    store = Store("sqlite:///" + str(ROOT / ".runtime" / ("faz2-" + uuid.uuid4().hex + ".db")))
    git = lambda *a: subprocess.run(["git", *a], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    started = time.time()
    write(output / "protocol.json", {
        "schema": 1, "question": "Faz 2 exit: a record learned from a Semgrep finding is chosen for the FindSecBugs finding of the same weakness and passes verification",
        "started_at": started, "git_commit": git("rev-parse", "HEAD"), "git_dirty": bool(git("status", "--porcelain", "--untracked-files=no")),
        "model": setting("OLLAMA_MODEL", "qwen2.5-coder:7b-instruct-q4_K_M"), "system_prompt_sha256": digest(SYSTEM),
        "weakness_notes_sha256": digest(canonical(WEAKNESS_NOTES)), "strategy": "guided+context", "max_attempts": 3, "seed": 42,
        "construction": {"case": CONSTRUCTION, "scanner": "semgrep", "memory_mode": "off"},
        "uses": {"cases": USES, "scanner": "findsecbugs", "memory_mode": "guarded"},
        "human_approval": f"SIMULATED: the accepted construction candidate is approved by {REVIEWER} in a separate experiment database",
        "python": platform.python_version()})
    job = run(store, CONSTRUCTION, "semgrep", "off", "memory-construction")
    write(output / "jobs" / (job["id"] + ".json"), job)
    construction = row(job)
    print(json.dumps({k: construction[k] for k in ("case_id", "scanner", "finding_rule", "accepted", "reason")}), flush=True)
    if job["status"] != "awaiting_review":
        write(output / "summary.json", {"condition_met": False, "reason": "the construction job was not accepted", "construction": construction})
        raise SystemExit("construction not accepted: no record to reuse")
    candidate = job["candidate"]
    approval = {"decision": "approve", "candidate_commit": candidate["commit"], "artifact_sha256": candidate["artifact_sha256"],
                "policy_version": candidate["policy_version"], "reviewer": REVIEWER, "approved_at": time.time(), "expires_at": time.time() + 86400}
    job = store.mutate(job["id"], lambda j: j.update(status="approved", approval=approval))
    case, files = baseline(job["case_id"], job["base_commit"])
    finding = primary_finding(job)
    record = Memory(store).promote(job, context_for(case, files, finding), files[finding["file"]], REVIEWER,
                                   "Experiment-only construction from a real verified local-model patch (Semgrep finding)")
    pool = Memory(store).all()
    write(output / "memory-pool.json", pool)
    record_id = (record or {}).get("id") or (pool[0]["id"] if pool else None)
    rows = []
    for case_id in USES:
        job = run(store, case_id, "findsecbugs", "guarded", "use")
        write(output / "jobs" / (job["id"] + ".json"), job)
        rows.append(row(job))
        write(output / "runs.json", rows)
        print(json.dumps({k: rows[-1][k] for k in ("case_id", "finding_rule", "memory_use", "memory_selected", "accepted", "reason", "rescan_remaining")}), flush=True)
    chosen = [r for r in rows if r["memory_selected"] == record_id]
    write(output / "summary.json", {
        "scope": "synthetic Faz 2 exit check (scanner independence); not an independent benchmark", "elapsed_seconds": round(time.time() - started, 3),
        "record": {"id": record_id, "learned_from_rule": construction["finding_rule"], "cwe_family": (pool[0]["context"].get("cwe_family") if pool else None)},
        "uses": [{k: r[k] for k in ("case_id", "finding_rule", "memory_use", "memory_selected", "accepted", "rescan_tools", "rescan_remaining")} for r in rows],
        "condition_met": any(r["accepted"] for r in chosen),
        "human_approval": "SIMULATED", "customer_validation": "not performed"})
    print("condition met:", any(r["accepted"] for r in chosen), "; written:", output)


if __name__ == "__main__":
    main()
