"""Real local inference + real Java/Semgrep evaluation. Never approves production.

The corpus has three synthetic families. Case variants are NOT independent
holdout projects. A/B/C are controlled recurrence/transfer smoke comparisons.
"""
import argparse
import csv
import json
import os
from pathlib import Path
import platform
import statistics
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from safepatch.common import POLICY, SOURCE, digest, canonical
from safepatch.engine import Engine
from safepatch.memory import Memory, context_for
from safepatch.repository import baseline, registry
from safepatch.store import Store


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def run(store, case_id, arm, phase, seed=42, attempts=2):
    now = time.time()
    job = {"id": uuid.uuid4().hex, "case_id": case_id, "base_commit": registry()[1][case_id]["commit"],
           "project": "owned-java-demo", "policy_version": POLICY, "scanner": "semgrep",
           "mode": "real-local-model", "evaluation": phase != "memory-construction",
           "status": "queued", "owner": "BENCHMARK-NOT-A-HUMAN", "started_at": now,
           "deadline": now+1200, "max_attempts": attempts, "attempt_count": 0,
           "attempts": [], "events": [], "approval": None, "memory_mode": arm, "seed": seed}
    store.create(job, job["id"])
    start = time.perf_counter()
    Engine(store).run(job["id"])
    job = store.get(job["id"])
    job.update(phase=phase, wall_seconds=round(time.perf_counter()-start, 3))
    return job


def metrics(job):
    measured = [a["proposal"].get("metrics", {}) for a in job["attempts"]]
    def total(key):
        values = [m.get(key) for m in measured]
        return sum(values) if values and all(v is not None for v in values) else None
    return {"id": job["id"], "case_id": job["case_id"], "phase": job["phase"],
            "arm": job["memory_mode"], "seed": job["seed"], "status": job["status"],
            "accepted": job["status"] == "awaiting_review", "reason": job.get("reason"),
            "wall_seconds": job["wall_seconds"], "attempts": job["attempt_count"],
            "model_seconds": total("duration_seconds"), "prompt_tokens": total("prompt_tokens_measured"),
            "output_tokens": total("output_tokens_measured"),
            "memory_hit": bool(job.get("memory_ids")),
            "replay": any(a["proposal"]["mode"] == "approved-memory-replay" for a in job["attempts"])}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port-base", type=int, default=8100)
    parser.add_argument("--output", default="evidence/benchmark")
    args = parser.parse_args()
    output = ROOT / args.output
    if (output / "summary.json").exists():
        raise SystemExit("Use a fresh --output; evidence is never overwritten")
    for service, offset in (("WORKER1", 1), ("WORKER2", 2)):
        os.environ[service+"_URL"] = f"http://127.0.0.1:{args.port_base+offset}"
        os.environ[service+"_TOKEN_FILE"] = str(ROOT / ".secrets" / (service.lower()+"_token"))
    db_file = ROOT / ".runtime" / ("benchmark-"+uuid.uuid4().hex+".db")
    store = Store("sqlite:///"+str(db_file))
    rows, construction = [], []
    started = time.time()
    write(output / "protocol.json", {"schema": 1, "started_at": started, "model": "qwen2.5-coder:7b-instruct-q4_K_M",
        "seed": 42, "max_attempts": 2, "job_wall_budget": 1200, "context": 8192, "max_output": 2048,
        "arms": {"off": "A: no memory", "naive": "B: project/rule retrieval without precondition filter; inference required", "guarded": "C: compatibility filter, exact source replay else inference"},
        "phases": ["recurrence: same vulnerable commit used for memory construction", "variant: same template family with small source changes"],
        "heldout_project_generalization": False, "human_approval": "SIMULATED benchmark-only memory construction",
        "memory_pool": "frozen after successful local-model construction; no benchmark candidates promoted",
        "order": "balanced rotation of arms across six case/phase blocks", "python": platform.python_version(),
        "scanner": "real Semgrep 1.136.0 with three owned rules", "runner": "native-same-user; no airgap claim"})
    for kind in ("sql", "path", "command"):
        job = run(store, kind+"-01", "off", "memory-construction", attempts=3)
        write(output / "jobs" / (job["id"]+".json"), job)
        construction.append(metrics(job))
        print(json.dumps({"construction": construction[-1]}), flush=True)
        if job["status"] == "awaiting_review":
            # Deliberate simulated review in a separate benchmark database.
            # Not a customer approval and never made available to the product DB.
            c = job["candidate"]
            job.update(status="approved", approval={"decision": "approve", "candidate_commit": c["commit"],
                "artifact_sha256": c["artifact_sha256"], "policy_version": c["policy_version"],
                "reviewer": "SIMULATED-BENCHMARK-REVIEWER", "expires_at": time.time()+86400})
            case, files = baseline(job["case_id"], job["base_commit"])
            Memory(store).promote(job, context_for(case, files, job["baseline"]["scans"][0]["findings"][0]),
                                  files[SOURCE], "SIMULATED-BENCHMARK-REVIEWER", "Benchmark-only construction from real verified local-model patch")
    write(output / "construction.json", construction)
    pool = Memory(store).all()
    write(output / "memory-pool.json", pool)
    arms = ["off", "naive", "guarded"]
    blocks = [(kind+suffix, phase) for phase, suffix in (("recurrence", "-01"), ("variant", "-03")) for kind in ("sql", "path", "command")]
    for index, (case, phase) in enumerate(blocks):
        for arm in arms[index % 3:]+arms[:index % 3]:
            job = run(store, case, arm, phase)
            write(output / "jobs" / (job["id"]+".json"), job)
            rows.append(metrics(job))
            write(output / "runs.json", rows)
            print(json.dumps(rows[-1]), flush=True)
    summary = {"scope": "synthetic controlled recurrence/variant smoke test; not independent project benchmark",
               "n": len(rows), "construction": construction, "memory_records": len(pool),
               "memory_pool_sha256": digest(canonical(pool)), "elapsed_seconds": round(time.time()-started, 3),
               "groups": [], "human_minutes_saved": None, "customer_validation": "not performed"}
    for phase in ("recurrence", "variant"):
        for arm in arms:
            group = [r for r in rows if r["phase"] == phase and r["arm"] == arm]
            summary["groups"].append({"phase": phase, "arm": arm, "n": len(group),
                "accepted": sum(r["accepted"] for r in group), "median_wall_seconds": round(statistics.median(r["wall_seconds"] for r in group), 3),
                "all_statuses": {s: sum(r["status"] == s for r in group) for s in sorted({r["status"] for r in group})}})
    write(output / "summary.json", summary)
    with (output / "runs.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader(); writer.writerows(rows)
    print(json.dumps(summary), flush=True)


if __name__ == "__main__":
    main()
