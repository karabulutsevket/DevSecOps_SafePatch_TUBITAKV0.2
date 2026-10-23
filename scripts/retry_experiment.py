"""H2 retry-strategy experiment: real local model, real Java/Semgrep verification.

Arms differ only in the retry strategy; memory is off and no human approval or
memory promotion happens. Guidance texts were written from development cases
(*-01); evaluation cases (*-02, *-03) are reported separately. Three small
synthetic families are not an independent project benchmark.
"""
import argparse
import csv
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from safepatch.common import POLICY, digest, evidence, setting
from safepatch.engine import STRATEGIES, Engine
from safepatch.feedback import GUIDANCE_SHA256
from safepatch.repository import registry
from safepatch.store import Store
from safepatch.worker1 import SYSTEM


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def run(store, case_id, strategy, seed, attempts):
    now = time.time()
    job = {"id": uuid.uuid4().hex, "case_id": case_id, "base_commit": registry()[1][case_id]["commit"],
           "project": "owned-java-demo", "policy_version": POLICY, "scanner": "semgrep",
           "mode": "real-local-model", "evaluation": True, "status": "queued",
           "owner": "EXPERIMENT-NOT-A-HUMAN", "started_at": now, "deadline": now + 1200,
           "max_attempts": attempts, "attempt_count": 0, "attempts": [], "events": [],
           "approval": None, "memory_mode": "off", "strategy": strategy, "seed": seed}
    store.create(job, job["id"])
    start = time.perf_counter()
    Engine(store).run(job["id"])
    job = store.get(job["id"])
    job["wall_seconds"] = round(time.perf_counter() - start, 3)
    return job


def row(job, case):
    attempts = job["attempts"]
    model = [a["proposal"].get("metrics", {}).get("duration_seconds") for a in attempts]
    return {"id": job["id"], "case_id": job["case_id"], "kind": case["kind"], "split": case["split"],
            "strategy": job["strategy"], "seed": job["seed"], "status": job["status"],
            "accepted": job["status"] == "awaiting_review", "reason": job.get("reason"),
            "attempts": job["attempt_count"], "wall_seconds": job["wall_seconds"],
            "model_seconds": round(sum(m for m in model if m), 3) if all(m is not None for m in model) else None,
            "failures": "|".join((a.get("failure") or {}).get("category", "passed" if a.get("verification", {}).get("passed") else a.get("stopped") or a.get("policy_error") or "-") for a in attempts)}


def summarize(rows, started):
    groups = []
    for strategy in dict.fromkeys(r["strategy"] for r in rows):
        for split in ("all", "development", "evaluation"):
            for kind in ("all", "sql", "path", "command"):
                group = [r for r in rows if r["strategy"] == strategy and split in ("all", r["split"]) and kind in ("all", r["kind"])]
                if group:
                    groups.append({"strategy": strategy, "split": split, "kind": kind, "n": len(group),
                                   "accepted": sum(r["accepted"] for r in group),
                                   "median_wall_seconds": round(statistics.median(r["wall_seconds"] for r in group), 3),
                                   "statuses": {s: sum(r["status"] == s for r in group) for s in sorted({r["status"] for r in group})},
                                   "reasons": {s: sum(r["reason"] == s for r in group) for s in sorted({str(r["reason"]) for r in group if r["reason"]})}})
    return {"scope": "synthetic H2 retry-strategy smoke experiment; not an independent project benchmark",
            "n": len(rows), "elapsed_seconds": round(time.time() - started, 3), "groups": groups,
            "human_minutes_saved": None, "customer_validation": "not performed"}


def main():
    cases = registry()[1]
    parser = argparse.ArgumentParser()
    parser.add_argument("--port-base", type=int, default=8100)
    parser.add_argument("--cases", default=",".join(sorted(cases)))
    parser.add_argument("--strategies", default=",".join(STRATEGIES))
    parser.add_argument("--seeds", default="42,43,44")
    parser.add_argument("--attempts", type=int, default=3)
    args = parser.parse_args()
    selected = args.cases.split(",")
    strategies = args.strategies.split(",")
    seeds = [int(s) for s in args.seeds.split(",")]
    if set(strategies) - set(STRATEGIES) or set(selected) - set(cases):
        raise SystemExit("Unknown strategy or case")
    output = evidence("retry")
    if (output / "summary.json").exists():
        raise SystemExit("Use a fresh EVIDENCE_DIR; evidence is never overwritten")
    for service, offset in (("WORKER1", 1), ("WORKER2", 2)):
        os.environ[service + "_URL"] = f"http://127.0.0.1:{args.port_base + offset}"
        os.environ[service + "_TOKEN_FILE"] = str(ROOT / ".secrets" / (service.lower() + "_token"))
    store = Store("sqlite:///" + str(ROOT / ".runtime" / ("retry-" + uuid.uuid4().hex + ".db")))
    git = lambda *a: subprocess.run(["git", *a], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    started = time.time()
    # Seeds outermost so a full seed finishes first; arm order rotates per case and seed.
    order = [(seed, case, strategy) for s_index, seed in enumerate(seeds) for c_index, case in enumerate(selected)
             for strategy in (strategies[(c_index + s_index) % len(strategies):] + strategies[:(c_index + s_index) % len(strategies)])]
    write(output / "protocol.json", {
        "schema": 1, "hypothesis": "H2: failure-aware retries solve more cases than the fixed V0.1 retry loop",
        "started_at": started, "git_commit": git("rev-parse", "HEAD"), "git_dirty": bool(git("status", "--porcelain", "--", "safepatch")),
        "model": setting("OLLAMA_MODEL", "qwen2.5-coder:7b-instruct-q4_K_M"), "system_prompt_sha256": digest(SYSTEM),
        "guidance_sha256": GUIDANCE_SHA256, "retry_temperature": float(setting("RETRY_TEMPERATURE", "0.4")),
        "strategies": strategies, "cases": selected, "seeds": seeds, "max_attempts": args.attempts, "memory": "off",
        "order": "seeds outermost; strategy order rotated per case and seed", "jobs": len(order),
        "guidance_origin": "team-written after inspecting V0.1 failures on development cases (*-01)",
        "guidance_placement": "appended after the JSON data in the user prompt. Pre-experiment probe on path-01 (seeds 43/44, temperature 0.4): the same text in the system prompt was ignored (identical patches); after the data it produced canonicalizing patches.",
        "duplicate_handling": "v01/sampling stop on a duplicate patch; guided strategies skip re-verification and retry with deeper guidance",
        "python": platform.python_version(), "scanner": "Semgrep 1.136.0 with three owned rules",
        "runner": "native-same-user; no airgap claim", "human_approval": "none; experiment never approves"})
    rows = []
    for index, (seed, case_id, strategy) in enumerate(order, 1):
        job = run(store, case_id, strategy, seed, args.attempts)
        write(output / "jobs" / (job["id"] + ".json"), job)
        rows.append(row(job, cases[case_id]))
        write(output / "runs.json", rows)
        print(json.dumps({"progress": f"{index}/{len(order)}", **rows[-1]}), flush=True)
    summary = summarize(rows, started)
    write(output / "summary.json", summary)
    with (output / "runs.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(json.dumps({"summary": [g for g in summary["groups"] if g["split"] == "all" and g["kind"] == "all"]}), flush=True)


if __name__ == "__main__":
    main()
