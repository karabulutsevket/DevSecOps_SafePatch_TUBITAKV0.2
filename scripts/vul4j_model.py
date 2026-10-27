"""VUL4J-79 with the real local model in region mode (ROADMAP.md week 5; L3 only).

ZipUtil.java (~98 KB) does not fit the model, so it sees the methods holding the four
answer-key findings and returns those; SafePatch puts them back into the file and verifies the
whole file in the JDK 8 sandbox like any patch. One job per seed: guided+context, memory off,
three attempts, experiment jobs (never approved, never enter memory).

Needs worker1 (Ollama running), worker2 and the runner started with PROJECTS_DIR=.runtime/l3/projects
SAFEPATCH_PROFILE=evaluation RUNNER_SANDBOX=docker SANDBOX_MAVEN_CACHE=<wsl path>.
Writes EVIDENCE_DIR/model/: protocol.json and summary.json. The model's diffs touch zt-zip code,
so they stay in .runtime/vul4j-model (not in Git); the evidence keeps their digests and sizes.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from safepatch.common import POLICY, digest, evidence, setting
from safepatch.engine import Engine
from safepatch.repository import registry
from safepatch.store import Store
from safepatch.worker1 import REGION_SYSTEM, WEAKNESS_NOTES
from prepare_vul4j import DERIVED, L3

CASE = "vul4j-79"


def attempt_row(attempt):
    proposal, verified = attempt["proposal"], attempt.get("verification") or {}
    metrics = proposal.get("metrics") or {}
    return {"number": attempt["number"], "edit_mode": metrics.get("edit_mode"),
            "regions_changed": [r["region"] for r in (proposal.get("region_patch") or {}).get("regions", [])],
            "imports_added": (proposal.get("region_patch") or {}).get("imports", []),
            "changed_lines": attempt.get("changed_lines"), "patch_sha256": attempt.get("patch_sha256"),
            "policy_error": attempt.get("policy_error"), "stopped": attempt.get("stopped"),
            "passed": verified.get("passed"), "failure": attempt.get("failure"), "no_change": attempt.get("no_change"),
            "build": (verified.get("build") or {}).get("passed"),
            "behavior": {k: (verified.get("behavior") or {}).get(k) for k in ("tests", "failures", "errors")},
            "security": {k: (verified.get("security") or {}).get(k) for k in ("tests", "failures", "errors")},
            "model_seconds": metrics.get("duration_seconds"), "prompt_tokens": metrics.get("prompt_tokens_measured"),
            "output_tokens": metrics.get("output_tokens_measured"), "dropped": metrics.get("dropped_optional_context")}


def run(store, seed):
    now = time.time()
    job = {"id": uuid.uuid4().hex, "case_id": CASE, "base_commit": DERIVED, "project": registry()[1][CASE]["project"],
           "policy_version": POLICY, "scanner": "known", "mode": "real-local-model", "evaluation": True,
           "status": "queued", "owner": "EXPERIMENT-NOT-A-HUMAN", "started_at": now, "deadline": now + 1800, "max_attempts": 3,
           "attempt_count": 0, "attempts": [], "events": [], "approval": None, "memory_mode": "off", "strategy": "guided+context", "seed": seed}
    store.create(job, job["id"])
    start = time.perf_counter()
    Engine(store).run(job["id"])
    job = store.get(job["id"])
    return job, round(time.perf_counter() - start, 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seeds", type=int, nargs="+", default=[42, 43, 44])
    args = parser.parse_args()
    if setting("SAFEPATCH_PROFILE") != "evaluation" or Path(setting("PROJECTS_DIR", "")).resolve() != (L3 / "projects").resolve():
        raise SystemExit("set SAFEPATCH_PROFILE=evaluation and PROJECTS_DIR=.runtime/l3/projects (and start the services with them)")
    for service, port in (("WORKER1", 8101), ("WORKER2", 8102)):
        os.environ.setdefault(service + "_URL", f"http://127.0.0.1:{port}")
        os.environ[service + "_TOKEN_FILE"] = str(ROOT / ".secrets" / (service.lower() + "_token"))
    out = evidence("model")
    if (out / "summary.json").exists():
        raise SystemExit("Use a fresh EVIDENCE_DIR; evidence is never overwritten")
    private = ROOT / ".runtime/vul4j-model" / uuid.uuid4().hex[:8]
    private.mkdir(parents=True)
    store = Store("sqlite:///" + (private / "jobs.db").as_posix())
    git = lambda *a: subprocess.run(["git", *a], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    out.mkdir(parents=True, exist_ok=True)
    (out / "protocol.json").write_text(json.dumps({
        "schema": 1, "what": "VUL4J-79 repaired by the local model in region mode, verified in the JDK 8 sandbox",
        "git_commit": git("rev-parse", "HEAD"), "git_dirty": bool(git("status", "--porcelain", "--untracked-files=no")),
        "started_at": time.time(), "seeds": args.seeds, "strategy": "guided+context", "memory_mode": "off", "max_attempts": 3,
        "scanner": "known (answer key; the witness decides)", "model": setting("OLLAMA_MODEL", "qwen2.5-coder:7b-instruct-q4_K_M"),
        "region_system_sha256": digest(REGION_SYSTEM), "weakness_note_cwe22_sha256": digest(WEAKNESS_NOTES["CWE-22"]),
        "experiment_jobs": "evaluation=true: never approved, never in memory; owner EXPERIMENT-NOT-A-HUMAN"}, indent=2) + "\n", encoding="utf-8")
    rows = []
    for seed in args.seeds:
        job, seconds = run(store, seed)
        for attempt in job["attempts"]:
            diff = next((e["content"] for e in (attempt["proposal"].get("patch") or {}).get("edits", [])), None)
            (private / f"seed{seed}-attempt{attempt['number']}.json").write_text(json.dumps(attempt["proposal"].get("region_patch"), indent=2), encoding="utf-8")
            if diff:
                (private / f"seed{seed}-attempt{attempt['number']}.java").write_text(diff, encoding="utf-8")
        rows.append({"seed": seed, "job": job["id"], "status": job["status"], "reason": job.get("reason"), "wall_seconds": seconds,
                     "attempts": [attempt_row(a) for a in job["attempts"]]})
        print(json.dumps({k: rows[-1][k] for k in ("seed", "status", "reason", "wall_seconds")}), flush=True)
    summary = {"case": "VUL4J-79", "jobs": len(rows), "verified": sum(r["status"] == "awaiting_review" for r in rows), "rows": rows}
    (out / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("verified", summary["verified"], "of", summary["jobs"], "; written:", out, "; model answers:", private)


if __name__ == "__main__":
    main()
