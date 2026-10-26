"""Model measurement on the L3 set, evaluation or development side (ROADMAP.md week 6).

Every ready evaluation case of l3/catalog.yml, one job each: the local model (region mode where
the file is too large for it), guided+context, memory off, three attempts, experiment jobs (never
approved, never in memory). OWASP Benchmark's safe cases stay in the denominator: the witness
passes on their original code, so the baseline is not valid and the job must return to a human
before any model call. Every accepted candidate then gets the case's hidden tests (l3_hidden.py),
which the verifier never ran; a candidate that fails them was a false acceptance.

Needs worker1 (Ollama running), worker2 and the runner started with PROJECTS_DIR=.runtime/l3/projects
SAFEPATCH_PROFILE=evaluation RUNNER_SANDBOX=docker SANDBOX_MAVEN_CACHE=<wsl path>; the same
variables here. `--split development` measures the owned development cases instead (lab profile,
native runner; PROJECTS_DIR must register all of them): Semgrep findings where the descriptor
has no answer key, no hidden tests. That side is for developing changes; the evaluation side
is not tuned on. Resumable: run it again with the same EVIDENCE_DIR and --run, finished cases are
skipped. Writes EVIDENCE_DIR/l3-model/: protocol.json (resume-*.json on later starts), one
jobs/<case>.json per finished job and summary.json once every case is done. The model's answers
touch third-party code, so they stay in .runtime/l3-measure/<run>/ (not in Git); the evidence
keeps their digests.
"""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from safepatch.common import POLICY, digest, evidence, setting
from safepatch.engine import Engine
from safepatch.repository import project, registry
from safepatch.store import Store
from safepatch.worker1 import REGION_SYSTEM, SYSTEM, WEAKNESS_NOTES
from l3_catalog import CATALOG, load
from l3_hidden import ACCEPTED, accepted_edits, hidden_result
from prepare_vul4j import L3
from vul4j_model import attempt_row

SEED = 42


def ready_cases(split="evaluation"):
    return [c for c in load().cases if c.split == split and c.status == "ready"]


def run(store, case_id, commit, seed, scanner="known"):
    now = time.time()
    job = {"id": uuid.uuid4().hex, "case_id": case_id, "base_commit": commit, "project": registry()[1][case_id]["project"],
           "policy_version": POLICY, "scanner": scanner, "mode": "real-local-model", "evaluation": True,
           "status": "queued", "owner": "EXPERIMENT-NOT-A-HUMAN", "started_at": now, "deadline": now + 1800, "max_attempts": 3,
           "attempt_count": 0, "attempts": [], "events": [], "approval": None, "memory_mode": "off", "strategy": "guided+context", "seed": seed}
    store.create(job, job["id"])
    start = time.perf_counter()
    Engine(store).run(job["id"])
    return store.get(job["id"]), round(time.perf_counter() - start, 1)


def measure(case, store, private, seed):
    commit = registry()[1][case.id]["commit"]
    spec = project(case.id, commit)
    labels, scanner = spec.labels, "known" if spec.scan.known else "semgrep"
    job, seconds = run(store, case.id, commit, seed, scanner)
    for attempt in job["attempts"]:
        for edit in (attempt["proposal"].get("patch") or {}).get("edits", []):
            (private / f"{case.id}-attempt{attempt['number']}-{Path(edit['path']).name}").write_text(edit["content"], encoding="utf-8", newline="")
    row = {"case": case.id, "cwe": case.cwe, "project": case.project, "source": case.source, "scanner": scanner,
           "vulnerable": labels.get("benchmark_real", "true") == "true", "seed": seed, "job": job["id"],
           "status": job["status"], "reason": job.get("reason"), "wall_seconds": seconds,
           "attempts": [attempt_row(a) for a in job["attempts"]], "hidden": None, "false_acceptance": None}
    if job["status"] in ACCEPTED and case.hidden is not None:
        edits, number = accepted_edits(job)
        row["accepted_attempt"] = number
        try:
            row["hidden"] = hidden_result(case.id, commit, edits)
            row["false_acceptance"] = not row["hidden"]["passed"]
        except Exception as exc:   # recorded, not retried: the job itself is done
            row["hidden"] = {"error": f"{type(exc).__name__}: {exc}"[:300]}
    return row


def summarize(rows):
    def counts(selected):
        accepted = [r for r in selected if r["status"] in ACCEPTED]
        return {"jobs": len(selected), "statuses": dict(Counter(r["status"] for r in selected)),
                "reasons": dict(Counter(r["reason"] for r in selected if r["reason"])),
                "accepted": len(accepted), "false_acceptances": sum(bool(r["false_acceptance"]) for r in accepted),
                "accepted_and_hidden_passed": sum(r["false_acceptance"] is False for r in accepted),
                "model_attempts": sum(len(r["attempts"]) for r in selected)}
    vulnerable = [r for r in rows if r["vulnerable"]]
    return {"jobs": len(rows), "vulnerable": counts(vulnerable), "safe": counts([r for r in rows if not r["vulnerable"]]),
            "by_cwe": {cwe: counts([r for r in vulnerable if r["cwe"] == cwe]) for cwe in sorted({r["cwe"] for r in rows})},
            "by_source": {s: counts([r for r in vulnerable if r["source"] == s]) for s in sorted({r["source"] for r in rows})}}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run", required=True, help="name of this run; the same name resumes it")
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--cases", nargs="+", help="only these cases (a trial; no summary is written)")
    parser.add_argument("--split", choices=("evaluation", "development"), default="evaluation")
    args = parser.parse_args()
    if args.split == "evaluation":
        for name, value in (("SAFEPATCH_PROFILE", "evaluation"), ("RUNNER_SANDBOX", "docker")):
            if setting(name) != value:
                raise SystemExit(f"set {name}={value} (and start the services with it)")
        if Path(setting("PROJECTS_DIR", "")).resolve() != (L3 / "projects").resolve():
            raise SystemExit("set PROJECTS_DIR=.runtime/l3/projects (and start the services with it)")
    else:
        missing = [c.id for c in ready_cases("development") if c.id not in registry()[1]]
        if setting("SAFEPATCH_PROFILE") != "lab" or missing:
            raise SystemExit(f"set SAFEPATCH_PROFILE=lab and a PROJECTS_DIR registering every development case (missing: {missing})")
    for service, port in (("WORKER1", 8101), ("WORKER2", 8102)):
        os.environ.setdefault(service + "_URL", f"http://127.0.0.1:{port}")
        os.environ[service + "_TOKEN_FILE"] = str(ROOT / ".secrets" / (service.lower() + "_token"))
    out = evidence("l3-model")
    if (out / "summary.json").exists():
        raise SystemExit("Use a fresh EVIDENCE_DIR; evidence is never overwritten")
    cases = ready_cases(args.split)
    if args.cases:
        cases = [c for c in cases if c.id in args.cases]
    private = ROOT / ".runtime/l3-measure" / args.run
    private.mkdir(parents=True, exist_ok=True)
    store = Store("sqlite:///" + (private / "jobs.db").as_posix())
    (out / "jobs").mkdir(parents=True, exist_ok=True)
    git = lambda *a: subprocess.run(["git", *a], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    started = {"started_at": time.time(), "git_commit": git("rev-parse", "HEAD"),
               "git_dirty": bool(git("status", "--porcelain", "--untracked-files=no")), "run": args.run, "split": args.split,
               # the prompt composer that served this run (worker1 runs as its own service)
               "worker1_sha256": digest((ROOT / "safepatch/worker1.py").read_bytes()),
               "cases": [c.id for c in cases if not (out / "jobs" / f"{c.id}.json").exists()]}
    first = not (out / "protocol.json").exists()
    record = out / "protocol.json" if first else out / f"resume-{int(started['started_at'])}.json"
    record.write_text(json.dumps({
        "schema": 1, **started, **({
            "what": "L3 evaluation set repaired by the local model, verified in the Docker sandbox; accepted candidates given the hidden tests",
            "catalog_sha256": digest(CATALOG.read_bytes()), "seed": args.seed, "strategy": "guided+context",
            "memory_mode": "off", "max_attempts": 3, "job_deadline_seconds": 1800, "scanner": "known (answer key; the witness decides)",
            "model": setting("OLLAMA_MODEL", "qwen2.5-coder:7b-instruct-q4_K_M"), "system_sha256": digest(SYSTEM),
            "region_system_sha256": digest(REGION_SYSTEM), "weakness_notes_sha256": {k: digest(v) for k, v in sorted(WEAKNESS_NOTES.items())},
            "experiment_jobs": "evaluation=true: never approved, never in memory; owner EXPERIMENT-NOT-A-HUMAN"} if first else {})}, indent=2) + "\n", encoding="utf-8")
    for case in cases:
        path = out / "jobs" / f"{case.id}.json"
        if path.exists():
            continue
        row = measure(case, store, private, args.seed)
        path.write_text(json.dumps(row, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(json.dumps({k: row[k] for k in ("case", "vulnerable", "status", "reason", "wall_seconds", "false_acceptance")}), flush=True)
    if args.cases:
        return
    rows = [json.loads((out / "jobs" / f"{c.id}.json").read_text(encoding="utf-8")) for c in ready_cases(args.split)]
    summary = {"run": args.run, **summarize(rows), "rows": [{k: r[k] for k in ("case", "cwe", "vulnerable", "status", "reason", "false_acceptance")} for r in rows]}
    (out / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({k: summary[k] for k in ("jobs", "vulnerable", "safe")}, indent=2), "\nwritten:", out, "; model answers:", private)


if __name__ == "__main__":
    main()
