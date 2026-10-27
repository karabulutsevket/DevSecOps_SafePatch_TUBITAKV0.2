"""Main experiment (ROADMAP.md week 9): arms A, B, C and C+L2, as fixed in docs/DENEY_PROTOKOLU.md.

`l2`: the C+L2 arm's package. Every development case with a reference fix (experiment_coverage.
REFERENCE) gets a job with no model attempt (its baseline scan only), then the reference fix as
an expert's patch, verified like any patch. Accepted fixes are approved by SIMULATED-EXPERIMENT-
REVIEWER into a lab database and signed into an experiment package (scripts/l2_build.py rules)
with a key made for the experiment. Services: PROJECTS_DIR=.runtime/dev-all/projects, lab profile.

`run`: every (seed, arm) in the protocol's order. Each is its own institution with its own
database; the cases come in the seed's order, the same for every arm. A: memory off. B: the
record most similar by embeddings (memory_mode "similar"). C: SafePatch's rules (guarded). C+L2:
C with the L2 package installed before the first case. Every candidate the verifier accepts gets
the case's hidden tests and is then approved by SIMULATED-EXPERIMENT-REVIEWER into that arm's
memory (decision 2a), so later cases may use it. A job ending in an infrastructure error is run
once more; both are kept. Services: PROJECTS_DIR=.runtime/l3/projects, SAFEPATCH_PROFILE=
evaluation, RUNNER_SANDBOX=docker; `--split development` (lab profile, dev-all projects) is the
trial on owned cases. Resumable with the same EVIDENCE_DIR and --run; refused if safepatch/
changed since the run began. Writes EVIDENCE_DIR/experiment/: protocol.json, l2/ (package and
public key), runs/<seed>-<arm>/<case>.json, summary.json once every row exists. The model's
answers touch third-party code and stay in .runtime/experiment/<run>/.
"""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
from safepatch import l2
from safepatch.common import POLICY, SOURCE, Patch, digest, evidence, setting
from safepatch.engine import Engine
from safepatch.memory import Memory
from safepatch.repository import baseline, project, registry
from safepatch.store import Store
from safepatch.worker1 import EMBED_MODEL, SYSTEM, WEAKNESS_NOTES
from experiment_coverage import DEVELOPMENT, REFERENCE
from l2_build import lab_records
from l2_exit import approve, keypair
from l3_catalog import CATALOG, load
from l3_hidden import ACCEPTED, accepted_edits, hidden_result
from prepare_vul4j import L3
from vul4j_model import attempt_row

SEEDS = (42, 43, 44)
ARMS = {"A": "off", "B": "similar", "C": "guarded", "C+L2": "guarded"}
REVIEWER, AUTHOR = "SIMULATED-EXPERIMENT-REVIEWER", "SAFEPATCH-LAB-REFERENCE"


def arm_order(seed):
    """Arms rotate from seed to seed: 42 A B C C+L2, 43 B C C+L2 A, 44 C C+L2 A B."""
    names = list(ARMS)
    shift = SEEDS.index(seed) % len(names) if seed in SEEDS else 0
    return names[shift:] + names[:shift]


def case_order(seed, cases):
    """The seed's order of the cases, the same for every arm."""
    ids = sorted(c.id for c in cases)
    random.Random(seed).shuffle(ids)
    by_id = {c.id: c for c in cases}
    return [by_id[i] for i in ids]


def code_digest():
    return digest(b"".join(p.read_bytes() for p in sorted((ROOT / "safepatch").glob("*.py"))))


def new_job(store, case_id, memory_mode, seed, max_attempts=3, experiment=None):
    now = time.time()
    info = registry()[1][case_id]
    spec = project(case_id, info["commit"])
    job = {"id": uuid.uuid4().hex, "case_id": case_id, "base_commit": info["commit"], "project": info["project"], "policy_version": POLICY,
           "scanner": "known" if spec.scan.known else "builtin", "mode": "real-local-model",
           # Not an evaluation job: its database is this experiment's institution, never operational memory.
           "evaluation": False, "experiment": experiment, "status": "queued", "owner": "EXPERIMENT-NOT-A-HUMAN", "started_at": now,
           "deadline": now + 1800, "max_attempts": max_attempts, "attempt_count": 0, "attempts": [], "events": [], "approval": None,
           "memory_mode": memory_mode, "strategy": "guided+context", "seed": seed}
    store.create(job, job["id"])
    return job["id"]


def reference_patch(case_id, files):
    fixed = REFERENCE[case_id]
    if fixed is None:   # the -01 labs: the tests' own correct fix
        from mock_patches import correct_patch
        return correct_patch(case_id.split("-")[0], files)
    return Patch.model_validate({"edits": [{"path": SOURCE, "old_sha256": digest(files[SOURCE]), "content": fixed.read_text(encoding="utf-8")}],
                                 "rationale": "SafePatch lab reference fix"})


def build_l2(out, private):
    """The experiment's L2 package from the development reference fixes; returns (package, trusted)."""
    if Path(setting("PROJECTS_DIR", "")).resolve() != DEVELOPMENT.resolve() or setting("SAFEPATCH_PROFILE") != "lab":
        raise SystemExit("l2: set PROJECTS_DIR=.runtime/dev-all/projects and SAFEPATCH_PROFILE=lab (and for the services)")
    lab = Store("sqlite:///" + (private / "l2-lab.db").as_posix())
    rows = []
    for case_id in sorted(REFERENCE):
        job_id = new_job(lab, case_id, "off", 42, max_attempts=0, experiment={"phase": "l2-construction"})
        Engine(lab).run(job_id)
        job = lab.get(job_id)
        if not (job.get("baseline") or {}).get("baseline_valid"):
            rows.append({"case": case_id, "accepted": False, "reason": job.get("reason")})
            continue
        _, files = baseline(case_id, job["base_commit"])
        patch = reference_patch(case_id, files)
        lab.mutate(job_id, lambda j: j.update(status="needs_human", pending_expert_patch={"patch": patch.model_dump(), "author": AUTHOR, "submitted_at": time.time()}))
        Engine(lab).run(job_id)
        job = lab.get(job_id)
        row = {"case": case_id, "accepted": job["status"] == "awaiting_review", "reason": job.get("reason")}
        if row["accepted"]:
            row["memory_id"] = approve(lab, job, REVIEWER, "Experiment-only: SafePatch lab reference fix, verified")["id"]
        rows.append(row)
        print(json.dumps(row), flush=True)
    key, trusted = private / "experiment-publisher", private / "experiment-publisher.allowed_signers"
    if not key.exists():   # a resumed construction keeps its key
        key, trusted = keypair(private, "experiment-publisher")
    package = l2.build(lab_records(lab, load()), "safepatch-lab", 1, key, private / "safepatch-l2-experiment-v1.zip", experiment=True)
    (out / "l2").mkdir(parents=True, exist_ok=True)
    shutil.copy2(package["path"], out / "l2" / "safepatch-l2-experiment-v1.zip")
    shutil.copy2(trusted, out / "l2" / "allowed_signers")
    (out / "l2" / "construction.json").write_text(json.dumps({"rows": rows, "package": package}, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(package), flush=True)


def lookup_row(job):
    lookup = job.get("memory_lookup") or {}
    chosen = next((c for c in lookup.get("considered", []) if c.get("id") == lookup.get("selected_id")), {})
    return {"decision": lookup.get("decision"), "tier": lookup.get("tier"), "use": lookup.get("use"), "selected_id": lookup.get("selected_id"),
            "considered": len(lookup.get("considered", [])), "same_shape": chosen.get("same_shape"), "similarity": chosen.get("similarity"),
            "warnings_sent": len(lookup.get("warnings_sent", []))}


def solve(store, case, seed, arm, position, private):
    """One case in one arm: the job (once more after an infrastructure error) and its hidden tests."""
    tries = []
    for _ in range(2):
        job_id = new_job(store, case.id, ARMS[arm], seed, experiment={"arm": arm, "seed": seed, "position": position})
        start = time.perf_counter()
        Engine(store).run(job_id)
        job = store.get(job_id)
        tries.append((job, round(time.perf_counter() - start, 1)))
        if job["status"] != "infrastructure_error":
            break
    job, seconds = tries[-1]
    for attempt in job["attempts"]:
        for edit in (attempt["proposal"].get("patch") or {}).get("edits", []):
            (private / f"{seed}-{arm}-{case.id}-attempt{attempt['number']}-{Path(edit['path']).name}").write_text(edit["content"], encoding="utf-8", newline="")
    labels = project(case.id, job["base_commit"]).labels
    row = {"case": case.id, "cwe": case.cwe, "project": case.project, "source": case.source, "vulnerable": labels.get("benchmark_real", "true") == "true",
           "seed": seed, "arm": arm, "position": position, "job": job["id"], "status": job["status"], "reason": job.get("reason"),
           "wall_seconds": seconds, "attempts": [attempt_row(a) for a in job["attempts"]], "memory": lookup_row(job),
           "infrastructure_retry": [{"job": j["id"], "reason": j.get("reason"), "wall_seconds": s} for j, s in tries[:-1]],
           "accepted": job["status"] in ACCEPTED, "hidden": None, "false_acceptance": None, "correct": None, "promoted": None}
    if row["accepted"]:
        edits, number = accepted_edits(job)
        row["accepted_attempt"] = number
        if case.hidden is not None:
            try:
                row["hidden"] = hidden_result(case.id, job["base_commit"], edits)
                row["false_acceptance"] = not row["hidden"]["passed"]
                row["correct"] = row["hidden"]["passed"]
            except Exception as exc:   # recorded, not retried: the job itself is done
                row["hidden"] = {"error": f"{type(exc).__name__}: {exc}"[:300]}
    elif case.hidden is not None:
        row["correct"] = False
    return row


def promote(store, row):
    """Decision 2a: every candidate the verifier accepted enters the arm's memory (simulated approval)."""
    job = store.get(row["job"])
    return approve(store, job, REVIEWER, f"Experiment-only: accepted by the verifier in arm {row['arm']}, seed {row['seed']}")["id"]


def summarize(rows):
    def counts(selected):
        accepted = [r for r in selected if r["accepted"]]
        used = [r for r in selected if r["memory"]["selected_id"]]
        return {"jobs": len(selected), "accepted": len(accepted), "correct": sum(r["correct"] is True for r in selected),
                "false_acceptances": sum(r["false_acceptance"] is True for r in selected),
                "memory_used": len(used), "memory_used_correct": sum(r["correct"] is True for r in used),
                "wrong_transfer": sum(r["false_acceptance"] is True for r in used),
                "different_shape_examples": sum(r["memory"]["same_shape"] is False for r in used),
                "statuses": dict(Counter(r["status"] for r in selected)), "infrastructure_retries": sum(bool(r["infrastructure_retry"]) for r in selected)}
    out = {}
    for arm in ARMS:
        mine = [r for r in rows if r["arm"] == arm]
        vulnerable = [r for r in mine if r["vulnerable"]]
        out[arm] = {"vulnerable": counts(vulnerable), "safe": counts([r for r in mine if not r["vulnerable"]]),
                    "by_cwe": {c: counts([r for r in vulnerable if r["cwe"] == c]) for c in sorted({r["cwe"] for r in rows})},
                    "by_seed": {s: counts([r for r in vulnerable if r["seed"] == s]) for s in sorted({r["seed"] for r in rows})}}
    return out


def run(args, out, private):
    if args.split == "evaluation":
        for name, value in (("SAFEPATCH_PROFILE", "evaluation"), ("RUNNER_SANDBOX", "docker")):
            if setting(name) != value:
                raise SystemExit(f"set {name}={value} (and start the services with it)")
        if Path(setting("PROJECTS_DIR", "")).resolve() != (L3 / "projects").resolve():
            raise SystemExit("set PROJECTS_DIR=.runtime/l3/projects (and start the services with it)")
    elif setting("SAFEPATCH_PROFILE") != "lab" or Path(setting("PROJECTS_DIR", "")).resolve() != DEVELOPMENT.resolve():
        raise SystemExit("trial: set SAFEPATCH_PROFILE=lab and PROJECTS_DIR=.runtime/dev-all/projects (and for the services)")
    package, trusted = out / "l2" / "safepatch-l2-experiment-v1.zip", out / "l2" / "allowed_signers"
    if "C+L2" in args.arms and not package.exists():
        raise SystemExit("build the L2 package first: main_experiment.py l2 (with the same EVIDENCE_DIR)")
    cases = [c for c in load().cases if c.split == args.split and c.status == "ready" and (not args.cases or c.id in args.cases)]
    git = lambda *a: subprocess.run(["git", *a], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    protocol = out / "protocol.json"
    if protocol.exists():
        if json.loads(protocol.read_text(encoding="utf-8"))["code_sha256"] != code_digest():
            raise SystemExit("safepatch/ changed since this run began; a changed run starts again under a new name")
    else:
        protocol.write_text(json.dumps({
            "schema": 1, "run": args.run, "protocol": "docs/DENEY_PROTOKOLU.md", "started_at": time.time(), "git_commit": git("rev-parse", "HEAD"),
            "git_dirty": bool(git("status", "--porcelain", "--untracked-files=no")), "code_sha256": code_digest(), "split": args.split,
            "catalog_sha256": digest(CATALOG.read_bytes()), "seeds": args.seeds, "arms": {a: ARMS[a] for a in args.arms},
            "arm_order": {s: [a for a in arm_order(s) if a in args.arms] for s in args.seeds},
            "case_order": {s: [c.id for c in case_order(s, cases)] for s in args.seeds},
            "model": setting("OLLAMA_MODEL", "qwen2.5-coder:7b-instruct-q4_K_M"), "embedding_model": {"name": EMBED_MODEL[0], "digest": EMBED_MODEL[1]},
            "system_sha256": digest(SYSTEM), "weakness_notes_sha256": {k: digest(v) for k, v in sorted(WEAKNESS_NOTES.items())},
            "budget": {"strategy": "guided+context", "max_attempts": 3, "job_deadline_seconds": 1800, "scanner": "known (answer key) where defined"},
            "memory_admission": "2a: every candidate the verifier accepts, simulated approval by " + REVIEWER,
            "l2_package_sha256": digest(package.read_bytes()) if package.exists() else None,
            "human_approval": "SIMULATED", "customer_validation": "not performed"}, indent=2) + "\n", encoding="utf-8")
    for seed in args.seeds:
        for arm in [a for a in arm_order(seed) if a in args.arms]:
            folder = out / "runs" / f"{seed}-{arm}"
            folder.mkdir(parents=True, exist_ok=True)
            store = Store("sqlite:///" + (private / f"{seed}-{arm}.db").as_posix())
            if arm == "C+L2" and not l2.Shared(store).installed():
                l2.Shared(store).install(package, trusted)
            for position, case in enumerate(case_order(seed, cases), 1):
                path = folder / f"{case.id}.json"
                row = json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
                if row is None:
                    row = solve(store, case, seed, arm, position, private)
                    path.write_text(json.dumps(row, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
                    print(json.dumps({k: row[k] for k in ("seed", "arm", "position", "case", "status", "correct", "false_acceptance")} | {"memory": row["memory"]["use"]}), flush=True)
                # Written before the promotion, so a resumed run finishes an interrupted one.
                if row["accepted"] and row["promoted"] is None:
                    row["promoted"] = promote(store, row)
                    path.write_text(json.dumps(row, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    rows = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((out / "runs").glob("*/*.json"))]
    if args.cases or len(rows) < len(args.seeds) * len(args.arms) * len(cases):
        return
    (out / "summary.json").write_text(json.dumps({"run": args.run, "scope": args.split, "arms": summarize(rows)}, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({a: s["vulnerable"] for a, s in summarize(rows).items()}, indent=1), "\nwritten:", out)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("action", choices=("l2", "run"))
    parser.add_argument("--run", required=True, help="name of this run; the same name resumes it")
    parser.add_argument("--split", choices=("evaluation", "development"), default="evaluation")
    parser.add_argument("--seeds", nargs="+", type=int, default=list(SEEDS))
    parser.add_argument("--arms", nargs="+", choices=list(ARMS), default=list(ARMS))
    parser.add_argument("--cases", nargs="+", help="only these cases (a trial; no summary is written)")
    args = parser.parse_args()
    for service, port in (("WORKER1", 8101), ("WORKER2", 8102)):
        os.environ.setdefault(service + "_URL", f"http://127.0.0.1:{port}")
        os.environ[service + "_TOKEN_FILE"] = str(ROOT / ".secrets" / (service.lower() + "_token"))
    out = evidence("experiment")
    out.mkdir(parents=True, exist_ok=True)
    if (out / "summary.json").exists():
        raise SystemExit("Use a fresh EVIDENCE_DIR; evidence is never overwritten")
    private = ROOT / ".runtime" / "experiment" / args.run
    private.mkdir(parents=True, exist_ok=True)
    if args.action == "l2":
        if (out / "l2" / "safepatch-l2-experiment-v1.zip").exists():
            raise SystemExit("this EVIDENCE_DIR already has its L2 package")
        build_l2(out, private)
    else:
        run(args, out, private)


if __name__ == "__main__":
    main()
