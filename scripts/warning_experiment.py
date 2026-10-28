"""Failure-warning experiment (docs/DENEY_UYARI.md): arm C against C without failure warnings.

In the main experiment, jobs that got only failure warnings did worse than the same cases with
memory off (docs/OLCUM_SONUCLARI_V02.md, exploratory). This tests that on the development cases,
never on the evaluation set. Arm C is SafePatch's rules as in the main experiment; arm C-W is the
same with the failure warnings withheld from the model (job field experiment_failure_warnings=
False, honoured by the engine in the lab and evaluation profiles only; the failures are still
found, recorded and listed as withheld). Everything else is the main experiment's: the seeded
case order shared by the arms, rotating arm order, a database per (seed, arm), admission 2a.
The development cases have no hidden tests, so the outcome is the verifier's acceptance.

Services: SAFEPATCH_PROFILE=lab, PROJECTS_DIR=.runtime/dev-all/projects. Resumable with the
same EVIDENCE_DIR and --run; refused if safepatch/ changed since the run began. Writes
EVIDENCE_DIR/deney/: protocol.json, runs/<seed>-<arm>/<case>.json, then summary.json and the
pre-declared analysis.json once every row exists.
"""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from safepatch.common import digest, evidence, setting
from safepatch.store import Store
from safepatch.worker1 import SYSTEM, WEAKNESS_NOTES
from experiment_analysis import bootstrap, paired
from experiment_coverage import DEVELOPMENT, contexts, key
from l3_catalog import CATALOG, load
from main_experiment import REVIEWER, case_order, code_digest, promote, solve

SEEDS = (42, 43, 44)
ARMS = {"C": ("guarded", None), "C-W": ("guarded", {"experiment_failure_warnings": False})}


def arm_order(seed):
    """Arms alternate from seed to seed: 42 C C-W, 43 C-W C, 44 C C-W."""
    names = list(ARMS)
    shift = SEEDS.index(seed) % len(names) if seed in SEEDS else 0
    return names[shift:] + names[:shift]


def cases():
    return [c for c in load().cases if c.split == "development" and c.status == "ready"]


def exposure(out):
    """Static and outcome-free, before the run: the development cases with a sibling of the same
    project, family, JDK and signature shape. Only those can get a failure warning, and only once
    such a sibling earlier in the order has failed."""
    target = out / "exposure.json"
    if target.exists():
        raise SystemExit("evidence is never overwritten; use a fresh EVIDENCE_DIR")
    ids = {c.id for c in cases()}
    # The -02/-03 labs' descriptors still say split "evaluation" (V0.1); the L3 catalog decides.
    found = {k: v for split in ("development", "evaluation") for k, v in contexts(DEVELOPMENT, split).items() if k in ids}
    rows = [{"case": case_id, "project": context["project"], "cwe_family": context["cwe_family"],
             "siblings": sorted(o for o, other in found.items() if o != case_id and other["project"] == context["project"]
                                and key(context)[2] and key(other) == key(context))}
            for case_id, context in sorted(found.items())]
    summary = {"cases": len(rows), "with_sibling": sum(bool(r["siblings"]) for r in rows),
               "by_family": {f: {"cases": n, "with_sibling": sum(bool(r["siblings"]) for r in rows if r["cwe_family"] == f)}
                             for f, n in sorted(Counter(r["cwe_family"] for r in rows).items())}}
    target.write_text(json.dumps({"scope": "static, outcome-free exposure before the warning experiment", "summary": summary, "cases": rows},
                                 indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=1), "\nwritten:", target)


def summarize(rows):
    def counts(selected):
        return {"jobs": len(selected), "accepted": sum(r["accepted"] for r in selected),
                "examples": sum(bool(r["memory"]["use"]) for r in selected),
                "warnings_sent_jobs": sum(r["memory"]["warnings_sent"] > 0 for r in selected),
                "warnings_withheld_jobs": sum(r["memory"].get("warnings_withheld", 0) > 0 for r in selected),
                "statuses": dict(Counter(r["status"] for r in selected)), "infrastructure_retries": sum(bool(r["infrastructure_retry"]) for r in selected)}
    out = {}
    for arm in ARMS:
        mine = [r for r in rows if r["arm"] == arm]
        out[arm] = {"total": counts(mine), "by_cwe": {c: counts([r for r in mine if r["cwe"] == c]) for c in sorted({r["cwe"] for r in rows})},
                    "by_seed": {s: counts([r for r in mine if r["seed"] == s]) for s in sorted({r["seed"] for r in rows})}}
    return out


def warned(row, only=False):
    """Did memory send (C) or withhold (C-W) failure warnings, optionally with no example?"""
    memory = row["memory"]
    told = memory["warnings_sent"] > 0 or memory.get("warnings_withheld", 0) > 0
    return told and not (only and memory["use"])


def analyze(rows):
    """The pre-declared analysis: C-W against C on acceptance, all pairs and the warned subgroups."""
    outcome = {(r["arm"], r["case"], r["seed"]): bool(r["accepted"]) for r in rows}
    by_key = {(r["arm"], r["case"], r["seed"]): r for r in rows}
    keys = {(r["case"], r["seed"]) for r in rows}

    def compare(selected):
        return {**paired(outcome, "C-W", "C", selected), "bootstrap_95": bootstrap(outcome, "C-W", "C", selected)}
    # The subgroups are defined by arm C's own job: where the model did get the warnings.
    only = {k for k in keys if warned(by_key[("C", *k)], only=True)}
    any_ = {k for k in keys if warned(by_key[("C", *k)])}
    family = {r["case"]: r["cwe"] for r in rows}
    return {"outcome": "verifier accepted (development cases have no hidden tests)",
            "primary": compare(keys),
            "secondary_c_sent_warnings_only": compare(only),
            "secondary_c_sent_any_warning": compare(any_),
            "c_w_withheld_jobs": sum(warned(by_key[("C-W", *k)]) for k in keys),
            "by_cwe_descriptive": {c: paired(outcome, "C-W", "C", {k for k in keys if family[k[0]] == c}) for c in sorted(set(family.values()))}}


def run(args, out, private):
    if setting("SAFEPATCH_PROFILE") != "lab" or Path(setting("PROJECTS_DIR", "")).resolve() != DEVELOPMENT.resolve():
        raise SystemExit("set SAFEPATCH_PROFILE=lab and PROJECTS_DIR=.runtime/dev-all/projects (and for the services)")
    chosen = [c for c in cases() if not args.cases or c.id in args.cases]
    git = lambda *a: subprocess.run(["git", *a], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    protocol = out / "protocol.json"
    if protocol.exists():
        if json.loads(protocol.read_text(encoding="utf-8"))["code_sha256"] != code_digest():
            raise SystemExit("safepatch/ changed since this run began; a changed run starts again under a new name")
    else:
        protocol.write_text(json.dumps({
            "schema": 1, "run": args.run, "protocol": "docs/DENEY_UYARI.md", "started_at": time.time(), "git_commit": git("rev-parse", "HEAD"),
            "git_dirty": bool(git("status", "--porcelain", "--untracked-files=no")), "code_sha256": code_digest(), "split": "development",
            "catalog_sha256": digest(CATALOG.read_bytes()), "seeds": args.seeds, "arms": {a: {"memory_mode": m, "fields": f} for a, (m, f) in ARMS.items()},
            "arm_order": {s: arm_order(s) for s in args.seeds}, "case_order": {s: [c.id for c in case_order(s, chosen)] for s in args.seeds},
            "model": setting("OLLAMA_MODEL", "qwen2.5-coder:7b-instruct-q4_K_M"), "system_sha256": digest(SYSTEM),
            "weakness_notes_sha256": {k: digest(v) for k, v in sorted(WEAKNESS_NOTES.items())},
            "budget": {"strategy": "guided+context", "max_attempts": 3, "job_deadline_seconds": 1800},
            "memory_admission": "2a: every candidate the verifier accepts, simulated approval by " + REVIEWER,
            "outcome": "verifier accepted (no hidden tests on the development cases)", "human_approval": "SIMULATED"}, indent=2) + "\n", encoding="utf-8")
    for seed in args.seeds:
        for arm in arm_order(seed):
            folder = out / "runs" / f"{seed}-{arm}"
            folder.mkdir(parents=True, exist_ok=True)
            store = Store("sqlite:///" + (private / f"{seed}-{arm}.db").as_posix())
            for position, case in enumerate(case_order(seed, chosen), 1):
                path = folder / f"{case.id}.json"
                row = json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
                if row is None:
                    row = solve(store, case, seed, arm, position, private, setup=ARMS[arm])
                    path.write_text(json.dumps(row, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
                    print(json.dumps({k: row[k] for k in ("seed", "arm", "position", "case", "status")}
                                     | {"example": row["memory"]["use"], "sent": row["memory"]["warnings_sent"], "withheld": row["memory"]["warnings_withheld"]}), flush=True)
                if row["accepted"] and row["promoted"] is None:
                    row["promoted"] = promote(store, row)
                    path.write_text(json.dumps(row, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    rows = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((out / "runs").glob("*/*.json"))]
    if args.cases or len(rows) < len(args.seeds) * len(ARMS) * len(chosen):
        return
    (out / "summary.json").write_text(json.dumps({"run": args.run, "arms": summarize(rows)}, indent=2) + "\n", encoding="utf-8")
    (out / "analysis.json").write_text(json.dumps(analyze(rows), indent=2) + "\n", encoding="utf-8")
    print(json.dumps(analyze(rows)["primary"], indent=1), "\nwritten:", out)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("action", choices=("exposure", "run"))
    parser.add_argument("--run", required=True, help="name of this run; the same name resumes it")
    parser.add_argument("--seeds", nargs="+", type=int, default=list(SEEDS))
    parser.add_argument("--cases", nargs="+", help="only these cases (a trial; no summary is written)")
    args = parser.parse_args()
    for service, port in (("WORKER1", 8101), ("WORKER2", 8102)):
        os.environ.setdefault(service + "_URL", f"http://127.0.0.1:{port}")
        os.environ[service + "_TOKEN_FILE"] = str(ROOT / ".secrets" / (service.lower() + "_token"))
    out = evidence("deney")
    out.mkdir(parents=True, exist_ok=True)
    if args.action == "exposure":
        return exposure(out)
    if (out / "summary.json").exists():
        raise SystemExit("Use a fresh EVIDENCE_DIR; evidence is never overwritten")
    private = ROOT / ".runtime" / "experiment" / args.run
    private.mkdir(parents=True, exist_ok=True)
    run(args, out, private)


if __name__ == "__main__":
    main()
