"""Week 10 analysis of the main experiment (docs/DENEY_PROTOKOLU.md, "Analiz").

Reads EVIDENCE_DIR/experiment (the rows scripts/main_experiment.py wrote) and writes
EVIDENCE_DIR/analiz/analysis.json. Nothing runs again: every number comes from the stored rows.

Pre-declared: the paired comparisons C-A, C-B and C+L2-C on the primary outcome (the verifier
accepted and the hidden tests passed) over (case, seed) pairs of the vulnerable cases, with an
exact McNemar test and a 95% bootstrap interval of the difference in correct-repair rate that
resamples cases (a case keeps its three seeds); in total, per CWE family and per seed.
Extra comparisons and the split of jobs by what memory sent to the model are exploratory: they
were chosen after the results were seen, and are labelled so. With --previous (ana-2, declared in
docs/DENEY_ANA2.md) each arm is also compared with the same arm of the earlier run.
"""
import argparse
from collections import Counter, defaultdict
from hashlib import sha256
import json
from math import comb
from pathlib import Path
import random
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from safepatch.common import evidence

ARMS = ("A", "B", "C", "C+L2")
DECLARED = (("C", "A"), ("C", "B"), ("C+L2", "C"))
EXTRA = (("B", "A"), ("C+L2", "A"))
ITERATIONS, BOOTSTRAP_SEED = 10000, 20261028


def load(folder):
    """The rows and a digest binding the analysis to their exact bytes."""
    files = sorted((folder / "runs").glob("*/*.json"))
    hashed = sha256()
    for file in files:
        hashed.update(file.relative_to(folder).as_posix().encode() + b"\0" + file.read_bytes())
    return [json.loads(f.read_text(encoding="utf-8")) for f in files], hashed.hexdigest()


def mcnemar(only_x, only_y):
    """Exact two-sided McNemar test: a binomial test on the discordant pairs."""
    n = only_x + only_y
    if n == 0:
        return 1.0
    return min(1.0, 2 * sum(comb(n, i) for i in range(min(only_x, only_y) + 1)) / 2**n)


def holm(pvalues):
    """Holm-adjusted p-values, in the order given."""
    order = sorted(range(len(pvalues)), key=lambda i: pvalues[i])
    adjusted, running = [0.0] * len(pvalues), 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (len(pvalues) - rank) * pvalues[i]))
        adjusted[i] = running
    return adjusted


def correct(rows):
    """{(arm, case, seed): primary outcome} for the vulnerable cases; a hidden-test error is not a pass."""
    return {(r["arm"], r["case"], r["seed"]): r["correct"] is True for r in rows if r["vulnerable"]}


def paired(outcome, x, y, keys):
    keys = sorted(keys)
    both = sum(outcome[(x, *k)] and outcome[(y, *k)] for k in keys)
    only_x = sum(outcome[(x, *k)] and not outcome[(y, *k)] for k in keys)
    only_y = sum(outcome[(y, *k)] and not outcome[(x, *k)] for k in keys)
    n = len(keys)
    return {"pairs": n, "both": both, "only_" + x: only_x, "only_" + y: only_y, "neither": n - both - only_x - only_y,
            "correct_" + x: both + only_x, "correct_" + y: both + only_y,
            "difference": round((only_x - only_y) / n, 4) if n else None, "mcnemar_p": round(mcnemar(only_x, only_y), 4)}


def interval(keys, value, iterations=ITERATIONS, seed=BOOTSTRAP_SEED):
    """95% percentile interval of sum(value)/pairs, resampling cases (a case keeps all its seeds)."""
    per_case = defaultdict(lambda: [0, 0])
    for case, s in keys:
        per_case[case][0] += value(case, s)
        per_case[case][1] += 1
    cases = sorted(per_case)
    if not cases:
        return None
    rng, values = random.Random(seed), []
    for _ in range(iterations):
        drawn = [per_case[rng.choice(cases)] for _ in cases]
        values.append(sum(v for v, _ in drawn) / sum(n for _, n in drawn))
    values.sort()
    return [round(values[int(0.025 * iterations)], 4), round(values[int(0.975 * iterations) - 1], 4)]


def bootstrap(outcome, x, y, keys, **options):
    """Interval of rate(x) - rate(y) over the same pairs."""
    return interval(keys, lambda case, s: outcome[(x, case, s)] - outcome[(y, case, s)], **options)


def rate_interval(outcome, arm, keys, **options):
    return interval(keys, lambda case, s: outcome[(arm, case, s)], **options)


def compare(rows, outcome, x, y):
    keys = {(r["case"], r["seed"]) for r in rows if r["vulnerable"]}
    family = {r["case"]: r["cwe"] for r in rows}
    result = {"total": {**paired(outcome, x, y, keys), "bootstrap_95": bootstrap(outcome, x, y, keys)}}
    result["by_cwe"] = {c: {**paired(outcome, x, y, {k for k in keys if family[k[0]] == c}),
                            "bootstrap_95": bootstrap(outcome, x, y, {k for k in keys if family[k[0]] == c})}
                        for c in sorted(set(family[k[0]] for k in keys))}
    result["by_seed"] = {str(s): paired(outcome, x, y, {k for k in keys if k[1] == s}) for s in sorted({k[1] for k in keys})}
    return result


def arm_summary(rows, outcome):
    keys = {(r["case"], r["seed"]) for r in rows if r["vulnerable"]}
    out = {}
    for arm in ARMS:
        mine = [r for r in rows if r["arm"] == arm and r["vulnerable"]]
        accepted = [r for r in mine if r["accepted"]]
        used = [r for r in mine if r["memory"]["selected_id"]]
        safe = [r for r in rows if r["arm"] == arm and not r["vulnerable"]]
        out[arm] = {"jobs": len(mine), "correct": sum(r["correct"] is True for r in mine),
                    "rate": round(sum(r["correct"] is True for r in mine) / len(mine), 4), "rate_bootstrap_95": rate_interval(outcome, arm, keys),
                    "accepted": len(accepted), "false_acceptances": sum(r["false_acceptance"] is True for r in mine),
                    "hidden_errors": sum(r["accepted"] and r["correct"] is None for r in mine),
                    "accepted_attempt": dict(sorted(Counter(r.get("accepted_attempt") for r in accepted).items())),
                    "wall_seconds_median": round(statistics.median(r["wall_seconds"] for r in mine), 1),
                    "memory_used": len(used), "wrong_transfer": sum(r["false_acceptance"] is True for r in used),
                    "warnings_sent_jobs": sum(r["memory"]["warnings_sent"] > 0 for r in mine),
                    "warnings_withheld_jobs": sum(r["memory"].get("warnings_withheld", 0) > 0 for r in mine),
                    "memory_use": dict(Counter(f'{r["memory"]["tier"]}:{r["memory"]["use"]}' for r in used)),
                    "different_shape_examples": sum(r["memory"]["same_shape"] is False for r in used),
                    "reasons_not_accepted": dict(Counter(r["reason"] for r in mine if not r["accepted"])),
                    "safe_jobs": len(safe), "safe_stopped_before_model": sum(not r["attempts"] and not r["accepted"] for r in safe),
                    "infrastructure_retries": sum(bool(r["infrastructure_retry"]) for r in mine + safe)}
    return out


def memory_class(row):
    """What memory sent to the model in this job (exploratory)."""
    example, warned = bool(row["memory"]["use"]), bool(row["memory"]["warnings_sent"])
    return {(True, True): "example_and_warnings", (True, False): "example_only",
            (False, True): "warnings_only", (False, False): "neither"}[(example, warned)]


def attempt_outcome(attempt):
    if attempt.get("passed"):
        return "passed"
    if isinstance(attempt.get("failure"), dict):
        return attempt["failure"]["category"]
    return attempt.get("policy_error") or attempt.get("stopped") or "unknown"


def failures(rows):
    return dict(sorted(Counter(attempt_outcome(a) for r in rows for a in r["attempts"]).items()))


def exploratory(rows, outcome):
    """Each memory arm's jobs split by what memory sent, paired with A on the same case and seed."""
    by_key = {(r["arm"], r["case"], r["seed"]): r for r in rows if r["vulnerable"]}
    out = {}
    for arm in ("B", "C", "C+L2"):
        groups = defaultdict(list)
        for r in rows:
            if r["arm"] == arm and r["vulnerable"]:
                groups[memory_class(r)].append(r)
        out[arm] = {}
        for name, mine in sorted(groups.items()):
            keys = {(r["case"], r["seed"]) for r in mine}
            out[arm][name] = {**paired(outcome, arm, "A", keys),
                              "attempt_outcomes_" + arm: failures(mine),
                              "attempt_outcomes_A": failures([by_key[("A", *k)] for k in sorted(keys)])}
        out[arm]["by_tier"] = {tier: paired(outcome, arm, "A", {(r["case"], r["seed"]) for r in rows
                                                                 if r["arm"] == arm and r["vulnerable"] and r["memory"]["tier"] == tier})
                               for tier in sorted({r["memory"]["tier"] for r in rows if r["arm"] == arm and r["memory"]["use"]})}
    return out


def warning_kinds(rows, private):
    """Relation and failure category of every failure warning sent to the model, counted from the
    arms' local databases (.runtime/experiment/<run>; not in Git: they hold model answers on
    third-party code). Only counts and the databases' digests reach the evidence."""
    from safepatch.store import Store
    vulnerable = {r["job"] for r in rows if r["vulnerable"] and "job" in r}
    kinds, digests = defaultdict(lambda: defaultdict(Counter)), {}
    for db in sorted(private.glob("*.db")):
        arm = db.stem.partition("-")[2]
        if arm not in ("C", "C+L2"):
            continue
        digests[db.name] = sha256(db.read_bytes()).hexdigest()
        for job in Store("sqlite:///" + db.as_posix()).all():
            lookup = job.get("memory_lookup") or {}
            if job["id"] not in vulnerable:
                continue
            group = "with_example" if lookup.get("selected_id") else "warnings_only"
            for warning in lookup.get("warnings_sent") or []:
                kinds[arm][group][f'{warning["relation"]}/{warning["failure"]}'] += 1
    return {"databases_sha256": digests,
            "kinds": {arm: {g: dict(sorted(c.items())) for g, c in sorted(groups.items())} for arm, groups in sorted(kinds.items())}}


def ceiling(rows, outcome):
    """How many vulnerable cases any arm could change: never, always or sometimes repaired."""
    solved = defaultdict(int)
    runs = defaultdict(int)
    for (arm, case, s), ok in outcome.items():
        solved[case] += ok
        runs[case] += 1
    never = sorted(c for c in solved if solved[c] == 0)
    always = sorted(c for c in solved if solved[c] == runs[c])
    return {"cases": len(solved), "never_repaired": len(never), "always_repaired": len(always),
            "sometimes": len(solved) - len(never) - len(always), "always_cases": always}


def cross_run(rows, previous):
    """Each arm against the same arm of an earlier run (ana-2 against ana-1), same case and seed.
    An arm the change between the runs does not touch (A, B) shows how far a rerun alone moves the
    outcome; identical attempt hashes show whether the model answered the same way again."""
    outcome = {(f"{a}@run", c, s): v for (a, c, s), v in correct(rows).items()}
    outcome |= {(f"{a}@previous", c, s): v for (a, c, s), v in correct(previous).items()}
    patches = lambda selected: {(r["arm"], r["case"], r["seed"]): [a.get("patch_sha256") for a in r["attempts"]] for r in selected if r["vulnerable"]}
    now, before = patches(rows), patches(previous)
    out = {}
    for arm in ARMS:
        keys = {k[1:] for k in now if k[0] == arm} & {k[1:] for k in before if k[0] == arm}
        if keys:
            x, y = arm + "@run", arm + "@previous"
            out[arm] = {**paired(outcome, x, y, keys), "bootstrap_95": bootstrap(outcome, x, y, keys),
                        "same_attempt_patches": sum(now[(arm, *k)] == before[(arm, *k)] for k in keys)}
    return out


def analyze(folder, private=None, previous=None):
    rows, runs_sha256 = load(folder)
    outcome = correct(rows)
    declared = {f"{x}-{y}": compare(rows, outcome, x, y) for x, y in DECLARED}
    adjusted = holm([d["total"]["mcnemar_p"] for d in declared.values()])
    for d, p in zip(declared.values(), adjusted):
        d["total"]["holm_p"] = round(p, 4)
    protocol = folder / "protocol.json"
    if previous:
        earlier, earlier_sha256 = load(previous)
        run_of = lambda f: json.loads((f / "protocol.json").read_text(encoding="utf-8")).get("run") if (f / "protocol.json").exists() else None
        previous = {"run": run_of(previous), "rows": len(earlier), "runs_sha256": earlier_sha256, "arms": cross_run(rows, earlier)}
    return {"schema": 1, "protocol": json.loads(protocol.read_text(encoding="utf-8")).get("protocol", "docs/DENEY_PROTOKOLU.md") if protocol.exists() else "docs/DENEY_PROTOKOLU.md",
            "inputs": {"rows": len(rows), "runs_sha256": runs_sha256,
                       "protocol_sha256": sha256(protocol.read_bytes()).hexdigest() if protocol.exists() else None,
                       "run": json.loads(protocol.read_text(encoding="utf-8")).get("run") if protocol.exists() else None},
            "method": {"outcome": "verifier accepted AND hidden tests passed; a hidden-test error counts as not passed",
                       "test": "exact two-sided McNemar (binomial on discordant case-seed pairs); Holm over the three declared comparisons",
                       "interval": f"95% percentile bootstrap, {ITERATIONS} resamples of cases (each with all its seeds), random seed {BOOTSTRAP_SEED}"},
            "arms": arm_summary(rows, outcome), "declared": declared,
            "extra_comparisons_exploratory": {f"{x}-{y}": compare(rows, outcome, x, y) for x, y in EXTRA},
            "memory_split_exploratory": exploratory(rows, outcome),
            "warnings_sent_exploratory": warning_kinds(rows, private) if private and private.is_dir() else None,
            "ceiling": ceiling(rows, outcome),
            **({"cross_run": previous} if previous else {})}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--private", type=Path, help="the run's local databases (default .runtime/experiment/<run>)")
    parser.add_argument("--previous", type=Path, help="an earlier run's experiment folder to compare arm by arm (ana-2 against ana-1)")
    args = parser.parse_args()
    source, out = evidence("experiment"), evidence("analiz")
    if not (source / "summary.json").exists():
        raise SystemExit(f"{source} has no finished run (summary.json)")
    target = out / "analysis.json"
    if target.exists():
        raise SystemExit("evidence is never overwritten; use a fresh EVIDENCE_DIR")
    out.mkdir(parents=True, exist_ok=True)
    run = json.loads((source / "protocol.json").read_text(encoding="utf-8"))["run"] if (source / "protocol.json").exists() else None
    if args.previous and not (args.previous / "summary.json").exists():
        raise SystemExit(f"{args.previous} has no finished run (summary.json)")
    result = analyze(source, args.private or (ROOT / ".runtime" / "experiment" / run if run else None), args.previous)
    target.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({k: v["total"] for k, v in result["declared"].items()}, indent=1), "\nwritten:", target)


if __name__ == "__main__":
    main()
