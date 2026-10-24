"""Recompute the H2 retry-experiment numbers from raw job files (no hand-typed numbers).

Writes analysis.json next to the run. Paired comparisons use the exact McNemar test
over (case, seed) pairs; pairs share cases, so they are not independent projects.
"""
import collections
import json
import math
from pathlib import Path
import re
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from safepatch.common import evidence

# normalize() is purely lexical (it never reads the file system); toRealPath() resolves
# symbolic links. The current path witness only tries '../secret.txt'.
REAL_PATH = re.compile(r"resolve\([^)]*\)[^;]*toRealPath\(")


def mcnemar(key, pairs, a, b):
    only_b = sum(key[(b, *p)] and not key[(a, *p)] for p in pairs)
    only_a = sum(key[(a, *p)] and not key[(b, *p)] for p in pairs)
    n = only_a + only_b
    p = min(1.0, 2 * sum(math.comb(n, k) for k in range(min(only_a, only_b) + 1)) / 2 ** n) if n else 1.0
    return {"baseline": a, "compared": b, "only_compared_solved": only_b, "only_baseline_solved": only_a, "exact_p_two_sided": round(p, 5)}


def main():
    run = evidence("retry")
    rows = json.loads((run / "runs.json").read_text(encoding="utf-8"))
    jobs = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((run / "jobs").glob("*.json"))]
    strategies = list(dict.fromkeys(r["strategy"] for r in rows))
    rate = lambda group: {"accepted": sum(r["accepted"] for r in group), "n": len(group)}
    by = {s: {"all": rate([r for r in rows if r["strategy"] == s]),
              **{k: rate([r for r in rows if r["strategy"] == s and r["kind"] == k]) for k in ("sql", "path", "command")},
              **{x: rate([r for r in rows if r["strategy"] == s and r["split"] == x]) for x in ("development", "evaluation")},
              **{f"seed_{z}": rate([r for r in rows if r["strategy"] == s and r["seed"] == z]) for z in sorted({r["seed"] for r in rows})}}
          for s in strategies}
    key = {(r["strategy"], r["case_id"], r["seed"]): r["accepted"] for r in rows}
    pairs = sorted({(r["case_id"], r["seed"]) for r in rows})
    paired = [mcnemar(key, pairs, "v01", s) for s in strategies if s != "v01"] + [mcnemar(key, pairs, "guided", "guided+context")]
    per_case = {c: {s: sum(key[(s, c, z)] for (cc, z) in pairs if cc == c) for s in strategies} for c in sorted({p[0] for p in pairs})}
    timing = {s: {"median_wall_seconds": statistics.median(r["wall_seconds"] for r in rows if r["strategy"] == s),
                  "median_wall_seconds_accepted": statistics.median([r["wall_seconds"] for r in rows if r["strategy"] == s and r["accepted"]] or [0]),
                  "attempts_of_accepted": dict(collections.Counter(str(r["attempts"]) for r in rows if r["strategy"] == s and r["accepted"])),
                  "stop_reasons": dict(collections.Counter(r["reason"] for r in rows if r["strategy"] == s and r["reason"]))} for s in strategies}
    path_quality = collections.defaultdict(lambda: {"accepted": 0, "real_path_on_target": 0, "lexical_normalize_only": 0})
    for job in jobs:
        if job["status"] != "awaiting_review" or not job["case_id"].startswith("path"):
            continue
        content = next(a for a in reversed(job["attempts"]) if a.get("verification", {}).get("passed"))["proposal"]["patch"]["edits"][0]["content"]
        q = path_quality[job["strategy"]]
        q["accepted"] += 1
        q["real_path_on_target" if REAL_PATH.search(content) else "lexical_normalize_only"] += 1
    first_patch_same = {s: sum(len({j["attempts"][0].get("patch_sha256") for j in jobs if j["strategy"] == s and j["case_id"] == c}) == 1 for c in per_case) for s in ("v01", "sampling")}
    dropped = collections.Counter("+".join(a["proposal"].get("metrics", {}).get("dropped_optional_context") or []) or "none"
                                  for j in jobs if j["strategy"] == "guided+context" for a in j["attempts"] if a["proposal"].get("metrics"))
    analysis = {"source": "runs.json and jobs/*.json in this folder", "n": len(rows), "by_strategy": by, "paired_mcnemar": paired,
                "per_case_accepted_of_3_seeds": per_case, "timing": timing, "path_fix_quality": dict(path_quality),
                "path_quality_note": "normalize() is lexical and does not resolve symbolic links; the current witness only tests '../secret.txt', so normalize-only fixes pass it",
                "first_attempt_patch_identical_across_seeds": first_patch_same, "guided_context_dropped_optional_context": dict(dropped),
                "pairs_note": "pairs are (case, seed); 9 synthetic cases from 3 families, so pairs are not independent projects"}
    (run / "analysis.json").write_text(json.dumps(analysis, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"by_strategy_all": {s: by[s]["all"] for s in strategies}, "paired": paired, "path_fix_quality": dict(path_quality)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
