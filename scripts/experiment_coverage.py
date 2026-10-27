"""Before the main experiment (ROADMAP.md week 9): which evaluation cases could memory reach at all.

Static and outcome-free: no model call, no verification, no hidden test. For every ready
evaluation case it reads the memory context of its answer-key finding (CWE family, JDK,
structural signature) and counts:
- L2 matches: development cases with a reference fix of the same family, JDK and signature
  shape (what an L2 package of reference fixes could offer; projects may differ);
- L1 siblings: other vulnerable evaluation cases of the same project, family, JDK and shape
  (what an institution's own memory could offer once one of them is repaired and approved).
Matching follows safepatch/memory.py and safepatch/l2.py as they are; nothing is tuned here.

Needs .runtime/l3/projects (prepare_l3.py, prepare_benchmark.py) and .runtime/dev-all/projects
(every development descriptor). Writes EVIDENCE_DIR/coverage.json.
"""
from collections import Counter
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from safepatch.common import evidence
from safepatch.memory import SHAPE, context_for
from safepatch.repository import baseline, registry
from safepatch.weakness import family

EVALUATION = ROOT / ".runtime/l3/projects"
DEVELOPMENT = ROOT / ".runtime/dev-all/projects"
# Development cases with a reference fix: samples/variants/fixed, samples/package/fixed, and the
# three -01 labs (tests/mock_patches.correct_patch). The region cases have none.
REFERENCE = {**{f"variant-{p.stem}": p for p in sorted((ROOT / "samples/variants/fixed").glob("*.java"))},
             **{f"package-{p.stem}": p for p in sorted((ROOT / "samples/package/fixed").glob("*.java"))},
             **{f"{kind}-01": None for kind in ("sql", "path", "command")}}
FAMILY = {"sql": "CWE-89", "path": "CWE-22", "command": "CWE-78"}


def contexts(projects, split):
    """{case: memory context} of the split's cases registered in `projects`."""
    os.environ["PROJECTS_DIR"] = str(projects)
    found = {}
    for case_id, info in sorted(registry()[1].items()):
        if info.get("split") != split:
            continue
        case, files = baseline(case_id, info["commit"])
        spec = case["spec"]
        if spec.scan.known:
            known = spec.scan.known[0]
            finding = {"file": known.file, "line": known.line, "cwe": known.cwe, "rule_id": "known:" + known.id}
        else:   # the -01 labs: the finding is the scanner's; its family and file are fixed
            finding = {"file": spec.scan.paths[0], "line": None, "cwe": FAMILY[case["kind"]], "rule_id": "lab"}
        context = context_for(case, files, finding)
        shape = [(context["signature"] or {}).get(k) for k in SHAPE] if context["signature"] else None
        found[case_id] = {"project": context["project"], "cwe_family": family(finding), "jdk": context["jdk"], "shape": shape,
                          "vulnerable": spec.labels.get("benchmark_real", "true") == "true"}
    return found


def key(context):
    return (context["cwe_family"], context["jdk"], tuple(context["shape"]) if context["shape"] else None)


def main():
    out = evidence("coverage.json")
    if out.exists():
        raise SystemExit("Use a fresh EVIDENCE_DIR; evidence is never overwritten")
    evaluation = contexts(EVALUATION, "evaluation")
    development = {k: v for k, v in contexts(DEVELOPMENT, "development").items() if k in REFERENCE}
    rows = []
    for case_id, context in evaluation.items():
        if not context["vulnerable"]:
            continue
        shape = key(context)
        l2 = sorted(d for d, other in development.items() if shape[2] and key(other) == shape)
        siblings = sorted(e for e, other in evaluation.items()
                          if e != case_id and other["vulnerable"] and other["project"] == context["project"] and shape[2] and key(other) == shape)
        rows.append({"case": case_id, **context, "l2_matches": l2, "l1_siblings": siblings})
    summary = {"vulnerable_cases": len(rows), "with_l2_match": sum(bool(r["l2_matches"]) for r in rows),
               "with_l1_sibling": sum(bool(r["l1_siblings"]) for r in rows), "unknown_signature": sum(r["shape"] is None for r in rows),
               "by_family": {f: {"cases": n, "with_l2_match": sum(bool(r["l2_matches"]) for r in rows if r["cwe_family"] == f),
                                 "with_l1_sibling": sum(bool(r["l1_siblings"]) for r in rows if r["cwe_family"] == f)}
                             for f, n in sorted(Counter(r["cwe_family"] for r in rows).items())},
               "reference_fixes": sorted(development)}
    out.write_text(json.dumps({"scope": "static, outcome-free coverage before the main experiment", "summary": summary,
                               "evaluation": rows, "development": development}, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2), "\nwritten:", out)


if __name__ == "__main__":
    main()
