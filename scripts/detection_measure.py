"""Comparative detection on the L3 evaluation set: Semgrep, FindSecBugs and both (ROADMAP.md week 7).

Every ready evaluation case is scanned once at its base commit with `semgrep+findsecbugs` (a
job's first verification: build, tests, scan). Per tool, a case counts as found when the tool
reports a finding in the answer key's file of the same CWE family; on an exact answer-key line
it is also found on the line. On a vulnerable case that is a detection, on a safe case (an
OWASP Benchmark false positive) a false alarm. A case whose scan fails is recorded as such and
stays in the denominator. Our Semgrep rules are SafePatch's three own rules written for the
synthetic lab; Semgrep's published collections are not used (CLAUDE.md, rule 8).

Needs PROJECTS_DIR=.runtime/l3/projects RUNNER_SANDBOX=docker SANDBOX_MAVEN_CACHE=<wsl path>
SEMGREP_WSL=<semgrep in WSL> and the FindSecBugs tools (scripts/prepare_findsecbugs.py).
Resumable: rows go to EVIDENCE_DIR/detection/cases/<case>.json as each case ends; summary.json
is written once every case has a row.
"""
import json
import math
from pathlib import Path
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from safepatch.common import VerifyRequest, evidence
from safepatch.repository import project, registry
from safepatch.runner import execute
from safepatch.weakness import family
from l3_measure import ready_cases

TOOLS = ("semgrep", "findsecbugs")


def wilson(k, n, z=1.96):
    if not n:
        return None
    p = k / n
    centre, half = p + z * z / (2 * n), z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [round(100 * (centre - half) / (1 + z * z / n)), round(100 * (centre + half) / (1 + z * z / n))]


def judge(findings, known):
    """(found in the answer key's file and family, found on an answer-key line)."""
    files = {k.file for k in known}
    families = {family({"cwe": k.cwe}) for k in known}
    lines = {(k.file, k.line) for k in known}
    hits = [f for f in findings if f["file"] in files and family(f) in families]
    return bool(hits), any((f["file"], f["line"]) in lines for f in hits)


def measure(case):
    commit = registry()[1][case.id]["commit"]
    spec = project(case.id, commit)
    row = {"case": case.id, "cwe": case.cwe, "vulnerable": spec.labels.get("benchmark_real", "true") == "true",
           "known": [{"file": k.file, "line": k.line} for k in spec.scan.known]}
    started = time.time()
    try:
        result = execute(VerifyRequest(job_id=uuid.uuid4().hex, case_id=case.id, base_commit=commit, attempt=0,
                                       deadline=time.time() + 1800, scanner="semgrep+findsecbugs"))
    except Exception as exc:          # recorded, never dropped from the denominator
        row.update(error=f"{type(exc).__name__}: {exc}"[:300], seconds=round(time.time() - started, 1))
        return row
    for report in result["scans"]:
        found, on_line = judge(report["findings"], spec.scan.known)
        row[report["tool"]] = {"found": found, "on_line": on_line, "version": report.get("version"),
                               "findings": [{k: f.get(k) for k in ("rule_id", "cwe", "file", "line")} for f in report["findings"]],
                               "other_findings": len(report.get("other_findings", [])), "unmapped_results": report.get("unmapped_results", 0)}
    row["seconds"] = round(time.time() - started, 1)
    return row


def summarize(rows):
    def tally(selected):
        ok = [r for r in selected if "error" not in r]
        out = {"cases": len(selected), "scan_errors": len(selected) - len(ok)}
        for name, test in (("semgrep", lambda r: r["semgrep"]["found"]), ("findsecbugs", lambda r: r["findsecbugs"]["found"]),
                           ("either", lambda r: r["semgrep"]["found"] or r["findsecbugs"]["found"]),
                           ("both", lambda r: r["semgrep"]["found"] and r["findsecbugs"]["found"])):
            k = sum(test(r) for r in ok)
            out[name] = {"found": k, "of": len(selected), "wilson95": wilson(k, len(selected))}
        out["findsecbugs_on_line"] = sum(r["findsecbugs"]["on_line"] for r in ok)
        out["semgrep_on_line"] = sum(r["semgrep"]["on_line"] for r in ok)
        return out
    families = sorted({r["cwe"] for r in rows})
    return {"vulnerable": {"all": tally([r for r in rows if r["vulnerable"]]), **{c: tally([r for r in rows if r["vulnerable"] and r["cwe"] == c]) for c in families}},
            "safe_false_alarms": {"all": tally([r for r in rows if not r["vulnerable"]]), **{c: tally([r for r in rows if not r["vulnerable"] and r["cwe"] == c]) for c in families}}}


def main():
    out = evidence("detection")
    if (out / "summary.json").exists():
        raise SystemExit("Use a fresh EVIDENCE_DIR; evidence is never overwritten")
    (out / "cases").mkdir(parents=True, exist_ok=True)
    cases = ready_cases("evaluation")
    for case in cases:
        path = out / "cases" / f"{case.id}.json"
        if path.exists():
            continue
        row = measure(case)
        path.write_text(json.dumps(row, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"case": case.id, "vulnerable": row["vulnerable"], "error": row.get("error"),
                          **{t: (row.get(t) or {}).get("found") for t in TOOLS}, "seconds": row["seconds"]}), flush=True)
    rows = [json.loads((out / "cases" / f"{c.id}.json").read_text(encoding="utf-8")) for c in cases]
    summary = summarize(rows)
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary["vulnerable"]["all"], indent=2), "\nfalse alarms:", json.dumps(summary["safe_false_alarms"]["all"]), "\nwritten:", out)


if __name__ == "__main__":
    main()
