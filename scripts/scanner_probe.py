"""Baseline scans of named cases with one scanner, recorded (ROADMAP.md week 7).

Each case is verified at its base commit like a job's first scan (build, tests, scan) with
`--scanner`; the record keeps per case the findings SafePatch acts on, the other findings
(weaknesses outside the supported families) and the baseline verdict. Writes
scanner-probe-<scanner>.json to EVIDENCE_DIR. Real projects need the sandbox settings
(RUNNER_SANDBOX=docker, SANDBOX_MAVEN_CACHE) and PROJECTS_DIR registering the cases.

    python scripts/scanner_probe.py --scanner findsecbugs sql-01 command-01 path-01
"""
import argparse
import json
from pathlib import Path
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from safepatch.common import VerifyRequest, evidence
from safepatch.repository import registry
from safepatch.runner import execute


def brief(finding):
    return {k: finding.get(k) for k in ("rule_id", "cwe", "file", "line")}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scanner", required=True)
    parser.add_argument("cases", nargs="+")
    args = parser.parse_args()
    out = evidence(f"scanner-probe-{args.scanner.replace('+', '-')}.json")
    if out.exists():
        raise SystemExit("Use a fresh EVIDENCE_DIR; evidence is never overwritten")
    rows = []
    for case in args.cases:
        started = time.time()
        result = execute(VerifyRequest(job_id=uuid.uuid4().hex, case_id=case, base_commit=registry()[1][case]["commit"], attempt=0,
                                       deadline=time.time() + 1800, scanner=args.scanner))
        scans = result["scans"]
        row = {"case": case, "baseline_valid": result["baseline_valid"], "seconds": round(time.time() - started, 1),
               "tools": [s["tool"] + " " + s.get("version", "") for s in scans],
               "findings": [brief(f) for s in scans for f in s["findings"]],
               "other_findings": [brief(f) for s in scans for f in s.get("other_findings", [])],
               "unmapped_results": sum(s.get("unmapped_results", 0) for s in scans)}
        rows.append(row)
        print(json.dumps({"case": case, "baseline_valid": row["baseline_valid"], "findings": len(row["findings"]),
                          "other_findings": len(row["other_findings"]), "seconds": row["seconds"]}), flush=True)
    out.write_text(json.dumps({"scanner": args.scanner, "rows": rows}, indent=2) + "\n", encoding="utf-8")
    print("written:", out)


if __name__ == "__main__":
    main()
