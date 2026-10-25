"""Re-verify previously accepted patches against today's tests, without the model.

Answers one question: does a patch that passed an older, weaker security witness still
pass the current one? Accepted jobs are read from a published evidence folder (never
written); each distinct patch runs once through the in-process runner on the case's
current registered commit, with the scanner its job used. Output goes to
evidence("reverify").
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from safepatch.common import Patch, VerifyRequest, digest, evidence
from safepatch.engine import primary_finding
from safepatch.feedback import classify
from safepatch.repository import baseline, registry
from safepatch.runner import execute


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def accepted(source, cases):
    for file in sorted((ROOT / source / "jobs").glob("*.json")):
        job = json.loads(file.read_text(encoding="utf-8"))
        if job["status"] == "awaiting_review" and job["case_id"] in cases:
            yield job, next(a for a in reversed(job["attempts"]) if a.get("verification", {}).get("passed"))


def summarize(rows):
    groups = []
    for strategy in ["all", *dict.fromkeys(r["strategy"] for r in rows)]:
        for split in ("all", "development", "evaluation"):
            group = [r for r in rows if strategy in ("all", r["strategy"]) and split in ("all", r["split"])]
            if group:
                groups.append({"strategy": strategy, "split": split, "accepted_before": len(group),
                               "distinct_patches": len({(r["case_id"], r["patch_sha256"]) for r in group}),
                               "still_pass": sum(r["passed"] for r in group),
                               "mentions_toRealPath": sum(r["mentions_toRealPath"] for r in group),
                               "still_pass_without_toRealPath": sum(r["passed"] and not r["mentions_toRealPath"] for r in group)})
    return groups


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, help="published experiment folder, e.g. evidence/v02-retry/retry")
    parser.add_argument("--cases", required=True)
    args = parser.parse_args()
    output = evidence("reverify")
    if (output / "summary.json").exists():
        raise SystemExit("Use a fresh EVIDENCE_DIR; evidence is never overwritten")
    git = lambda *a: subprocess.run(["git", *a], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    cases, selected = registry()[1], args.cases.split(",")
    source_protocol = json.loads((ROOT / args.source / "protocol.json").read_text(encoding="utf-8"))
    tests = {}
    for case_id in selected:
        _, files = baseline(case_id, cases[case_id]["commit"])
        tests[case_id] = {p: digest(files.raw(p)) for p in files if p.startswith("src/test/")}
    write(output / "protocol.json", {
        "schema": 1, "question": "Do patches accepted under an earlier security witness pass the current witness?",
        "started_at": time.time(), "git_commit": git("rev-parse", "HEAD"), "git_dirty": bool(git("status", "--porcelain", "--", "safepatch", "samples", "scripts")),
        "source": args.source, "source_git_commit": source_protocol.get("git_commit"), "cases": selected,
        "current_commits": {c: cases[c]["commit"] for c in selected}, "current_test_sha256": tests,
        "model": "not used", "method": "each distinct accepted patch re-run once by the in-process runner on the current commit; the job's scanner; no human approval",
        "source_unchanged_check": "every patch's old_sha256 must equal the current source file, or the run stops (stale_base_hash)"})
    rows, results = [], {}
    for job, attempt in accepted(args.source, selected):
        patch = Patch.model_validate(attempt["proposal"]["patch"])
        target = primary_finding(job)["file"]
        key = (job["case_id"], attempt["patch_sha256"])
        if key not in results:
            request = VerifyRequest(job_id=uuid.uuid4().hex, case_id=job["case_id"], base_commit=cases[job["case_id"]]["commit"], attempt=1,
                                    deadline=time.time() + 600, scanner=job["scanner"], patch=patch, target_file=target)
            result = execute(request)
            result.pop("artifact_b64", None)
            results[key] = result
            write(output / "results" / f"{key[0]}-{key[1][:12]}.json", {"case_id": key[0], "patch_sha256": key[1], "result": result})
        result = results[key]
        content = next(e.content for e in patch.edits if e.path == target)
        rows.append({"source_job": job["id"], "case_id": job["case_id"], "split": cases[job["case_id"]]["split"],
                     "strategy": job["strategy"], "seed": job["seed"], "patch_sha256": attempt["patch_sha256"],
                     "mentions_toRealPath": "toRealPath" in content, "passed": bool(result["passed"]),
                     "failure": None if result["passed"] else classify(result)["category"],
                     "failed_tests": sorted(d["name"] for s in ("behavior", "security") for d in (result.get(s) or {}).get("details", []))})
        print(json.dumps(rows[-1]), flush=True)
    write(output / "runs.json", rows)
    write(output / "summary.json", {"scope": "re-verification of earlier accepted patches; synthetic cases, not an independent benchmark",
                                    "n": len(rows), "groups": summarize(rows)})


if __name__ == "__main__":
    main()
