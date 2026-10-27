"""Verify stored L3 candidates again, without the model (ROADMAP.md week 6).

A candidate kept in .runtime/l3-measure/<run>/jobs.db goes through today's verification (policy,
sandbox build, behaviour, witness) on the case's current evaluation commit, and through the
hidden tests if it is accepted. For a candidate an earlier policy refused, this shows what the
verifier would have said. Its target file must be the same on the current commit. Writes
l3-candidates.json to EVIDENCE_DIR. Needs PROJECTS_DIR=.runtime/l3/projects
SAFEPATCH_PROFILE=evaluation RUNNER_SANDBOX=docker SANDBOX_MAVEN_CACHE=<wsl path>.

    python scripts/l3_candidates.py l3-model-1/owasp-benchmark-01643/1 l3-model-2/owasp-benchmark-00306/1
"""
import argparse
import json
from pathlib import Path
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from safepatch import runner
from safepatch.common import Patch, VerifyRequest, digest, evidence, setting
from safepatch.repository import baseline, registry
from safepatch.store import Store
from l3_hidden import hidden_result


def stored(run, case, number):
    job = next(j for j in Store("sqlite:///" + (ROOT / ".runtime/l3-measure" / run / "jobs.db").as_posix()).all() if j["case_id"] == case)
    attempt = next(a for a in job["attempts"] if a["number"] == number)
    return job, attempt


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("answers", nargs="+", help="run/case/attempt")
    args = parser.parse_args()
    for name, value in (("SAFEPATCH_PROFILE", "evaluation"), ("RUNNER_SANDBOX", "docker")):
        if setting(name) != value:
            raise SystemExit(f"set {name}={value}")
    out = evidence("l3-candidates.json")
    if out.exists():
        raise SystemExit("Use a fresh EVIDENCE_DIR; evidence is never overwritten")
    rows = []
    for answer in args.answers:
        run, case, number = answer.split("/")
        job, attempt = stored(run, case, int(number))
        commit = registry()[1][case]["commit"]
        _, tracked = baseline(case, commit)
        edits = attempt["proposal"]["patch"]["edits"]
        if any(digest(tracked[e["path"]]) != e["old_sha256"] for e in edits):
            raise SystemExit(f"{answer}: the target file differs on the current commit")
        patch = Patch.model_validate(attempt["proposal"]["patch"])
        result = runner.execute(VerifyRequest(job_id=uuid.uuid4().hex, case_id=case, base_commit=commit, attempt=1, deadline=time.time() + 1800,
                                              scanner="known", patch=patch, target_file=edits[0]["path"]))
        row = {"answer": answer, "run_status": job["status"], "run_policy_error": attempt.get("policy_error"), "commit": commit,
               "patch_sha256": digest(json.dumps(attempt["proposal"]["patch"], sort_keys=True)),
               "passed": result["passed"], "code": result["feedback"]["code"],
               **{s: {k: (result.get(s) or {}).get(k) for k in ("tests", "failures", "errors")} for s in ("behavior", "security")}, "hidden": None}
        if result["passed"]:
            hidden = hidden_result(case, commit, {e["path"]: e["content"] for e in edits})
            row["hidden"] = {k: hidden.get(k) for k in ("passed", "tests", "failures", "errors", "details")}
        rows.append(row)
        print(json.dumps({k: row[k] for k in ("answer", "passed", "code", "behavior", "security", "hidden")}), flush=True)
    out.write_text(json.dumps({"rows": rows}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("written:", out)


if __name__ == "__main__":
    main()
