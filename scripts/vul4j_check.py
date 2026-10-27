"""Check the VUL4J-79 evaluation case end to end in the JDK 8 sandbox (L3 only).

1. Baseline: the vulnerable revision builds, the behaviour suite passes and the PoV witness
   fails; findings come from the answer key.
2. Human fix: the upstream fix of ZipUtil.java goes through the same patch policy and
   verification as any candidate, and must pass.
3. Control: a patch that only adds a comment must fail, so the witness tells a fix apart.
4. Partial fix (week 6): the human fix's guards for the two sinks the witness exercises only.
   It passes verification; the hidden evaluation tests (l3/hidden/vul4j-79), which the
   verifier never runs, must catch it. Hidden tests run on every variant.
Writes vul4j-79-check.json to EVIDENCE_DIR. Needs prepare_vul4j.py (with --prefetch) first and:
PROJECTS_DIR=.runtime/l3/projects SAFEPATCH_PROFILE=evaluation RUNNER_SANDBOX=docker SANDBOX_MAVEN_CACHE=<wsl path>
"""
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from safepatch import runner
from safepatch.common import Patch, VerifyRequest, digest, evidence, setting
from safepatch.repository import baseline
from prepare_vul4j import DERIVED, FIX, L3, TARGET
from l3_hidden import hidden_result

CASE = "vul4j-79"
# One inserted guard of the upstream fix: a blank line, a comment, the check and a blank line.
GUARD = re.compile(r"\n[ \t]*/\* If we see the relative traversal string.*?\n[ \t]*\}\n\n", re.S)


def partial(fixed):
    """The fix with only its first two guards (Unpacker, backslash directories): the witness's sinks."""
    guards = list(GUARD.finditer(fixed))
    assert len(guards) == 4
    return fixed[:guards[2].start()] + fixed[guards[2].end():guards[3].start()] + fixed[guards[3].end():]


def suite(result):
    return {k: result.get(k) for k in ("passed", "tests", "failures", "errors", "skipped", "details", "duration_seconds", "reason")}


def summary(result):
    return {"passed": result["passed"], "baseline_valid": result.get("baseline_valid"), "feedback": result["feedback"]["code"],
            "build": result.get("build"), "behavior": suite(result.get("behavior", {})), "security": suite(result.get("security", {})),
            "findings": [f["rule_id"] + " " + f["file"] + ":" + str(f["line"]) for s in result.get("scans", []) for f in s["findings"]],
            "patch": {k: (result.get("patch") or {}).get(k) for k in ("patch_sha256", "changed_lines")},
            "source_revision": result.get("source_revision"), "artifact_sha256": result.get("artifact_sha256"),
            "runner_profile": result.get("runner_profile"), "duration_seconds": result.get("duration_seconds")}


def verify(patch=None):
    return runner.execute(VerifyRequest(job_id=uuid.uuid4().hex, case_id=CASE, base_commit=DERIVED, attempt=1 if patch else 0,
                                        deadline=time.time() + 3600, scanner="known", patch=patch, target_file=TARGET if patch else None))


def main():
    for name, value in (("SAFEPATCH_PROFILE", "evaluation"), ("RUNNER_SANDBOX", "docker")):
        if setting(name) != value:
            raise SystemExit(f"set {name}={value}")
    if not Path(setting("PROJECTS_DIR", "")).resolve() == (L3 / "projects").resolve():
        raise SystemExit("set PROJECTS_DIR to .runtime/l3/projects")
    _, files = baseline(CASE, DERIVED)
    fixed = subprocess.run(["git", "show", f"{FIX}:{TARGET}"], cwd=L3 / "repos/zt-zip-upstream", capture_output=True, check=True).stdout.decode("utf-8")
    patch = Patch.model_validate({"edits": [{"path": TARGET, "old_sha256": digest(files[TARGET]), "content": fixed}],
                                  "rationale": "Upstream human fix 759b72f (zt-zip), used to check the evaluation case."})
    control = Patch.model_validate({"edits": [{"path": TARGET, "old_sha256": digest(files[TARGET]), "content": files[TARGET] + "// control: no fix\n"}],
                                    "rationale": "Negative control: changes nothing that runs."})
    half = Patch.model_validate({"edits": [{"path": TARGET, "old_sha256": digest(files[TARGET]), "content": partial(fixed)}],
                                 "rationale": "Partial fix: guards only the two sinks the witness exercises."})
    started = time.time()
    record = {"case": "VUL4J-79", "cve": "CVE-2018-1002201", "cwe": "CWE-22", "upstream": "zeroturnaround/zt-zip", "derived_commit": DERIVED,
              "human_fix_commit": FIX, "started_at": started}
    record["baseline"] = summary(verify())
    print("baseline:", json.dumps({k: record["baseline"][k] for k in ("baseline_valid", "feedback", "duration_seconds")}), flush=True)
    record["human_fix"] = summary(verify(patch))
    print("human fix:", json.dumps({k: record["human_fix"][k] for k in ("passed", "feedback", "duration_seconds")}), flush=True)
    record["control"] = summary(verify(control))
    print("control:", json.dumps({k: record["control"][k] for k in ("passed", "feedback", "duration_seconds")}), flush=True)
    record["partial_fix"] = summary(verify(half))
    print("partial fix:", json.dumps({k: record["partial_fix"][k] for k in ("passed", "feedback", "duration_seconds")}), flush=True)
    for name, edits in (("baseline", {}), ("human_fix", {TARGET: fixed}), ("control", {TARGET: control.edits[0].content}), ("partial_fix", {TARGET: half.edits[0].content})):
        record[name]["hidden"] = hidden_result(CASE, DERIVED, edits)
        print(name, "hidden:", json.dumps({k: record[name]["hidden"][k] for k in ("passed", "tests", "failures", "errors")}), flush=True)
    out = evidence("vul4j-79-check.json")
    out.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("written:", out)
    expected = (record["baseline"]["baseline_valid"] and record["human_fix"]["passed"] and not record["control"]["passed"] and record["partial_fix"]["passed"]
                and record["human_fix"]["hidden"]["passed"] and not record["baseline"]["hidden"]["passed"] and not record["partial_fix"]["hidden"]["passed"])
    if not expected:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
