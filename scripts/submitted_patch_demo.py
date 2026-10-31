"""Patches submitted from outside SafePatch, end to end through the orchestrator (docs/YAMA_DOGRULAMA.md).

For each synthetic family (sql-01, path-01, command-01) four patches arrive as real `git diff`
output, the form a developer, GitHub Copilot Autofix or Sonar AI CodeFix would hand them over in:
  reference      the known correct repair (tests/mock_patches.py)
  scanner_quiet  rewritten so our Semgrep rule no longer matches, the weakness left in place
  disabled       the method reduced to a constant: no sink and no function (V0.1's negative control)
  test_change    the security test switched off instead of the code fixed
All of them are written for this check and labelled `handwritten-control`; none comes from a tool,
so the run shows what the gate does with each kind of patch, not how good any tool's patches are.
The first three are verified (Semgrep, Docker sandbox); the fourth is expected to be refused at
submission. A reference patch that reaches review is then approved and promoted: the submitter
first, who must be refused both times, then a second identity.

Identities and decisions are SIMULATED: test identities driven by this script, with random tokens
that live only in this process. The orchestrator app runs in process (routes, auth, store, engine);
worker2 and the runner must be running (scripts/start-native.ps1) with RUNNER_SANDBOX=docker.
Writes EVIDENCE_DIR/demo/: protocol.json, summary.json, one file per job, the diffs, audit.json.
"""
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]
from fastapi.testclient import TestClient

from mock_patches import correct_patch
from safepatch import orchestrator
from safepatch.audit import AuditLog
from safepatch.common import POLICY, SOURCE, digest, evidence, setting
from safepatch.engine import Engine
from safepatch.repository import baseline, checkout, registry, run_git
from safepatch.runner import discard
from safepatch.store import Store

SUBMITTER, REVIEWER = "SIMULATED-developer", "SIMULATED-reviewer"
LABEL = "handwritten-control"
TEST = "src/test/java/demo/SecurityTest.java"
DISABLED = 'package demo;\npublic class DemoService {\n    public String lookup(String input) throws Exception { return ""; }\n}\n'
# Rewrites that our rule for the family (rules/java.yml) no longer matches; the weakness stays.
QUIET = {
    "sql": [('"SELECT name FROM accounts WHERE name = \'" + input + "\'"', 'String.format("SELECT name FROM accounts WHERE name = \'%s\'", input)')],
    "path": [("Path target = root.resolve(input);\n", 'Path target = root.resolve(input);\n        if (!target.startsWith(root)) { throw new SecurityException("outside root"); }\n')],
    "command": [("new ProcessBuilder(shell, flag, command)", "new ProcessBuilder(List.of(shell, flag, command))"),
                ("import java.nio.file.*;\n", "import java.nio.file.*;\nimport java.util.List;\n")],
}
RATIONALES = {
    "reference": {"sql": "Bind the input with a PreparedStatement parameter instead of concatenating it into the query.",
                  "path": "Resolve the real path and refuse anything that lies outside the root directory.",
                  "command": "Run the fixed Java executable with the input as one argument, without a shell."},
    "scanner_quiet": {"sql": "Build the query with String.format instead of string concatenation.",
                      "path": "Check that the resolved path stays under the root before reading it.",
                      "command": "Pass the command to ProcessBuilder as a list."},
    "disabled": "Remove the unsafe lookup so the method no longer reaches the sink.",
    "test_change": "Switch off the failing security test until the fix is ready.",
}
EXPECTED = {"reference": "awaiting_review", "scanner_quiet": "needs_human", "disabled": "needs_human", "test_change": "refused"}


def identities(folder):
    tokens = {SUBMITTER: secrets.token_urlsafe(32), REVIEWER: secrets.token_urlsafe(32)}
    roles = {SUBMITTER: ["submit", "review"], REVIEWER: ["review"]}
    users = [{"subject": s, "roles": roles[s], "token_sha256": digest(t)} for s, t in tokens.items()]
    (folder / "users.json").write_text(json.dumps(users), encoding="utf-8")
    os.environ["USERS_FILE"] = str(folder / "users.json")
    return tokens


class Driver:
    def __init__(self, folder):
        self.folder = folder
        self.tokens = identities(folder)
        self.store = Store("sqlite:///" + (folder / "jobs.db").as_posix())
        orchestrator.store = self.store   # no lifespan: this script runs the queued work itself
        self.client = TestClient(orchestrator.app)
        self.steps = []

    def call(self, who, method, path, body=None, expect=200):
        response = self.client.request(method, path, headers={"Authorization": "Bearer " + self.tokens[who]}, json=body)
        self.steps.append({"actor": who, "call": f"{method} {path}", "status": response.status_code,
                           **({"detail": response.json().get("detail")} if response.status_code >= 400 else {})})
        if response.status_code != expect:
            raise SystemExit(f"{method} {path} as {who}: {response.status_code} {response.text[:300]}")
        return response.json()

    def work(self, job_id):
        started = time.monotonic()
        Engine(self.store).run(job_id)
        job = self.store.get(job_id)
        self.steps.append({"engine": job_id, "status": job["status"], "reason": job.get("reason"), "seconds": round(time.monotonic() - started, 1)})
        return job

    def diff(self, case_id, files, content, path=SOURCE):
        """`git diff` of one changed file in a fresh clone of the pinned commit: the form tools hand over."""
        work = self.folder / ("clone-" + uuid.uuid4().hex[:8])
        try:
            checkout(case_id, files.commit, work)
            (work / path).write_text(content, encoding="utf-8", newline="\n")
            return run_git(work, "diff").decode("utf-8")
        finally:
            discard(work)


def quiet(kind, source):
    for old, new in QUIET[kind]:
        if source.count(old) != 1:
            raise SystemExit(f"{kind}: the scanner_quiet rewrite no longer fits the source")
        source = source.replace(old, new)
    return source


def suite(result):
    return {k: (result or {}).get(k) for k in ("passed", "tests", "failures", "errors", "skipped")} | {"assertions": sorted({d["assertion"] for d in (result or {}).get("details", [])})}


def summary(job):
    """The job without file contents: submission, statuses, verification, candidate, approval."""
    attempts = []
    for a in job["attempts"]:
        v = a.get("verification") or {}
        attempts.append({"number": a["number"], **{k: a["proposal"].get(k) for k in ("mode", "author", "tool", "diff_sha256")},
                         "changed_lines": a.get("changed_lines"), "patch_sha256": a.get("patch_sha256"), "passed": v.get("passed"), "failure": a.get("failure"),
                         "build": (v.get("build") or {}).get("passed"), "behavior": suite(v.get("behavior")), "security": suite(v.get("security")),
                         "scans": [{"tool": s.get("tool"), "version": s.get("version"), "status": s.get("status"), "findings": len(s.get("findings", []))} for s in v.get("scans", [])],
                         "remaining_rules": (v.get("feedback") or {}).get("remaining_rules"), "runner_profile": v.get("runner_profile"), "duration_seconds": v.get("duration_seconds")})
    initial = job.get("baseline") or {}
    return {"id": job["id"], "case_id": job["case_id"], "mode": job["mode"], "scanner": job["scanner"], "status": job["status"], "reason": job.get("reason"),
            "base_commit": job["base_commit"], "target_file": job.get("target_file"),
            "submission": {k: job["submission"][k] for k in ("tool", "author", "diff_sha256", "rationale")},
            "findings": [f"{f['rule_id']} line {f.get('line')}" for f in job.get("findings", [])],
            "baseline": {"baseline_valid": initial.get("baseline_valid"), "security": suite(initial.get("security")), "runner_profile": initial.get("runner_profile"),
                         "duration_seconds": initial.get("duration_seconds")},
            "attempts": attempts,
            "candidate": {k: (job.get("candidate") or {}).get(k) for k in ("origin", "author", "tool", "commit", "artifact_sha256", "patch_sha256", "evidence_sha256")},
            "approval": {k: (job.get("approval") or {}).get(k) for k in ("reviewer", "decision", "mode")},
            "events": [{k: e.get(k) for k in ("status", "actor", "reason", "origin") if e.get(k)} for e in job["events"]]}


def main():
    if setting("SAFEPATCH_PROFILE", "product") != "product":
        raise SystemExit("run in the product profile, as an installation at a customer would")
    os.environ.setdefault("WORKER2_URL", "http://127.0.0.1:8102")
    os.environ["WORKER2_TOKEN_FILE"] = str(ROOT / ".secrets" / "worker2_token")
    out = evidence("demo")
    if out.exists() and any(out.iterdir()):
        raise SystemExit(f"{out} is not empty: evidence is never overwritten")
    folder = ROOT / ".runtime/submitted-demo" / uuid.uuid4().hex[:8]
    folder.mkdir(parents=True)
    d = Driver(folder)
    rows, jobs, diffs = [], [], {}
    for kind in ("sql", "path", "command"):
        case_id = kind + "-01"
        case, files = baseline(case_id, registry()[1][case_id]["commit"])
        contents = {"reference": correct_patch(kind, files).edits[0].content, "scanner_quiet": quiet(kind, files[SOURCE]), "disabled": DISABLED}
        for name, content in contents.items():
            diff = diffs[f"{case_id}-{name}"] = d.diff(case_id, files, content)
            rationale = RATIONALES[name] if isinstance(RATIONALES[name], str) else RATIONALES[name][kind]
            preview = d.call(SUBMITTER, "POST", "/v1/verifications/preview", {"case_id": case_id, "diff": diff})
            job = d.call(SUBMITTER, "POST", "/v1/verifications", {"case_id": case_id, "idempotency_key": uuid.uuid4().hex, "scanner": "semgrep",
                                                                   "tool": LABEL, "diff": diff, "rationale": rationale}, 201)
            job = d.work(job["id"])
            verdict = job["status"]   # the engine's; a reference patch moves on to approved below
            if name == "reference" and verdict == "awaiting_review":
                c = job["candidate"]
                decision = {"candidate_commit": c["commit"], "artifact_sha256": c["artifact_sha256"], "policy_version": c["policy_version"], "decision": "approve"}
                d.call(SUBMITTER, "POST", f"/v1/jobs/{job['id']}/approval", decision, 409)   # four eyes: the submitter counts as the author
                d.call(REVIEWER, "POST", f"/v1/jobs/{job['id']}/approval", decision)
                promote = {"job_id": job["id"], "reason": "Submitted reference fix, reviewed (simulated)"}
                d.call(SUBMITTER, "POST", "/v1/memory/promote", promote, 409)
                d.call(REVIEWER, "POST", "/v1/memory/promote", promote, 201)
            job = d.store.get(job["id"])
            jobs.append(job["id"])
            last = job["attempts"][-1] if job["attempts"] else {}
            v = last.get("verification") or {}
            rows.append({"case": case_id, "patch": name, "expected": EXPECTED[name], "verdict": verdict, "status": job["status"], "reason": job.get("reason"),
                         "failure": (last.get("failure") or {}).get("category"), "build": (v.get("build") or {}).get("passed"),
                         "behavior": (v.get("behavior") or {}).get("passed"), "witness": (v.get("security") or {}).get("passed"),
                         # What a gate that looks only at the rescan would decide (V0.1's scanner-only gate).
                         "rescan_clean": bool(v.get("scans")) and all(s["status"] == "ok" and not s["findings"] for s in v["scans"]),
                         "changed_lines": preview["changed_lines"], "job": job["id"],
                         "seconds": next(s["seconds"] for s in reversed(d.steps) if s.get("engine") == job["id"])})
            print(json.dumps(rows[-1]), flush=True)
        diff = diffs[f"{case_id}-test_change"] = d.diff(case_id, files, files[TEST].replace("@Test", "@org.junit.jupiter.api.Disabled @Test"), TEST)
        refused = d.call(SUBMITTER, "POST", "/v1/verifications", {"case_id": case_id, "idempotency_key": uuid.uuid4().hex, "scanner": "semgrep",
                                                                   "tool": LABEL, "diff": diff, "rationale": RATIONALES["test_change"]}, 409)
        rows.append({"case": case_id, "patch": "test_change", "expected": "refused", "verdict": "refused", "status": "refused", "reason": refused["detail"],
                     "failure": None, "build": None, "behavior": None, "witness": None, "rescan_clean": None, "changed_lines": None, "job": None, "seconds": None})
        print(json.dumps(rows[-1]), flush=True)

    out.mkdir(parents=True, exist_ok=True)
    (out / "diffs").mkdir()
    for name, diff in diffs.items():
        (out / "diffs" / (name + ".diff")).write_bytes(diff.encode("utf-8"))
    for job_id in jobs:
        (out / f"job-{job_id}.json").write_text(json.dumps(summary(d.store.get(job_id)), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    log = AuditLog(d.store)
    (out / "audit.json").write_text(json.dumps({"verify": log.verify(), "entries": log.entries()}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    memory = [{k: r.get(k) for k in ("id", "provenance", "tool", "author", "model", "source_job", "state")} for r in d.call(REVIEWER, "GET", "/v1/memory")]
    matched = sum(r["verdict"] == r["expected"] for r in rows)
    bad = [r for r in rows if r["patch"] in ("scanner_quiet", "disabled")]
    gates = {"bad_patches_verified": len(bad), "accepted_by_safepatch": sum(r["verdict"] == "awaiting_review" for r in bad),
             "rescan_clean_so_scanner_only_gate_accepts": sum(bool(r["rescan_clean"]) for r in bad)}
    (out / "summary.json").write_text(json.dumps({"rows": rows, "matched_expectation": matched, "patches": len(rows), "gates": gates, "memory": memory},
                                                 indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    dirty = bool(subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT, capture_output=True, text=True).stdout.strip())
    protocol = {"schema": 1, "what": "Patches submitted from outside SafePatch through POST /v1/verifications: three synthetic families, four kinds of hand-written "
                                     "patch each, as real git diff output; Semgrep in the Docker sandbox; four-eyes approval and memory for the reference patches",
                "recorded_at": time.time(), "git_commit": head, "git_dirty": dirty, "policy": POLICY, "scanner": "semgrep",
                "runner_sandbox": "docker (worker2 and runner as services; see each job's runner_profile)",
                "identities": f"{SUBMITTER} (submit+review), {REVIEWER} (review): test identities driven by scripts/submitted_patch_demo.py; SIMULATED decisions, not human ones",
                "patches": {"reference": "tests/mock_patches.py correct_patch", "scanner_quiet": QUIET, "disabled": DISABLED,
                            "test_change": "@Test -> @org.junit.jupiter.api.Disabled @Test in " + TEST},
                "label": f"every patch is submitted with tool={LABEL!r}: written for this check, no tool's output",
                "model": "not called: a submitted patch is verified as it is", "jobs": jobs, "steps": d.steps}
    (out / "protocol.json").write_text(json.dumps(protocol, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"matched_expectation": matched, "patches": len(rows), **gates, "audit_ok": log.verify()["ok"]}))
    print("written:", out)


if __name__ == "__main__":
    main()
