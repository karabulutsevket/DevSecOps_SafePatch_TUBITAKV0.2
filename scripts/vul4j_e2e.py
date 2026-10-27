"""VUL4J-79 end to end through the orchestrator (ROADMAP.md week 5; L3 only).

Job 1: known-finding scan in the JDK 8 sandbox -> the model cannot hold ZipUtil.java (~98 KB)
-> needs_human -> expert patch (the upstream human fix 759b72f) -> the same policy and
verification as a model patch -> the author cannot approve it -> a second identity approves
and promotes it to memory. Job 2: same case -> exact replay of that record, verified again
-> the replayed patch keeps its author, who again cannot approve it.

Identities and decisions are SIMULATED: two test identities driven by this script, with
random tokens that live only in this process. The orchestrator app runs in process (routes,
auth, store, engine); worker2 and the runner must be running with PROJECTS_DIR=.runtime/l3/projects
SAFEPATCH_PROFILE=evaluation RUNNER_SANDBOX=docker SANDBOX_MAVEN_CACHE=<wsl path>.
Writes EVIDENCE_DIR/e2e/: protocol.json, one summary per job, memory.json.
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
sys.path.insert(0, str(ROOT))
from fastapi.testclient import TestClient

from safepatch import orchestrator
from safepatch.common import POLICY, digest, evidence, setting
from safepatch.engine import Engine
from safepatch.store import Store
from prepare_vul4j import DERIVED, FIX, L3, TARGET

CASE, SCOPE = "vul4j-79", "l3-vul4j-zt-zip"
EXPERT, REVIEWER = "SIMULATED-expert", "SIMULATED-reviewer"


def identities(folder):
    tokens = {EXPERT: secrets.token_urlsafe(32), REVIEWER: secrets.token_urlsafe(32)}
    roles = {EXPERT: ["submit", "review"], REVIEWER: ["review"]}
    users = [{"subject": s, "roles": roles[s], "projects": [SCOPE], "token_sha256": digest(t)} for s, t in tokens.items()]
    (folder / "users.json").write_text(json.dumps(users), encoding="utf-8")
    os.environ["USERS_FILE"] = str(folder / "users.json")
    return tokens


class Driver:
    def __init__(self, folder):
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

    def decide(self, who, job, expect=200):
        c = job["candidate"]
        return self.call(who, "POST", f"/v1/jobs/{job['id']}/approval", {"candidate_commit": c["commit"], "artifact_sha256": c["artifact_sha256"],
                                                                         "policy_version": c["policy_version"], "decision": "approve"}, expect)


def summary(job):
    """The job without file contents: statuses, attempts, candidate, approval, memory lookup."""
    lookup = job.get("memory_lookup") or {}
    return {"id": job["id"], "case_id": job["case_id"], "scanner": job["scanner"], "status": job["status"], "reason": job.get("reason"),
            "base_commit": job["base_commit"], "target_file": job.get("target_file"),
            "findings": [f"{f['rule_id']} line {f.get('line')}" for f in job.get("findings", [])],
            "baseline": {k: (job.get("baseline") or {}).get(k) for k in ("baseline_valid", "runner_profile", "duration_seconds")},
            "attempts": [{"number": a["number"], "mode": a["proposal"].get("mode"), "author": a["proposal"].get("author"),
                          "memory_id": a["proposal"].get("memory_id"), "changed_lines": a.get("changed_lines"), "patch_sha256": a.get("patch_sha256"),
                          "passed": (a.get("verification") or {}).get("passed"), "failure": a.get("failure")} for a in job["attempts"]],
            "candidate": {k: (job.get("candidate") or {}).get(k) for k in ("origin", "author", "commit", "artifact_sha256", "patch_sha256")},
            "approval": {k: (job.get("approval") or {}).get(k) for k in ("reviewer", "decision")},
            "memory": {"use": lookup.get("use"), "selected_id": lookup.get("selected_id"), "ids": job.get("memory_ids", [])},
            "events": [{k: e.get(k) for k in ("status", "actor", "reason", "origin") if e.get(k)} for e in job["events"]]}


def main():
    if setting("SAFEPATCH_PROFILE") != "evaluation" or Path(setting("PROJECTS_DIR", "")).resolve() != (L3 / "projects").resolve():
        raise SystemExit("set SAFEPATCH_PROFILE=evaluation and PROJECTS_DIR=.runtime/l3/projects (and start worker2 and the runner with them)")
    for service, port in (("WORKER1", 8101), ("WORKER2", 8102)):
        os.environ.setdefault(service + "_URL", f"http://127.0.0.1:{port}")
        os.environ[service + "_TOKEN_FILE"] = str(ROOT / ".secrets" / (service.lower() + "_token"))
    folder = ROOT / ".runtime/vul4j-e2e" / uuid.uuid4().hex[:8]
    folder.mkdir(parents=True)
    d = Driver(folder)
    fixed = subprocess.run(["git", "show", f"{FIX}:{TARGET}"], cwd=L3 / "repos/zt-zip-upstream", capture_output=True, check=True).stdout.decode("utf-8")

    cases = d.call(EXPERT, "GET", "/v1/cases")
    assert cases[CASE]["known_findings"] == 4 and cases[CASE]["commit"] == DERIVED
    new = {"case_id": CASE, "scanner": "known", "memory_mode": "guarded"}
    first = d.call(EXPERT, "POST", "/v1/jobs", {**new, "idempotency_key": uuid.uuid4().hex}, 201)
    first = d.work(first["id"])
    assert (first["status"], first["reason"], first["attempt_count"]) == ("needs_human", "source_exceeds_model_context", 0), first.get("reason")

    source = d.call(EXPERT, "GET", f"/v1/jobs/{first['id']}/expert-source")
    assert source["path"] == TARGET and len(source["content"]) > 90_000
    patch = {"edits": [{"path": TARGET, "old_sha256": source["sha256"], "content": fixed}],
             "rationale": "Upstream human fix 759b72f of zt-zip: refuse entries whose canonical path leaves the output directory."}
    preview = d.call(EXPERT, "POST", f"/v1/jobs/{first['id']}/expert-patch/preview", patch)
    d.call(EXPERT, "POST", f"/v1/jobs/{first['id']}/expert-patch", patch, 202)
    first = d.work(first["id"])
    assert first["status"] == "awaiting_review" and first["candidate"]["author"] == EXPERT, first.get("reason")
    d.decide(EXPERT, first, 409)                       # four eyes: the author cannot approve
    first = d.decide(REVIEWER, first)
    d.call(EXPERT, "POST", "/v1/memory/promote", {"job_id": first["id"], "reason": "VUL4J-79 expert fix, reviewed (simulated)"}, 409)
    record = d.call(REVIEWER, "POST", "/v1/memory/promote", {"job_id": first["id"], "reason": "VUL4J-79 expert fix, reviewed (simulated)"}, 201)

    second = d.call(EXPERT, "POST", "/v1/jobs", {**new, "idempotency_key": uuid.uuid4().hex}, 201)
    second = d.work(second["id"])
    assert second["status"] == "awaiting_review" and second["attempts"][0]["proposal"]["mode"] == "approved-memory-replay", second.get("reason")
    d.decide(EXPERT, second, 409)                      # a replayed expert patch keeps its author
    second = d.decide(REVIEWER, second)

    out = evidence("e2e")
    out.mkdir(parents=True, exist_ok=True)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    dirty = bool(subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT, capture_output=True, text=True).stdout.strip())
    memory = next(r for r in d.call(REVIEWER, "GET", "/v1/memory") if r["id"] == record["id"])
    for job in (first, second):
        (out / f"job-{job['id']}.json").write_text(json.dumps(summary(d.store.get(job["id"])), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    # File contents stay out of the evidence; their digests identify them.
    contents = {k: digest(memory[k] if isinstance(memory[k], str) else json.dumps(memory[k], sort_keys=True)) for k in ("patch", "diff", "before") if k in memory}
    (out / "memory.json").write_text(json.dumps({k: v for k, v in memory.items() if k not in contents} | {k + "_sha256": v for k, v in contents.items()},
                                                indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    protocol = {"schema": 1, "what": "VUL4J-79 through the orchestrator: known-finding scan in the JDK 8 sandbox, model limit, expert patch, "
                                      "four-eyes approval, memory, exact replay in a second job",
                "recorded_at": time.time(), "git_commit": head, "git_dirty": dirty, "policy": POLICY,
                "identities": f"{EXPERT} (submit+review), {REVIEWER} (review): test identities driven by scripts/vul4j_e2e.py; SIMULATED decisions, not human ones",
                "expert_patch": f"the upstream human fix {FIX} of {TARGET}, submitted as the expert's patch; preview changed_lines={preview['changed_lines']}",
                "model": "not called: the file exceeds the model's input budget (source_exceeds_model_context)",
                "jobs": [first["id"], second["id"]], "memory_id": record["id"], "steps": d.steps}
    (out / "protocol.json").write_text(json.dumps(protocol, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps([{"job": j["id"], "status": d.store.get(j["id"])["status"]} for j in (first, second)]))
    print("written:", out)


if __name__ == "__main__":
    main()
