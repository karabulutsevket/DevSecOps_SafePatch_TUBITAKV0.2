"""Faz 2 exit, signed L2 package (ROADMAP.md week 7): build, sign, import offline, use, promote.

Real local model, real Java verification, owned synthetic projects only.

1. Lab (SafePatch): path-01 (project owned-java-demo), scanner semgrep, memory off. An accepted
   candidate is approved by SIMULATED-EXPERIMENT-REVIEWER and promoted to the lab's L1.
2. Package: the lab's approved records become an experiment package (scripts/l2_build.py), signed
   with a key generated for this run; the private key stays under .runtime.
3. Import into a fresh installation database with no L1 record, offline, against an allowed-signers
   file holding only this run's public key. Refused on copies: a changed record, an unknown key.
4. Use: package-path-1 (project safepatch-package-dev; other code, same weakness shape), scanner
   known (answer key), memory guarded. The L2 record can only be an example for the model.
5. If accepted: SIMULATED-CUSTOMER-REVIEWER approves and the repair is promoted to the
   installation's L1 with its L2 origin; a second job on the same case then takes the L1 record.
6. Update: version 2 is imported (local evidence kept), then version 1 again is refused.

The Faz 2 condition (a signed L2 package can be imported) is decided by steps 3 and 6; steps 4-5
show the trust level at work. One seed and one pair of cases: a demonstration, not a measurement.

Needs worker1 (Ollama), worker2 and the runner started with PROJECTS_DIR=.runtime/dev-all/projects
and SAFEPATCH_PROFILE=lab (set both here too), SEMGREP_WSL, and OpenSSH's ssh-keygen.
Writes EVIDENCE_DIR/l2/: protocol.json, jobs/, package/, lab-memory.json, import.json, runs.json,
installation-memory.json, summary.json.
"""
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from safepatch import l2
from safepatch.common import POLICY, canonical, digest, evidence, setting
from safepatch.engine import Engine, primary_finding
from safepatch.memory import Memory, context_for
from safepatch.repository import baseline, registry
from safepatch.store import Store
from safepatch.worker1 import SYSTEM, WEAKNESS_NOTES
from faz2_exit import write
from l2_build import lab_records
from l3_catalog import load

LAB_CASE, USE_CASE = "path-01", "package-path-1"
LAB_REVIEWER, CUSTOMER_REVIEWER = "SIMULATED-EXPERIMENT-REVIEWER", "SIMULATED-CUSTOMER-REVIEWER"


def run(store, case_id, scanner, memory_mode, phase, seed=42):
    now = time.time()
    info = registry()[1][case_id]
    job = {"id": uuid.uuid4().hex, "case_id": case_id, "base_commit": info["commit"], "project": info["project"],
           "policy_version": POLICY, "scanner": scanner, "mode": "real-local-model", "evaluation": False,
           "status": "queued", "owner": "EXPERIMENT-NOT-A-HUMAN", "started_at": now, "deadline": now + 1200, "max_attempts": 3,
           "attempt_count": 0, "attempts": [], "events": [], "approval": None, "memory_mode": memory_mode, "strategy": "guided+context", "seed": seed}
    store.create(job, job["id"])
    start = time.perf_counter()
    Engine(store).run(job["id"])
    job = store.get(job["id"])
    job.update(phase=phase, wall_seconds=round(time.perf_counter() - start, 3))
    return job


def row(job):
    lookup = job.get("memory_lookup") or {}
    return {"id": job["id"], "case_id": job["case_id"], "project": job["project"], "phase": job["phase"], "scanner": job["scanner"],
            "memory_mode": job["memory_mode"], "status": job["status"], "accepted": job["status"] == "awaiting_review", "reason": job.get("reason"),
            "attempts": job["attempt_count"], "wall_seconds": job["wall_seconds"], "memory_tier": lookup.get("tier"), "memory_use": lookup.get("use"),
            "memory_selected": lookup.get("selected_id"),
            "considered": [{k: c.get(k) for k in ("id", "tier", "use", "rank", "differences")} for c in lookup.get("considered", [])],
            "proposal_modes": [a.get("proposal", {}).get("mode") for a in job["attempts"]]}


def approve(store, job, reviewer, rationale):
    """SIMULATED approval and promotion, as in scripts/faz2_exit.py; never a customer approval."""
    candidate = job["candidate"]
    approval = {"decision": "approve", "candidate_commit": candidate["commit"], "artifact_sha256": candidate["artifact_sha256"],
                "policy_version": candidate["policy_version"], "reviewer": reviewer, "approved_at": time.time(), "expires_at": time.time() + 86400}
    job = store.mutate(job["id"], lambda j: j.update(status="approved", approval=approval))
    case, files = baseline(job["case_id"], job["base_commit"])
    finding = primary_finding(job)
    return Memory(store).promote(job, context_for(case, files, finding), files[finding["file"]], reviewer, rationale)


def keypair(folder, name):
    key = folder / name
    subprocess.run([l2.keygen(), "-q", "-t", "ed25519", "-N", "", "-C", f"{name} (experiment key)", "-f", str(key)], check=True, capture_output=True)
    trusted = folder / (name + ".allowed_signers")
    trusted.write_text(f'{l2.NAMESPACE} namespaces="{l2.NAMESPACE}" ' + (folder / (name + ".pub")).read_text().strip() + "\n", encoding="utf-8")
    return key, trusted


def refused(action):
    try:
        action()
    except l2.PackageError as exc:
        return str(exc)
    return None


def main():
    if not all(case in registry()[1] for case in (LAB_CASE, USE_CASE)) or setting("SAFEPATCH_PROFILE") != "lab":
        raise SystemExit("set PROJECTS_DIR=.runtime/dev-all/projects and SAFEPATCH_PROFILE=lab here and for the services")
    output = evidence("l2")
    if (output / "summary.json").exists():
        raise SystemExit("Use a fresh EVIDENCE_DIR; evidence is never overwritten")
    for service, port in (("WORKER1", 8101), ("WORKER2", 8102)):
        os.environ.setdefault(service + "_URL", f"http://127.0.0.1:{port}")
        os.environ[service + "_TOKEN_FILE"] = str(ROOT / ".secrets" / (service.lower() + "_token"))
    name = uuid.uuid4().hex
    work = ROOT / ".runtime" / "l2-experiment" / name
    work.mkdir(parents=True)
    lab, installation = (Store("sqlite:///" + str(work / f"{side}.db")) for side in ("lab", "installation"))
    git = lambda *a: subprocess.run(["git", *a], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    started = time.time()
    write(output / "protocol.json", {
        "schema": 1, "question": "Faz 2 exit: a signed L2 package is imported offline and its record is used at its own trust level",
        "started_at": started, "git_commit": git("rev-parse", "HEAD"), "git_dirty": bool(git("status", "--porcelain", "--untracked-files=no")),
        "model": setting("OLLAMA_MODEL", "qwen2.5-coder:7b-instruct-q4_K_M"), "system_prompt_sha256": digest(SYSTEM),
        "weakness_notes_sha256": digest(canonical(WEAKNESS_NOTES)), "strategy": "guided+context", "max_attempts": 3, "seed": 42,
        "lab": {"case": LAB_CASE, "scanner": "semgrep", "memory_mode": "off"}, "use": {"case": USE_CASE, "scanner": "known", "memory_mode": "guarded"},
        "signature": {"tool": "ssh-keygen -Y sign/verify", "algorithm": "ed25519", "namespace": l2.NAMESPACE,
                      "key": "generated for this run, no passphrase, experiment only; the private key stays under .runtime"},
        "human_approval": f"SIMULATED: {LAB_REVIEWER} in the lab database, {CUSTOMER_REVIEWER} in the installation database",
        "python": platform.python_version()})
    rows = []

    def record(job):
        write(output / "jobs" / (job["id"] + ".json"), job)
        rows.append(row(job))
        write(output / "runs.json", rows)
        print(json.dumps({k: rows[-1][k] for k in ("case_id", "phase", "memory_tier", "memory_use", "accepted", "reason", "attempts")}), flush=True)

    # 1. Lab
    job = run(lab, LAB_CASE, "semgrep", "off", "lab-construction")
    record(job)
    if job["status"] != "awaiting_review":
        write(output / "summary.json", {"condition_met": False, "reason": "the lab job was not accepted: nothing to package", "runs": rows})
        raise SystemExit("lab job not accepted")
    approve(lab, job, LAB_REVIEWER, "Experiment-only lab record from a real verified local-model patch (Semgrep finding)")
    write(output / "lab-memory.json", Memory(lab).all())

    # 2. Package
    key, trusted = keypair(work, "publisher")
    _, stranger = keypair(work, "stranger")
    records = lab_records(lab, load())
    packages = {v: l2.build(records, "safepatch-lab", v, key, work / f"safepatch-l2-v{v}.zip", experiment=True)["path"] for v in (1, 2)}
    (output / "package").mkdir(parents=True)
    for version, path in packages.items():
        shutil.copy2(path, output / "package" / Path(path).name)
    shutil.copy2(trusted, output / "package" / "allowed_signers")

    # 3. Import, and what is refused
    changed = work / "changed-record.zip"
    with zipfile.ZipFile(packages[1]) as src, zipfile.ZipFile(changed, "w") as dst:
        for info in src.infolist():
            data = src.read(info)
            # One more byte in the record's diff; manifest and signature unchanged.
            dst.writestr(info.filename, data.replace(b'"diff": "', b'"diff": " ', 1) if info.filename.startswith("records/") else data)
    refusals = {"changed_record": refused(lambda: l2.read(changed, trusted)), "unknown_key": refused(lambda: l2.read(packages[1], stranger)),
                "no_trust_file": refused(lambda: l2.read(packages[1], None))}
    installed = l2.Shared(installation).install(packages[1], trusted)
    print(json.dumps({"import": installed["status"], "records": installed["records"], "refusals": refusals}), flush=True)

    # 4. Use, 5. promotion and the next job
    job = run(installation, USE_CASE, "known", "guarded", "installation-use")
    record(job)
    promoted = None
    if job["status"] == "awaiting_review":
        promoted = approve(installation, job, CUSTOMER_REVIEWER, "Experiment-only: a repair built from an L2 example, verified and approved in this installation")
        record(run(installation, USE_CASE, "known", "guarded", "installation-after-promotion"))

    # 6. Update and downgrade
    update = l2.Shared(installation).install(packages[2], trusted)
    refusals["older_version"] = refused(lambda: l2.Shared(installation).install(packages[1], trusted))
    shared = l2.Shared(installation)
    write(output / "import.json", {"v1": installed, "v2": update, "refusals": refusals, "packages": shared.installed()})
    write(output / "installation-memory.json", {"L1": Memory(installation).all(), "L2": shared.all()})
    use = rows[1]
    met = installed["status"] == "installed" and update["status"] == "installed" and all(refusals.values())
    write(output / "summary.json", {
        "scope": "synthetic Faz 2 exit check (signed L2 import); one seed, one pair of cases; not a measurement of L2's effect",
        "elapsed_seconds": round(time.time() - started, 3),
        "condition": "L2 paketi imzalı olarak içeri alınabiliyor",
        "condition_met": met,
        "import": {"v1": installed["status"], "v2": update["status"], "signer": installed["signer"], "records": installed["records"]},
        "refusals": refusals,
        "use": {k: use[k] for k in ("case_id", "project", "memory_tier", "memory_use", "memory_selected", "accepted", "reason", "attempts", "proposal_modes")},
        "promotion": {"l1_id": promoted["id"], "l2_origin": promoted.get("l2_origin")} if promoted else None,
        "after_promotion": {k: rows[2][k] for k in ("memory_tier", "memory_use", "memory_selected", "accepted", "proposal_modes")} if len(rows) > 2 else None,
        "l2_records": [{k: r[k] for k in ("id", "state", "trust", "uses", "validated_here")} | {"version": r["package"]["version"]} for r in shared.all()],
        "human_approval": "SIMULATED", "customer_validation": "not performed"})
    print("condition met:", met, "; written:", output)


if __name__ == "__main__":
    main()
