import asyncio
from contextlib import asynccontextmanager
import html
import json
import queue
import threading
import time
import uuid

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import Field

from safepatch.audit import AuditLog
from safepatch.auth import identity, require_role
from safepatch.common import POLICY, PROJECT_ID, ROOT, Patch, Strict, canonical, digest, known_findings_enabled, request, seal, secret, setting
from safepatch.engine import Engine, check_expert_patch, expert_attempts_left, expert_scope, primary_finding
from safepatch.memory import Memory, context_for
from safepatch.acceptance import check_evidence
from safepatch.policy import PolicyError
from safepatch.repository import baseline
from safepatch.repository import projects, registry
from safepatch.store import Store
from safepatch.submission import ORIGIN as SUBMITTED, TOOL, submitted_patch

store = None
# Queued work: new jobs, and needs_human jobs that received an expert patch.
work = queue.Queue()


def consume():
    while True:
        job_id = work.get()
        try:
            job = store.get(job_id)
            if job["status"] == "queued":
                Engine(store).run(job_id)
                enqueue_children(job_id)
        finally:
            work.task_done()


def enqueue_children(job_id):
    """Per-file jobs split from this job's scan (week 4) wait in the same queue."""
    for child in store.get(job_id).get("children", []):
        if store.get(child)["status"] == "queued":
            work.put(child)


@asynccontextmanager
async def lifespan(app):
    global store
    store = Store()
    for job in store.all():
        if job["status"] == "queued":
            work.put(job["id"])
        elif job["status"] in ("scanning", "patching", "verifying", "deploying"):
            store.mutate(job["id"], lambda j: j.update(status="infrastructure_error", reason="orchestrator_restart_interrupted_job"))
    threading.Thread(target=consume, daemon=True).start()
    yield


app = FastAPI(title="BiGG SafePatch", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=ROOT / "safepatch/static"), name="static")


def audit(user, action, subject, **data):
    """A human decision joins the hash-chained audit log right after it took effect."""
    AuditLog(store).append(user["subject"], action, subject, **data)


def ensure_memory_and_evidence(job):
    try:
        if job.get("evaluation"):
            raise PolicyError("evaluation_job_cannot_be_approved_or_deployed")
        Memory(store).assert_active(job.get("memory_ids", []))
        check_evidence(job)
    except (PolicyError, KeyError) as exc:
        raise HTTPException(409, str(exc)) from exc


class Promote(Strict):
    job_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    reason: str = Field(min_length=10, max_length=1000)


@app.post("/v1/memory/promote", status_code=201)
def promote(req: Promote, user=Depends(identity)):
    require_role(user, "review")
    with store.lock:
        job = get_job(req.job_id, user)
        ensure_memory_and_evidence(job)
        case, files = baseline(job["case_id"], job["base_commit"])
        finding = primary_finding(job)
        context = context_for(case, files, finding)
        try:
            record = Memory(store).promote(job, context, files[finding["file"]], user["subject"], req.reason)
        except PolicyError as exc:
            raise HTTPException(409, str(exc)) from exc
        audit(user, "memory.promoted", record["id"], job_id=req.job_id, reason=req.reason, evidence_sha256=record.get("evidence_sha256"))
        return record


@app.get("/v1/memory")
def memories(user=Depends(identity)):
    return [r for r in Memory(store).all() if r["context"]["project"] in user["projects"]]


@app.get("/v1/memory/failures")
def failure_memory(user=Depends(identity)):
    return [r for r in Memory(store).failure_records() if r["context"]["project"] in user["projects"]]


@app.get("/v1/memory/shared")
def shared_memory(user=Depends(identity)):
    """L2: installed packages and their records (external data, no customer project in them).
    Imported offline with `python -m safepatch.l2 import`, never through this API."""
    shared = Memory(store).shared
    return {"packages": shared.installed(), "records": shared.all()}


class MemoryDecision(Strict):
    state: str = Field(pattern=r"^(quarantined|revoked|approved)$")   # approved: a reviewer re-approves (week 5)
    reason: str = Field(min_length=10, max_length=1000)


@app.post("/v1/memory/{memory_id}/state")
def memory_state(memory_id: str, req: MemoryDecision, user=Depends(identity)):
    require_role(user, "review")
    with store.lock:
        memory = Memory(store)
        try:
            record = memory.get(memory_id)
            if record["context"]["project"] not in user["projects"]:
                raise HTTPException(404, "Hafıza kaydı bulunamadı")
            record = memory.change(memory_id, req.state, user["subject"], req.reason)
        except KeyError as exc:
            raise HTTPException(404, "Hafıza kaydı bulunamadı") from exc
        except PolicyError as exc:
            raise HTTPException(409, str(exc)) from exc
        audit(user, "memory.state_changed", memory_id, state=req.state, reason=req.reason, affected_jobs=record.get("affected_jobs", []))
        return record


@app.middleware("http")
async def security_headers(req, call_next):
    response = await call_next(req)
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/", response_class=HTMLResponse)
def index():
    return (ROOT / "safepatch/static/index.html").read_text(encoding="utf-8")


@app.get("/health")
def health():
    return {"status": "ok", "service": "orchestrator", "policy": POLICY, "mode": "real-local-model"}


@app.get("/v1/me")
def me(user=Depends(identity)):
    return user


@app.get("/v1/cases")
def cases(user=Depends(identity)):
    specs = projects()
    # Evaluation cases with an answer key say so; the UI then offers the known-finding scanner.
    return {k: {**v, **({"known_findings": len(specs[k].scan.known)} if specs[k].scan.known else {})}
            for k, v in registry()[1].items() if v.get("project", "owned-java-demo") in user["projects"]}


SCANNERS = r"^(builtin|semgrep|sonarqube\+semgrep|known|findsecbugs|semgrep\+findsecbugs)$"
IDEMPOTENCY = r"^[A-Za-z0-9_-]+$"


class NewJob(Strict):
    case_id: str = Field(pattern=PROJECT_ID)   # registered project id (descriptor)
    idempotency_key: str = Field(min_length=8, max_length=100, pattern=IDEMPOTENCY)
    scanner: str = Field(default="semgrep", pattern=SCANNERS)
    max_attempts: int = Field(default=3, ge=1, le=3)
    second_review: bool = False
    memory_mode: str = Field(default="guarded", pattern=r"^(off|guarded)$")
    # Default chosen from the H2 measurement (docs/OLCUM_V02_YENIDEN_DENEME.md). Stored jobs
    # without this field keep the V0.1 loop in the engine.
    strategy: str = Field(default="guided+context", pattern=r"^(v01|sampling|guided|guided\+context)$")


def registered_case(case_id, user, scanner=None):
    """A registered project this user may submit to; the known-finding scanner's own conditions."""
    _, cases = registry()
    if case_id not in cases or cases[case_id].get("project", "owned-java-demo") not in user["projects"]:
        raise HTTPException(404, "Yetkili proje bulunamadı")
    if scanner == "known" and not known_findings_enabled():
        raise HTTPException(409, "known_findings_only_in_lab_profile")
    if scanner == "known" and not projects()[case_id].scan.known:
        raise HTTPException(409, "known_findings_need_answer_key_and_witness")
    return cases[case_id]


@app.post("/v1/jobs", status_code=201)
def create_job(req: NewJob, user=Depends(identity)):
    require_role(user, "submit")
    case = registered_case(req.case_id, user, req.scanner)
    now = time.time()
    data = {"id": uuid.uuid4().hex, "project": case.get("project", "owned-java-demo"), "memory_mode": req.memory_mode, "strategy": req.strategy, "case_id": req.case_id, "base_commit": case["commit"], "split": case["split"], "policy_version": POLICY, "scanner": req.scanner, "mode": "real-local-model", "status": "queued", "started_at": now, "deadline": now + int(setting("JOB_BUDGET_SECONDS", "1200")), "max_attempts": req.max_attempts, "attempt_count": 0, "attempts": [], "events": [{"time": now, "status": "queued"}], "owner": user["subject"], "second_review": req.second_review, "approval": None}
    try:
        job, created = store.create(data, user["subject"] + ":" + req.idempotency_key)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    if created:
        audit(user, "job.created", job["id"], case_id=req.case_id, base_commit=job["base_commit"], scanner=req.scanner,
              memory_mode=req.memory_mode, strategy=req.strategy, policy_version=POLICY)
        work.put(job["id"])
    return job


def get_job(job_id, user):
    try:
        job = store.get(job_id)
    except KeyError:
        raise HTTPException(404, "İş bulunamadı")
    if job.get("project", "owned-java-demo") not in user["projects"]:
        raise HTTPException(404, "İş bulunamadı")
    if job["owner"] != user["subject"] and not {"review", "deploy"}.intersection(user["roles"]):
        raise HTTPException(403, "Başka kullanıcıya ait iş")
    if job["status"] in ("awaiting_review", "approved") and time.time() > job["review_expires_at"]:
        job = store.mutate(job_id, lambda j: j.update(status="expired", reason="review_expired"))
    return job


@app.get("/v1/jobs")
def jobs(user=Depends(identity)):
    return [get_job(j["id"], user) for j in store.all() if j.get("project", "owned-java-demo") in user["projects"] and (j["owner"] == user["subject"] or {"review", "deploy"}.intersection(user["roles"]))]


@app.get("/v1/measurements")
def measurements(user=Depends(identity)):
    result = {}
    for name, filename in (("benchmark", "benchmark/summary.json"), ("acceptance", "acceptance/summary.json"), ("delivery", "delivery-summary.json")):
        file = ROOT / "evidence" / filename
        result[name] = json.loads(file.read_text(encoding="utf-8")) if file.exists() else {"status": "not_yet_measured"}
    return result


@app.get("/v1/jobs/{job_id}")
def job(job_id: str, user=Depends(identity)):
    return get_job(job_id, user)


@app.post("/v1/jobs/{job_id}/cancel")
def cancel(job_id: str, user=Depends(identity)):
    get_job(job_id, user)
    require_role(user, "submit")
    def change(j):
        if j["status"] in ("deployed", "deploying"):
            raise HTTPException(409, "Dağıtım iptal edilemez; rollback kullanın")
        j.update(status="cancelled", approval=None)
        j["events"].append({"time": time.time(), "status": "cancelled", "actor": user["subject"]})
    job = store.mutate(job_id, change)
    audit(user, "job.cancelled", job_id)
    return job


class ExpertPatch(Patch):
    # The author comes from the backend identity, never from the request body.
    rationale: str = Field(min_length=20, max_length=1600)


@app.get("/v1/jobs/{job_id}/expert-source")
def expert_source(job_id: str, user=Depends(identity)):
    """The finding's file as the expert edits it, with the base hash the patch must carry."""
    require_role(user, "submit")
    job = get_job(job_id, user)
    try:
        _, files, finding, allowed = expert_scope(job)
        if finding.get("file") not in allowed:
            raise PolicyError("finding_file_not_editable")
        content = files[finding["file"]]
    except PolicyError as exc:
        raise HTTPException(409, str(exc)) from exc
    return {"path": finding["file"], "content": content, "sha256": digest(content), "attempts_left": expert_attempts_left(job)}


@app.post("/v1/jobs/{job_id}/expert-patch/preview")
def expert_patch_preview(job_id: str, req: Patch, user=Depends(identity)):
    """Submission checks without storing anything: the diff exactly as it would be verified."""
    require_role(user, "submit")
    job = get_job(job_id, user)
    try:
        Memory(store).assert_active(job.get("memory_ids", []))
        return check_expert_patch(job, req)
    except PolicyError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.post("/v1/jobs/{job_id}/expert-patch", status_code=202)
def expert_patch(job_id: str, req: ExpertPatch, user=Depends(identity)):
    require_role(user, "submit")
    patch = Patch.model_validate(req.model_dump())
    with store.lock:
        job = get_job(job_id, user)
        try:
            Memory(store).assert_active(job.get("memory_ids", []))
            check_expert_patch(job, patch)
        except PolicyError as exc:
            # Refusals stay on the job's record; the job itself does not change.
            store.mutate(job_id, lambda j: j["events"].append({"time": time.time(), "status": "expert_patch_refused", "actor": user["subject"], "reason": str(exc)}))
            audit(user, "expert_patch.refused", job_id, reason=str(exc), patch_sha256=digest(canonical(patch.model_dump())))
            raise HTTPException(409, str(exc)) from exc
        now = time.time()
        def submit(j):
            j.update(status="queued", reason=None, deadline=now + int(setting("JOB_BUDGET_SECONDS", "1200")),
                     pending_expert_patch={"patch": patch.model_dump(), "author": user["subject"], "submitted_at": now})
            j["events"].append({"time": now, "status": "queued", "actor": user["subject"], "origin": "human-authored"})
        job = store.mutate(job_id, submit)
        audit(user, "expert_patch.submitted", job_id, patch_sha256=digest(canonical(patch.model_dump())), rationale=req.rationale)
    work.put(job_id)
    return job


class SubmittedDiff(Strict):
    case_id: str = Field(pattern=PROJECT_ID)
    # A unified diff (`git diff`) against the project's pinned base commit.
    diff: str = Field(min_length=1, max_length=200_000)
    rationale: str = Field(default="", max_length=1600)   # a draft may preview before its rationale is written


class Submission(SubmittedDiff):
    idempotency_key: str = Field(min_length=8, max_length=100, pattern=IDEMPOTENCY)
    scanner: str = Field(default="semgrep", pattern=SCANNERS)
    # The submitter comes from the backend identity, never from the request body.
    tool: str = Field(pattern=TOOL)
    rationale: str = Field(min_length=20, max_length=1600)


@app.post("/v1/verifications/preview")
def verification_preview(req: SubmittedDiff, user=Depends(identity)):
    """The submission checks without storing anything: the file and the diff exactly as they would be verified."""
    require_role(user, "submit")
    case = registered_case(req.case_id, user)
    try:
        patch, meta = submitted_patch(*baseline(req.case_id, case["commit"]), req.diff, req.rationale)
    except PolicyError as exc:
        raise HTTPException(409, str(exc)) from exc
    return {"path": patch.edits[0].path, **meta}


@app.post("/v1/verifications", status_code=201)
def submit_verification(req: Submission, user=Depends(identity)):
    """A patch written outside SafePatch, verified as it is: no model call, no memory (docs/YAMA_DOGRULAMA.md)."""
    require_role(user, "submit")
    case = registered_case(req.case_id, user, req.scanner)
    try:
        patch, meta = submitted_patch(*baseline(req.case_id, case["commit"]), req.diff, req.rationale)
    except PolicyError as exc:
        # Nothing is stored; who sent what, and why it was refused, joins the audit log.
        audit(user, "patch_submission.refused", req.case_id, reason=str(exc), diff_sha256=digest(req.diff), tool=req.tool)
        raise HTTPException(409, str(exc)) from exc
    now = time.time()
    submission = {"diff": req.diff, "diff_sha256": digest(req.diff), "rationale": req.rationale, "tool": req.tool, "author": user["subject"], "submitted_at": now}
    data = {"id": uuid.uuid4().hex, "project": case.get("project", "owned-java-demo"), "memory_mode": "off", "case_id": req.case_id, "base_commit": case["commit"], "split": case["split"],
            "policy_version": POLICY, "scanner": req.scanner, "mode": SUBMITTED, "status": "queued", "started_at": now, "deadline": now + int(setting("JOB_BUDGET_SECONDS", "1200")),
            "max_attempts": 1, "attempt_count": 0, "attempts": [], "events": [{"time": now, "status": "queued", "origin": SUBMITTED}], "owner": user["subject"],
            "second_review": False, "approval": None, "target_file": patch.edits[0].path, "submission": submission,
            "submission_sha256": digest(canonical({k: submission[k] for k in ("diff", "rationale", "tool")}))}
    try:
        job, created = store.create(data, user["subject"] + ":" + req.idempotency_key)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    if created:
        audit(user, "job.created", job["id"], case_id=req.case_id, base_commit=job["base_commit"], scanner=req.scanner, mode=SUBMITTED,
              tool=req.tool, diff_sha256=submission["diff_sha256"], patch_sha256=meta["patch_sha256"], policy_version=POLICY)
        work.put(job["id"])
    return job


class Decision(Strict):
    candidate_commit: str = Field(pattern=r"^[a-f0-9]{40}$")
    artifact_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    policy_version: str
    decision: str = Field(pattern=r"^(approve|reject)$")
    comment: str = Field(default="", max_length=1000)


@app.post("/v1/jobs/{job_id}/approval")
def approval(job_id: str, req: Decision, user=Depends(identity)):
    require_role(user, "review")
    get_job(job_id, user)
    def change(j):
        if j["status"] != "awaiting_review" or time.time() > j["review_expires_at"]:
            raise HTTPException(409, "İş onay beklemiyor veya süresi doldu")
        ensure_memory_and_evidence(j)
        c = j["candidate"]
        if c.get("author") is not None and c["author"] == user["subject"]:
            raise HTTPException(409, "Kendi yazdığınız yamayı onaylayamazsınız")
        if req.candidate_commit != c["commit"] or req.artifact_sha256 != c["artifact_sha256"] or req.policy_version != c["policy_version"] or req.policy_version != POLICY:
            raise HTTPException(409, "Onay kapsamı değişmiş")
        j["approval"] = {"job_id": job_id, "evidence_sha256": c["evidence_sha256"], "candidate_commit": req.candidate_commit, "artifact_sha256": req.artifact_sha256, "policy_version": POLICY, "reviewer": user["subject"], "approved_at": time.time(), "expires_at": j["review_expires_at"], "decision": req.decision, "comment": req.comment, "mode": j["mode"]}
        j["status"] = "approved" if req.decision == "approve" else "rejected"
        j["events"].append({"time": time.time(), "status": j["status"], "actor": user["subject"]})
    job = store.mutate(job_id, change)
    a = job["approval"]
    audit(user, "job." + job["status"], job_id, candidate_commit=a["candidate_commit"], artifact_sha256=a["artifact_sha256"],
          evidence_sha256=a["evidence_sha256"], policy_version=a["policy_version"], comment=a["comment"])
    # A reviewer's decision on a candidate built from memory is evidence about that record.
    for memory_id in job.get("memory_ids", []):
        Memory(store).settle(memory_id, job_id, review=req.decision)
    return job


@app.post("/v1/jobs/{job_id}/deploy")
def deploy(job_id: str, user=Depends(identity)):
    # Serializes release against memory revocation in the single-process profile.
    with store.lock:
        return release(job_id, user)


def release(job_id, user):
    require_role(user, "deploy")
    get_job(job_id, user)
    def reserve(j):
        if j["status"] != "approved" or not j["approval"] or time.time() > j["approval"]["expires_at"]:
            raise HTTPException(409, "Geçerli insan onayı gerekli")
        ensure_memory_and_evidence(j)
        a, c = j["approval"], j["candidate"]
        if a["artifact_sha256"] != c["artifact_sha256"] or a["candidate_commit"] != c["commit"] or a["policy_version"] != POLICY:
            raise HTTPException(409, "Artifact/commit/politika değişmiş")
        j["status"] = "deploying"
    data = store.mutate(job_id, reserve)
    payload = data["approval"]
    try:
        result = request(setting("DEPLOYER_URL", "http://127.0.0.1:8104") + "/deploy", "POST", token=secret("DEPLOYER_TOKEN"), body={"approval": payload, "signature": seal(payload, secret("APPROVAL_SIGNING_KEY"))}, timeout=90)
    except Exception as exc:
        store.mutate(job_id, lambda j: j.update(status="infrastructure_error", reason="staging_failed"))
        audit(user, "job.deploy_failed", job_id, artifact_sha256=payload["artifact_sha256"])
        raise HTTPException(502, "Staging dağıtımı doğrulanamadı") from exc
    job = store.mutate(job_id, lambda j: j.update(status="deployed", deployment=result))
    audit(user, "job.deployed", job_id, artifact_sha256=payload["artifact_sha256"], deployment_sha256=digest(canonical(result)))
    return job


@app.post("/v1/staging/rollback")
def rollback(user=Depends(identity)):
    require_role(user, "deploy")
    result = request(setting("DEPLOYER_URL", "http://127.0.0.1:8104") + "/rollback", "POST", token=secret("DEPLOYER_TOKEN"), body={"actor": user["subject"]}, timeout=90)
    audit(user, "staging.rolled_back", "staging", artifact_sha256=result.get("artifact_sha256"))
    return result


@app.get("/v1/jobs/{job_id}/evidence.json")
def evidence(job_id: str, user=Depends(identity)):
    return get_job(job_id, user)


@app.get("/v1/jobs/{job_id}/evidence.html", response_class=HTMLResponse)
def evidence_html(job_id: str, user=Depends(identity)):
    j = get_job(job_id, user)
    return "<!doctype html><html lang='tr'><meta charset='utf-8'><title>SafePatch Kanıtı</title><h1>Yerel DevSecOps kanıt paketi</h1><p>Mod: " + html.escape(j["mode"]) + " · Durum: " + html.escape(j["status"]) + "</p><p>Otomatik doğrulama bağımsız AppSec onayı değildir.</p><pre>" + html.escape(json.dumps(j, ensure_ascii=False, indent=2)) + "</pre></html>"
