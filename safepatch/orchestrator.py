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

from safepatch.auth import identity, require_role
from safepatch.common import POLICY, ROOT, Strict, request, seal, secret, setting
from safepatch.engine import Engine
from safepatch.memory import Memory, context_for
from safepatch.acceptance import check_evidence
from safepatch.policy import PolicyError
from safepatch.repository import baseline
from safepatch.common import SOURCE
from safepatch.repository import registry
from safepatch.store import Store

store = None
work = queue.Queue()


def consume():
    while True:
        job_id = work.get()
        try:
            job = store.get(job_id)
            if job["status"] == "queued":
                Engine(store).run(job_id)
        finally:
            work.task_done()


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
        context = context_for(case, files, job["baseline"]["scans"][0]["findings"][0])
        try:
            return Memory(store).promote(job, context, files[SOURCE], user["subject"], req.reason)
        except PolicyError as exc:
            raise HTTPException(409, str(exc)) from exc


@app.get("/v1/memory")
def memories(user=Depends(identity)):
    return [r for r in Memory(store).all() if r["context"]["project"] in user["projects"]]


class MemoryDecision(Strict):
    state: str = Field(pattern=r"^(quarantined|revoked)$")
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
            return memory.change(memory_id, req.state, user["subject"], req.reason)
        except KeyError as exc:
            raise HTTPException(404, "Hafıza kaydı bulunamadı") from exc
        except PolicyError as exc:
            raise HTTPException(409, str(exc)) from exc


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
    return {k: v for k, v in registry()[1].items() if v.get("project", "owned-java-demo") in user["projects"]}


class NewJob(Strict):
    case_id: str = Field(pattern=r"^(sql|path|command)-0[123]$")
    idempotency_key: str = Field(min_length=8, max_length=100, pattern=r"^[A-Za-z0-9_-]+$")
    scanner: str = Field(default="semgrep", pattern=r"^(builtin|semgrep|sonarqube\+semgrep)$")
    max_attempts: int = Field(default=3, ge=1, le=3)
    second_review: bool = False
    memory_mode: str = Field(default="guarded", pattern=r"^(off|guarded)$")


@app.post("/v1/jobs", status_code=201)
def create_job(req: NewJob, user=Depends(identity)):
    require_role(user, "submit")
    _, cases = registry()
    if req.case_id not in cases or cases[req.case_id].get("project", "owned-java-demo") not in user["projects"]:
        raise HTTPException(404, "Yetkili proje bulunamadı")
    now = time.time()
    data = {"id": uuid.uuid4().hex, "project": cases[req.case_id].get("project", "owned-java-demo"), "memory_mode": req.memory_mode, "case_id": req.case_id, "base_commit": cases[req.case_id]["commit"], "split": cases[req.case_id]["split"], "policy_version": POLICY, "scanner": req.scanner, "mode": "real-local-model", "status": "queued", "started_at": now, "deadline": now + int(setting("JOB_BUDGET_SECONDS", "1200")), "max_attempts": req.max_attempts, "attempt_count": 0, "attempts": [], "events": [{"time": now, "status": "queued"}], "owner": user["subject"], "second_review": req.second_review, "approval": None}
    try:
        job, created = store.create(data, user["subject"] + ":" + req.idempotency_key)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    if created:
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
    return store.mutate(job_id, change)


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
        if req.candidate_commit != c["commit"] or req.artifact_sha256 != c["artifact_sha256"] or req.policy_version != c["policy_version"] or req.policy_version != POLICY:
            raise HTTPException(409, "Onay kapsamı değişmiş")
        j["approval"] = {"job_id": job_id, "evidence_sha256": c["evidence_sha256"], "candidate_commit": req.candidate_commit, "artifact_sha256": req.artifact_sha256, "policy_version": POLICY, "reviewer": user["subject"], "approved_at": time.time(), "expires_at": j["review_expires_at"], "decision": req.decision, "comment": req.comment, "mode": j["mode"]}
        j["status"] = "approved" if req.decision == "approve" else "rejected"
        j["events"].append({"time": time.time(), "status": j["status"], "actor": user["subject"]})
    return store.mutate(job_id, change)


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
        raise HTTPException(502, "Staging dağıtımı doğrulanamadı") from exc
    return store.mutate(job_id, lambda j: j.update(status="deployed", deployment=result))


@app.post("/v1/staging/rollback")
def rollback(user=Depends(identity)):
    require_role(user, "deploy")
    return request(setting("DEPLOYER_URL", "http://127.0.0.1:8104") + "/rollback", "POST", token=secret("DEPLOYER_TOKEN"), body={"actor": user["subject"]}, timeout=90)


@app.get("/v1/jobs/{job_id}/evidence.json")
def evidence(job_id: str, user=Depends(identity)):
    return get_job(job_id, user)


@app.get("/v1/jobs/{job_id}/evidence.html", response_class=HTMLResponse)
def evidence_html(job_id: str, user=Depends(identity)):
    j = get_job(job_id, user)
    return "<!doctype html><html lang='tr'><meta charset='utf-8'><title>SafePatch Kanıtı</title><h1>Yerel DevSecOps kanıt paketi</h1><p>Mod: " + html.escape(j["mode"]) + " · Durum: " + html.escape(j["status"]) + "</p><p>Otomatik doğrulama bağımsız AppSec onayı değildir.</p><pre>" + html.escape(json.dumps(j, ensure_ascii=False, indent=2)) + "</pre></html>"
