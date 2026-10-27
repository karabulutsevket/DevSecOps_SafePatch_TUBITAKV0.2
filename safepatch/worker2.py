import base64
from pathlib import Path
import uuid

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse

from safepatch.common import VerifyRequest, digest, remaining, request, require_service, runtime, secret, setting
from safepatch.policy import validate_patch
from safepatch.repository import allowed_files, baseline, checkout, commit_candidate
from safepatch.acceptance import untolerated

app = FastAPI(title="Worker2 - independent verifier")


@app.get("/health")
def health():
    return {"service": "worker2", "status": "ok", "role": "verifier-without-AI-authority"}


@app.post("/verify", dependencies=[Depends(require_service("WORKER2_TOKEN"))])
def verify(req: VerifyRequest):
    case, files = baseline(req.case_id, req.base_commit)
    allowed = allowed_files(case["spec"], files, req.target_file)
    meta = validate_patch(files, req.patch, allowed=allowed) if req.patch else None
    result = request(setting("RUNNER_URL", "http://127.0.0.1:8103") + "/execute", "POST", token=secret("RUNNER_TOKEN"), body=req.model_dump(), timeout=remaining(req.deadline, 1200))
    if result.get("passed"):
        scans = result["scans"]
        if not req.patch or not result["behavior"]["passed"] or not result["security"]["passed"] or any(s["status"] != "ok" for s in scans) or untolerated([f for s in scans for f in s["findings"]], req.tolerated):
            raise HTTPException(502, "runner_result_inconsistent")
        binary = base64.b64decode(result.pop("artifact_b64"), validate=True)
        checksum = digest(binary)
        if checksum != result["artifact_sha256"] or result["patch"]["patch_sha256"] != meta["patch_sha256"]:
            raise HTTPException(502, "runner_artifact_mismatch")
        artifact = runtime("verified-artifacts") / (checksum + ".jar")
        artifact.write_bytes(binary)
        # Independent review copy: same pinned base, same patch, so the same candidate commit.
        review = runtime("review") / (req.job_id + "-" + uuid.uuid4().hex[:8])
        checkout(req.case_id, req.base_commit, review)
        validate_patch(files, req.patch, review, allowed)
        result["candidate_commit"] = commit_candidate(review, req.base_commit, req.patch.edits, meta["diff"])
        if result["candidate_commit"] != result["source_revision"]:
            raise HTTPException(502, "candidate_commit_mismatch")
        result["review_branch"] = "candidate"
        result["review_repository"] = str(review)
    return result


@app.get("/artifacts/{checksum}", dependencies=[Depends(require_service("ARTIFACT_READ_TOKEN"))])
def artifact(checksum: str):
    import re
    if not re.fullmatch(r"[a-f0-9]{64}", checksum):
        raise HTTPException(400, "invalid_digest")
    file = runtime("verified-artifacts") / (checksum + ".jar")
    if not file.exists() or digest(file.read_bytes()) != checksum:
        raise HTTPException(409, "artifact_missing_or_changed")
    return FileResponse(file, media_type="application/java-archive")
