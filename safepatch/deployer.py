import json
import os
from pathlib import Path
import subprocess
import socket
import threading
import time

import httpx
from fastapi import Depends, FastAPI, HTTPException
from pydantic import Field

from safepatch.common import POLICY, Strict, digest, local_url, require_service, runtime, secret, setting, verify_seal
from safepatch.process import child_env, terminate

app = FastAPI(title="Human-approved local staging")
lock = threading.Lock()
process = None


class Deployment(Strict):
    approval: dict
    signature: str = Field(pattern=r"^[a-f0-9]{64}$")


def check_approval(approval, signature, key, now=None, historical=False):
    verify_seal(approval, signature, key)
    if approval.get("decision") != "approve" or approval.get("policy_version") != POLICY or not approval.get("reviewer"):
        raise ValueError("invalid_approval")
    if not historical and (now or time.time()) > approval["expires_at"]:
        raise ValueError("expired_approval")
    if approval.get("mode") != "real-local-model" and setting("ALLOW_TEST_DEPLOYMENT") != "1":
        raise ValueError("mock_artifact_refused")


def ledger():
    file = runtime("staging") / "ledger.json"
    return json.loads(file.read_text()) if file.exists() else {"history": [], "active": None, "events": []}


def save_ledger(data):
    file = runtime("staging") / "ledger.json"
    temp = file.with_suffix(".tmp")
    temp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    temp.replace(file)


def download(checksum):
    import re
    if not re.fullmatch(r"[a-f0-9]{64}", checksum):
        raise ValueError("invalid_artifact_digest")
    url = local_url(setting("WORKER2_URL", "http://127.0.0.1:8102")) + "/artifacts/" + checksum
    with httpx.Client(trust_env=False, follow_redirects=False, timeout=30) as client:
        response = client.get(url, headers={"Authorization": "Bearer " + secret("ARTIFACT_READ_TOKEN")})
        response.raise_for_status()
    if response.is_redirect or digest(response.content) != checksum:
        raise ValueError("artifact_digest_mismatch")
    file = runtime("staging/artifacts") / (checksum + ".jar")
    file.write_bytes(response.content)
    return file


def launch(file, checksum):
    global process
    if digest(file.read_bytes()) != checksum:
        raise ValueError("stored_artifact_changed")
    if process:
        terminate(process)
    port = int(setting("STAGING_PORT", "18080"))
    # Fail before launch if an unrelated process owns the staging port.
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", port))
    env = child_env()
    with (runtime("staging") / "application.log").open("ab") as output:
        process = subprocess.Popen(["java", "-Xmx256m", "-jar", str(file), "--server.address=" + setting("STAGING_BIND", "127.0.0.1"), "--server.port=" + str(port)], cwd=runtime("staging"), env=env, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, start_new_session=os.name != "nt", creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    for _ in range(60):
        if process.poll() is not None:
            raise RuntimeError("staging_process_exited")
        try:
            with httpx.Client(trust_env=False, timeout=1) as client:
                resp = client.get(f"http://127.0.0.1:{port}/health")
                if resp.status_code == 200 and resp.json().get("scope") == "synthetic-local-staging":
                    return {"pid": process.pid, "artifact_sha256": checksum, "health": "ok", "url": f"http://127.0.0.1:{port}", "built_after_approval": False}
        except httpx.HTTPError:
            pass
        time.sleep(0.5)
    terminate(process)
    raise RuntimeError("staging_health_timeout")


@app.get("/health")
def health():
    return {"status": "ok", "service": "deployer", "scope": "local-staging-only"}


@app.post("/deploy", dependencies=[Depends(require_service("DEPLOYER_TOKEN"))])
def deploy(req: Deployment):
    with lock:
        try:
            check_approval(req.approval, req.signature, secret("APPROVAL_SIGNING_KEY"))
            checksum = req.approval["artifact_sha256"]
            data = ledger()
            existing = next((r for r in data["history"] if r["approval"]["job_id"] == req.approval["job_id"]), None)
            if existing:
                if existing["approval"] != req.approval:
                    raise ValueError("approval_replay_mismatch")
                # Retry must not silently re-deploy an older artifact over a newer one.
                if data["active"] != req.approval["job_id"]:
                    raise ValueError("already_deployed_historical_job")
                return existing["result"]
            file = download(checksum)
            result = launch(file, checksum)
            record = {**req.model_dump(), "result": result, "deployed_at": time.time()}
            data["history"].append(record)
            data["active"] = req.approval["job_id"]
            data["events"].append({"action": "deploy", "job_id": data["active"], "digest": checksum, "time": time.time()})
            save_ledger(data)
            return result
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc


class Rollback(Strict):
    actor: str = Field(min_length=1, max_length=100)


@app.post("/rollback", dependencies=[Depends(require_service("DEPLOYER_TOKEN"))])
def rollback(req: Rollback):
    with lock:
        data = ledger()
        index = next((i for i, r in enumerate(data["history"]) if r["approval"]["job_id"] == data["active"]), -1)
        if index < 1:
            raise HTTPException(409, "previous_approved_artifact_not_available")
        target = data["history"][index - 1]
        check_approval(target["approval"], target["signature"], secret("APPROVAL_SIGNING_KEY"), historical=True)
        checksum = target["approval"]["artifact_sha256"]
        result = launch(runtime("staging/artifacts") / (checksum + ".jar"), checksum)
        data["active"] = target["approval"]["job_id"]
        data["events"].append({"action": "rollback", "actor": req.actor, "job_id": data["active"], "digest": checksum, "time": time.time()})
        save_ledger(data)
        return result
