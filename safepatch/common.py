import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import socket
import time
from urllib.parse import urlsplit

import httpx
from fastapi import Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

ROOT = Path(__file__).resolve().parents[1]
POLICY = "java-synthetic-v1"
SOURCE = "src/main/java/demo/DemoService.java"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def setting(name, default=None):
    return os.environ.get(name, default)


def runtime(part=""):
    base = Path(setting("DATA_ROOT", str(ROOT / ".runtime")))
    path = base / part
    path.mkdir(parents=True, exist_ok=True)
    return path


def secret(name):
    value = setting(name)
    file = setting(name + "_FILE")
    if file:
        value = Path(file).read_text(encoding="utf-8").strip()
    if not value or len(value) < 32:
        raise RuntimeError(f"{name}: unique secret of at least 32 characters required")
    return value


def require_service(name):
    def dependency(authorization: str = Header(default="")):
        if not hmac.compare_digest(authorization, "Bearer " + secret(name)):
            raise HTTPException(401, "Service credential required")
    return dependency


def local_url(url):
    """Explicit local/private endpoint, no proxy, redirect, userinfo or cloud alias."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("Invalid local endpoint")
    allowed_names = {"ollama", "worker1", "worker2", "runner", "deployer", "sonarqube", "orchestrator"}
    if parts.hostname in allowed_names or parts.hostname == "localhost":
        return url.rstrip("/")
    try:
        addresses = [ipaddress.ip_address(parts.hostname)]
    except ValueError:
        addresses = [ipaddress.ip_address(x[4][0]) for x in socket.getaddrinfo(parts.hostname, parts.port or 80)]
    if not addresses or not all(a.is_loopback or (a.is_private and not a.is_link_local and not a.is_unspecified and not a.is_multicast) for a in addresses):
        raise ValueError("Only loopback/private endpoints are allowed")
    return url.rstrip("/")


def request(url, method="GET", *, token=None, body=None, timeout=30):
    local_url(url)
    headers = {"Authorization": "Bearer " + token} if token else {}
    with httpx.Client(trust_env=False, follow_redirects=False, timeout=timeout) as client:
        response = client.request(method, url, headers=headers, json=body)
    if response.is_redirect:
        raise RuntimeError("Redirect refused")
    response.raise_for_status()
    return response.json()


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Edit(Strict):
    path: str = Field(max_length=180)
    old_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    content: str = Field(max_length=24000)


class Patch(Strict):
    edits: list[Edit] = Field(min_length=1, max_length=3)
    rationale: str = Field(max_length=1600)


class VerifyRequest(Strict):
    job_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    case_id: str = Field(pattern=r"^(sql|path|command)-0[123]$")
    base_commit: str = Field(pattern=r"^[a-f0-9]{40}$")
    attempt: int = Field(ge=0, le=3)
    deadline: float
    patch: Patch | None = None
    scanner: str = Field(default="builtin", pattern=r"^(builtin|semgrep|sonarqube\+semgrep)$")


def remaining(deadline, cap=240):
    seconds = deadline - time.time()
    if seconds < 1:
        raise TimeoutError("job_deadline_exceeded")
    return max(1, min(seconds, cap))


def seal(payload, key):
    return hmac.new(key.encode(), canonical(payload).encode(), "sha256").hexdigest()


def verify_seal(payload, signature, key):
    if not hmac.compare_digest(seal(payload, key), signature):
        raise ValueError("Approval signature mismatch")
