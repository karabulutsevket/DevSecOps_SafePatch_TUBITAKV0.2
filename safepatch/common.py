import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import socket
import time
from urllib.parse import urlsplit

import httpx
from fastapi import Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

ROOT = Path(__file__).resolve().parents[1]
POLICY = "java-synthetic-v1"
# Editable file of the nine synthetic cases; real projects declare theirs in a descriptor.
SOURCE = "src/main/java/demo/DemoService.java"
PROJECT_ID = r"^[a-z0-9][a-z0-9._-]{0,62}$"


def safe_path(path):
    """Relative POSIX path inside a repository; no traversal, drive letter or backslash."""
    pure = PurePosixPath(path or "")
    return bool(path) and not pure.is_absolute() and ".." not in pure.parts and "\\" not in path and ":" not in path


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def setting(name, default=None):
    return os.environ.get(name, default)


# The model rewrites the whole file, so the file must fit its 8K-token context (worker1).
MODEL_SOURCE_CHARS = 24000
# A larger file is shown as the methods holding its findings (region mode, safepatch/region.py).
# The model returns those methods too: 2,048 output tokens hold about 6,000 characters of Java
# as JSON, so the regions stay well below that to leave room for the fix.
MODEL_REGION_CHARS = 5000


def known_findings_enabled():
    """Findings from an answer key are for the lab and evaluation profiles only (roadmap week 6)."""
    return setting("SAFEPATCH_PROFILE", "product") in ("lab", "evaluation")


def runtime(part=""):
    base = Path(setting("DATA_ROOT", str(ROOT / ".runtime")))
    path = base / part
    path.mkdir(parents=True, exist_ok=True)
    return path


def evidence(part=""):
    """Writable location for new measurements; V0.1 evidence is a read-only archive.

    EVIDENCE_DIR may be an evidence/v02-* folder or a path outside evidence/
    (tests, scratch runs). The archive root and its V0.1 folders are refused.
    """
    archive = (ROOT / "evidence").resolve()
    base = Path(setting("EVIDENCE_DIR", "evidence/v02-local"))
    base = (base if base.is_absolute() else ROOT / base).resolve()
    if base == archive or (base.is_relative_to(archive) and not base.relative_to(archive).parts[0].startswith("v02-")):
        raise RuntimeError("V0.1 evidence is read-only; set EVIDENCE_DIR to evidence/v02-<name>")
    base.mkdir(parents=True, exist_ok=True)
    return base / part


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
    # Whole-file replacement; real project files run to ~100 KB. The model input stays capped in worker1.
    content: str = Field(max_length=1_000_000)


class Patch(Strict):
    edits: list[Edit] = Field(min_length=1, max_length=3)
    rationale: str = Field(max_length=1600)


class VerifyRequest(Strict):
    job_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    case_id: str = Field(pattern=PROJECT_ID)
    base_commit: str = Field(pattern=r"^[a-f0-9]{40}$")
    attempt: int = Field(ge=0, le=6)   # 0 baseline; up to 3 model and then 3 expert attempts
    deadline: float
    patch: Patch | None = None
    scanner: str = Field(default="builtin", pattern=r"^(builtin|semgrep|sonarqube\+semgrep|known|findsecbugs|semgrep\+findsecbugs)$")
    # The finding's file: the only file a patch may change (decision 5, 25 Oct 2026).
    target_file: str | None = Field(default=None, max_length=300)
    # Fingerprints of baseline findings in other files. Only the target file changes, so they
    # may remain; anything else left after the patch, or new, fails the rescan (week 4).
    tolerated: list[str] = Field(default_factory=list, max_length=500)

    @field_validator("tolerated")
    @classmethod
    def fingerprints(cls, value):
        if any(not re.fullmatch(r"[A-Za-z0-9_:.\-]{1,200}", v) for v in value):
            raise ValueError("invalid finding fingerprint")
        return value

    @field_validator("target_file")
    @classmethod
    def target_path(cls, value):
        if value is not None and not safe_path(value):
            raise ValueError("unsafe target file")
        return value


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
