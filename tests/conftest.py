import json
import time
import uuid

import pytest

from safepatch.common import POLICY, SOURCE, Patch, digest
from safepatch.repository import registry
from safepatch.store import Store


@pytest.fixture
def source():
    from safepatch.repository import baseline
    case = registry()[1]["sql-01"]
    return baseline("sql-01", case["commit"])[1]


@pytest.fixture
def patch_factory(source):
    def factory(content=None, path=SOURCE):
        return Patch.model_validate({"edits": [{"path": path, "old_sha256": digest(source[SOURCE]), "content": content or source[SOURCE].replace("// Case", "// changed Case")}], "rationale": "MOCK TEST ONLY"})
    return factory


@pytest.fixture
def job_store(tmp_path, monkeypatch):
    for name in ("WORKER1_TOKEN", "WORKER2_TOKEN", "DEPLOYER_TOKEN", "APPROVAL_SIGNING_KEY", "ARTIFACT_READ_TOKEN"):
        monkeypatch.setenv(name, "test-only-" + name * 4)
        monkeypatch.delenv(name + "_FILE", raising=False)
    db = Store("sqlite:///" + str(tmp_path / "jobs.db"))
    now = time.time()
    j = {"id": uuid.uuid4().hex, "case_id": "sql-01", "base_commit": registry()[1]["sql-01"]["commit"], "policy_version": POLICY, "scanner": "builtin", "status": "queued", "mode": "mock-test", "owner": "developer", "started_at": now, "deadline": now + 1200, "attempt_count": 0, "max_attempts": 3, "attempts": [], "events": [], "approval": None}
    db.create(j, "test-key")
    return db, j


@pytest.fixture
def api(job_store, tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from safepatch import orchestrator
    db, job = job_store
    users = [{"subject": role, "roles": [permission], "token_sha256": digest(role + "-secret")} for role, permission in (("developer", "submit"), ("reviewer", "review"), ("deployer", "deploy"))]
    file = tmp_path / "users.json"
    file.write_text(json.dumps(users))
    monkeypatch.setenv("USERS_FILE", str(file))
    monkeypatch.setattr(orchestrator, "store", db)
    client = TestClient(orchestrator.app)
    return client, db, job


def headers(role):
    return {"Authorization": "Bearer " + role + "-secret"}
