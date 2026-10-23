import time

import pytest

from safepatch.common import SOURCE
from safepatch.engine import Engine


def fake_initial():
    return {"baseline_valid": True, "scans": [{"findings": [{"rule_id": "test.rule", "file": SOURCE}]}]}


def scenario(job_store, patch_factory, source, failures, duplicate=False):
    db, job = job_store
    count = {"propose": 0, "verify": 0}
    def call(url, method="GET", **kwargs):
        body = kwargs.get("body", {})
        if url.endswith("/propose"):
            count["propose"] += 1
            number = 1 if duplicate else count["propose"]
            return {"mode": "mock-test", "patch": patch_factory(source[SOURCE] + f"// mock variation {number}\n").model_dump()}
        if body.get("attempt") == 0:
            return fake_initial()
        count["verify"] += 1
        return failures[count["verify"] - 1]
    Engine(db, call).run(job["id"])
    return db.get(job["id"]), count


def test_three_attempt_cap(job_store, patch_factory, source):
    failures = [{"passed": False, "feedback": {"code": code}} for code in ("compile", "behavior", "security")]
    job, count = scenario(job_store, patch_factory, source, failures)
    assert count == {"propose": 3, "verify": 3}
    assert job["reason"] == "attempt_budget_exhausted"


def test_same_patch_stops_early(job_store, patch_factory, source):
    job, count = scenario(job_store, patch_factory, source, [{"passed": False, "feedback": {"code": "compile"}}], True)
    assert count == {"propose": 2, "verify": 1}
    assert job["reason"] == "duplicate_patch"


def test_no_progress_stops_early(job_store, patch_factory, source):
    failures = [{"passed": False, "feedback": {"code": "compile"}}] * 2
    job, count = scenario(job_store, patch_factory, source, failures)
    assert count["propose"] == 2
    assert job["reason"] == "no_progress"


def test_scanner_failure_is_not_clean(job_store):
    db, job = job_store
    def broken(*args, **kwargs):
        raise RuntimeError("scanner failed")
    Engine(db, broken).run(job["id"])
    assert db.get(job["id"])["status"] == "infrastructure_error"
    assert db.get(job["id"])["attempt_count"] == 0


def test_job_deadline(job_store):
    db, job = job_store
    db.mutate(job["id"], lambda j: j.update(deadline=time.time() - 1))
    Engine(db, lambda *a, **k: pytest.fail("worker called after deadline")).run(job["id"])
    assert db.get(job["id"])["reason"] == "job_deadline_exceeded"


def test_cancelled_job_cannot_progress(job_store):
    db, job = job_store
    db.mutate(job["id"], lambda j: j.update(status="cancelled"))
    Engine(db, lambda *a, **k: pytest.fail("cancelled worker called")).run(job["id"])
    assert db.get(job["id"])["status"] == "cancelled"


def test_mock_result_not_accepted_as_real(job_store, patch_factory):
    db, job = job_store
    db.mutate(job["id"], lambda j: j.update(mode="real-local-model"))
    def call(url, *a, **kwargs):
        return fake_initial() if url.endswith("/verify") else {"mode": "mock-test", "patch": patch_factory().model_dump()}
    Engine(db, call).run(job["id"])
    assert db.get(job["id"])["reason"] == "mock_result_on_real_job"


def test_success_waits_for_human(job_store, patch_factory, source):
    success = {"passed": True, "candidate_commit": "a" * 40, "artifact_sha256": "b" * 64, "review_repository": "mock-only", "review_branch": "candidate"}
    job, _ = scenario(job_store, patch_factory, source, [success])
    assert job["status"] == "awaiting_review"
    assert job["approval"] is None
