import copy
import time

import pytest

from conftest import headers
from test_approval import ready
from safepatch.acceptance import check_evidence
from safepatch.common import SOURCE, canonical, digest
from safepatch.memory import Memory, applicability, context_for
from safepatch.policy import PolicyError, validate_patch
from safepatch.repository import baseline, registry
from mock_patches import correct_patch


def approved_record(db, job, actor="SIMULATED-UNIT-REVIEWER"):
    case, files = baseline(job["case_id"], job["base_commit"])
    patch = correct_patch(case["kind"], files)
    meta = validate_patch(files, patch)
    ready(db, job)
    j = db.get(job["id"])
    j["candidate"].update(patch_sha256=meta["patch_sha256"], diff=meta["diff"])
    j["acceptance_manifest"]["patch_sha256"] = meta["patch_sha256"]
    j["candidate"]["evidence_sha256"] = digest(canonical(j["acceptance_manifest"]))
    j.update(status="approved", attempts=[{"proposal": {"mode": "mock-test", "patch": patch.model_dump()}, "patch_sha256": meta["patch_sha256"], "verification": {"passed": True}}])
    j["approval"] = {"decision": "approve", "candidate_commit": j["candidate"]["commit"], "artifact_sha256": j["candidate"]["artifact_sha256"], "policy_version": j["candidate"]["policy_version"], "expires_at": time.time()+300, "reviewer": actor}
    j["baseline"] = {"scans": [{"findings": [{"rule_id": "bigg.java.sql-concatenation"}]}]}
    db.mutate(j["id"], lambda x: x.update(j))
    context = context_for(case, files, j["baseline"]["scans"][0]["findings"][0])
    return Memory(db).promote(j, context, files[SOURCE], actor, "Simulated unit fixture approval")


@pytest.mark.parametrize("field", ["project", "kind", "rule_id", "jdk", "source_path", "build_sha256", "contract_sha256"])
def test_wrong_precondition_never_replayed(job_store, field):
    db, job = job_store
    record = approved_record(db, job)
    changed = {**record["context"], field: "different"}
    assert applicability(record["context"], changed) == "incompatible"
    assert Memory(db).search(changed)["selected"] is None


@pytest.mark.parametrize("field", ["kind", "jdk", "build_sha256", "contract_sha256"])
def test_unknown_precondition_abstains(job_store, field):
    db, job = job_store
    record = approved_record(db, job)
    changed = {**record["context"], field: None}
    assert applicability(record["context"], changed) == "unknown"
    assert Memory(db).search(changed)["selected"] is None


def test_exact_match_and_disable(job_store):
    db, job = job_store
    record = approved_record(db, job)
    assert Memory(db).search(record["context"])["selected"]["id"] == record["id"]
    assert Memory(db).search(record["context"], "off")["selected"] is None


def test_no_promotion_without_human_approval(job_store, source):
    db, job = job_store
    with pytest.raises(PolicyError, match="human_approved"):
        Memory(db).promote(job, {}, source[SOURCE], "worker1", "cannot approve")


def test_evaluation_cannot_promote(job_store):
    db, job = job_store
    job["evaluation"] = True
    with pytest.raises(PolicyError, match="evaluation"):
        Memory(db).promote(job, {}, "", "test", "blocked")


@pytest.mark.parametrize("state", ["revoked", "quarantined"])
def test_lifecycle_invalidates_waiting_approval(job_store, state):
    db, job = job_store
    record = approved_record(db, job)
    db.mutate(job["id"], lambda j: j.update(memory_ids=[record["id"]]))
    result = Memory(db).change(record["id"], state, "reviewer", "Unsafe pattern discovered")
    assert result["affected_jobs"] == [job["id"]]
    assert db.get(job["id"])["approval"] is None
    assert db.get(job["id"])["status"] == "needs_human"
    assert Memory(db).search(record["context"])["selected"] is None
    with pytest.raises(PolicyError):
        Memory(db).assert_active([record["id"]])


def test_deployed_revocation_alert_does_not_silently_rollback(job_store):
    db, job = job_store
    record = approved_record(db, job)
    db.mutate(job["id"], lambda j: j.update(memory_ids=[record["id"]], status="deployed"))
    Memory(db).change(record["id"], "revoked", "reviewer", "Defect found later")
    assert db.get(job["id"])["status"] == "deployed"
    assert db.get(job["id"])["memory_alert"]["state"] == "revoked"


def test_revocation_survives_database_reopen(job_store):
    from safepatch.store import Store
    db, job = job_store
    r = approved_record(db, job)
    Memory(db).change(r["id"], "revoked", "reviewer", "Persistent revocation")
    reopened = Store(str(db.engine.url))
    assert Memory(reopened).search(r["context"])["selected"] is None


def test_worker_or_submitter_cannot_promote(api):
    client, db, job = api
    assert client.post('/v1/memory/promote', headers=headers('developer'), json={"job_id": job["id"], "reason": "Attempted by submitter"}).status_code == 403


def test_changed_evidence_is_not_approvable(api):
    client, db, job = api
    decision = ready(db, job)
    db.mutate(job["id"], lambda j: j["acceptance_manifest"]["verification"].update(passed=False))
    assert client.post(f'/v1/jobs/{job["id"]}/approval', headers=headers('reviewer'), json=decision).status_code == 409


def test_evaluation_approval_blocked(api):
    client, db, job = api
    decision = ready(db, job)
    db.mutate(job["id"], lambda j: j.update(evaluation=True))
    assert client.post(f'/v1/jobs/{job["id"]}/approval', headers=headers('reviewer'), json=decision).status_code == 409


def test_replay_runs_verifier_but_not_llm(job_store):
    from safepatch.engine import Engine
    db, job = job_store
    record = approved_record(db, job)
    db.mutate(job["id"], lambda j: j.update(status="queued", approval=None, attempts=[]))
    calls = []
    def call(url, *args, **kwargs):
        calls.append(url)
        assert not url.endswith('/propose'), "exact replay must not invoke LLM"
        if kwargs['body']['attempt'] == 0:
            return {"baseline_valid": True, "scans": [{"findings": [{"rule_id": record["context"]["rule_id"]}]}]}
        return {"passed": False, "feedback": {"code": "security_regression"}}
    db.mutate(job["id"], lambda j: j.update(max_attempts=1))
    Engine(db, call).run(job["id"])
    assert len(calls) == 2
    assert db.get(job["id"])["status"] == "needs_human"


def test_revocation_during_verification_blocks_candidate(job_store):
    from safepatch.engine import Engine
    db, job = job_store
    record = approved_record(db, job)
    db.mutate(job["id"], lambda j: j.update(status="queued", approval=None, attempts=[]))
    def call(url, *args, **kwargs):
        if kwargs['body']['attempt'] == 0:
            return {"baseline_valid": True, "scans": [{"findings": [{"rule_id": record["context"]["rule_id"]}]}]}
        Memory(db).change(record['id'], 'revoked', 'reviewer', 'Concurrent revocation')
        return {"passed": True}
    Engine(db, call).run(job["id"])
    assert db.get(job["id"])["status"] == "rejected"
    assert db.get(job["id"])["reason"] == "memory_no_longer_approved"


def test_token_budget_stops_before_model(job_store, monkeypatch):
    from safepatch.engine import Engine
    from test_engine import fake_initial
    db, job = job_store
    monkeypatch.setenv('JOB_TOKEN_BUDGET', '1')
    calls = []
    def call(url, *args, **kwargs):
        calls.append(url)
        return fake_initial()
    Engine(db, call).run(job["id"])
    assert len(calls) == 1
    assert db.get(job["id"])["reason"] == "token_budget_exhausted"
