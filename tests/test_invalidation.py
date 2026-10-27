"""Invalidation v1 (roadmap week 5): a record falls to needs_revalidation and is not used until a person re-approves it."""
import copy
import json
import time

import pytest

from conftest import headers
from test_evidence_vector import replay
from test_memory import approved_record
from safepatch import memory as memory_module
from safepatch.memory import Memory, staleness
from safepatch.policy import PolicyError

FAILED = {"passed": False, "feedback": {"code": "validation_failed", "remaining_rules": [], "behavior": {"passed": False, "details": []}, "security": {"passed": True}}}
VERIFIED = {"passed": True, "candidate_commit": "a" * 40, "artifact_sha256": "b" * 64, "review_repository": "mock-only", "review_branch": "candidate"}


def test_a_failed_replay_needs_revalidation_and_the_record_is_not_used(job_store):
    db, job = job_store
    record = approved_record(db, job)
    after = replay(db, job, record, FAILED)
    assert after["state"] == "needs_revalidation" and after["events"][-1]["reason"] == "replay_failed:" + job["id"]
    lookup = Memory(db).search(record["context"])
    assert lookup["selected"] is None
    assert lookup["considered"] == [{"id": record["id"], "exact": None, "adaptive": None, "differences": ["state:needs_revalidation"],
                                     "use": None, "score": None, "rank": None}]


def test_a_verified_replay_or_a_failed_example_keeps_the_record(job_store):
    db, job = job_store
    record = approved_record(db, job)
    assert replay(db, job, record, VERIFIED)["state"] == "approved"
    # A failed *example* is the model's adaptation failing, not the record.
    Memory(db).use(record["id"], "e" * 32, "example")
    assert Memory(db).settle(record["id"], "e" * 32, "failed")["state"] == "approved"


def test_a_changed_rule_invalidates_only_its_own_records(job_store, monkeypatch):
    db, job = job_store
    record = approved_record(db, job)
    assert record["rule_sha256"] == memory_module.RULE_DIGESTS[record["context"]["rule_id"]]
    monkeypatch.setitem(memory_module.RULE_DIGESTS, "bigg.java.path-resolution", "0" * 64)    # another rule changed
    assert Memory(db).search(record["context"])["use"] == "replay"
    monkeypatch.setitem(memory_module.RULE_DIGESTS, record["context"]["rule_id"], "1" * 64)      # its own rule changed
    lookup = Memory(db).search(record["context"])
    assert lookup["selected"] is None and Memory(db).get(record["id"])["events"][-1]["reason"] == "rule_changed:" + record["context"]["rule_id"]


def signature(version):
    return {"schema": "safepatch-signature/1", "sink": "org.springframework.jdbc.core.JdbcTemplate.queryForList", "construction": "format",
            "source": "http_request", "library": "spring-jdbc", "library_version": version}


@pytest.mark.parametrize("saved,current,reason", [
    ("6.1.14", "6.2.0", "dependency_version_changed:spring-jdbc 6.1.14 -> 6.2.0"),
    ("6.1.14", "6.1.14", None),
    ("managed", "6.2.0", None),                  # a BOM-managed version is unknown, not different
    (None, "6.2.0", None),
])
def test_a_new_library_version_for_the_same_sink_invalidates(saved, current, reason):
    record = {"context": {"rule_id": "x", "signature": signature(saved)}}
    assert staleness(record, {"signature": signature(current)}) == reason
    other_sink = {**signature(current), "sink": "org.springframework.jdbc.core.JdbcTemplate.update"}
    assert staleness(record, {"signature": other_sink}) is None


def test_waiting_approvals_of_jobs_that_used_the_record_go_back_to_a_human(job_store):
    db, job = job_store
    record = approved_record(db, job)
    other = {**copy.deepcopy(job), "id": "d" * 32, "status": "awaiting_review", "memory_ids": [record["id"]], "review_expires_at": time.time() + 300}
    db.create(other, "other-job")
    Memory(db).change(record["id"], "needs_revalidation", "safepatch", "replay_failed:x")
    assert (db.get(other["id"])["status"], db.get(other["id"])["reason"]) == ("needs_human", "memory_no_longer_approved")


def test_transitions(job_store):
    db, job = job_store
    record = approved_record(db, job)
    memory = Memory(db)
    with pytest.raises(PolicyError, match="invalid_memory_transition"):
        memory.change(record["id"], "approved", "rev", "already approved")
    memory.change(record["id"], "needs_revalidation", "safepatch", "replay_failed:x")
    with pytest.raises(PolicyError, match="invalid_memory_transition"):
        memory.change(record["id"], "needs_revalidation", "safepatch", "twice")
    assert memory.change(record["id"], "approved", "rev", "Re-verified by hand")["affected_jobs"] == []
    assert memory.get(record["id"])["state"] == "approved" and memory.search(record["context"])["use"] == "replay"
    memory.change(record["id"], "revoked", "rev", "Wrong fix after all")
    with pytest.raises(PolicyError, match="revoked_memory_is_terminal"):
        memory.change(record["id"], "approved", "rev", "too late")


def test_reviewers_re_approve_through_the_api_but_never_their_own_record(api, tmp_path):
    client, db, job = api
    record = approved_record(db, job)
    table = Memory(db).table
    from sqlalchemy import update
    with db.engine.begin() as conn:
        conn.execute(update(table).where(table.c.id == record["id"]).values(data={**record, "author": "lead"}))
    Memory(db).change(record["id"], "needs_revalidation", "safepatch", "rule_changed:x")
    file = tmp_path / "users.json"
    users = json.loads(file.read_text())
    from safepatch.common import digest
    users.append({"subject": "lead", "roles": ["submit", "review"], "token_sha256": digest("lead-secret")})
    file.write_text(json.dumps(users))
    body = {"state": "approved", "reason": "Patch re-verified on the new rule"}
    assert client.post(f'/v1/memory/{record["id"]}/state', headers=headers("lead"), json=body).status_code == 409
    assert client.post(f'/v1/memory/{record["id"]}/state', headers=headers("developer"), json=body).status_code == 403
    response = client.post(f'/v1/memory/{record["id"]}/state', headers=headers("reviewer"), json=body)
    assert response.status_code == 200 and response.json()["state"] == "approved"
