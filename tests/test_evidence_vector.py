"""Evidence vector of a memory record: its own acceptance, and how every reuse ended (week 4)."""
import pytest

from conftest import headers
from test_memory import approved_record
from safepatch.common import SOURCE
from safepatch.engine import Engine
from safepatch.memory import Memory, evidence_vector, reuse_result

VERIFIED = {"passed": True, "build": {"passed": True, "duration_seconds": 4.1},
            "behavior": {"passed": True, "tests": 2}, "security": {"passed": True, "tests": 1},
            "scans": [{"tool": "semgrep", "status": "ok", "findings": [{"rule_id": "x", "file": "src/main/java/demo/Other.java", "fingerprint": "f1"}]}],
            "tolerated": ["f1"]}


def test_vector_states_what_the_acceptance_proved():
    job = {"approval": {"reviewer": "rev", "approved_at": 1792900000.0}}
    vector = evidence_vector(job, {"verification": VERIFIED})
    assert vector == {"build": True, "behavior": {"passed": True, "tests": 2}, "security": {"passed": True, "tests": 1},
                      "rescan": {"tools": ["semgrep"], "remaining": 0, "tolerated": 1},
                      "approval": {"reviewer": "rev", "at": 1792900000.0},
                      "reuse": {"verified": 0, "failed": 0, "inconclusive": 0, "approved_by_reviewer": 0, "rejected_by_reviewer": 0}}


def test_answer_key_findings_are_not_reported_as_a_clean_rescan():
    # Known-finding mode (VUL4J-79): after a patch nothing is rescanned, the witness decides.
    known = {**VERIFIED, "scans": [{"tool": "known-finding", "status": "ok", "findings": []}], "tolerated": []}
    assert evidence_vector({}, {"verification": known})["rescan"] == {"tools": ["known-finding"], "remaining": None, "tolerated": 0}


def test_missing_facts_are_unknown_never_failed():
    vector = evidence_vector({}, {"verification": {"passed": True}})
    assert (vector["build"], vector["behavior"], vector["security"], vector["rescan"]) == (None, None, None, None)


def test_promoted_record_carries_its_vector(job_store):
    db, job = job_store
    record = approved_record(db, job)
    assert record["evidence"]["approval"]["reviewer"] == "SIMULATED-UNIT-REVIEWER" and record["reuse"] == []


@pytest.mark.parametrize("job,result", [
    ({"status": "awaiting_review"}, "verified"), ({"status": "deployed"}, "verified"),
    ({"status": "needs_human", "reason": "attempt_budget_exhausted"}, "failed"),
    ({"status": "rejected", "reason": "protected_or_unauthorized_path"}, "failed"),
    ({"status": "needs_human", "reason": "job_deadline_exceeded"}, "inconclusive"),
    ({"status": "needs_human", "reason": "security_witness_missing"}, "inconclusive"),
    ({"status": "needs_human", "reason": "verification_infrastructure:build_without_compiler_diagnostic"}, "inconclusive"),
    ({"status": "infrastructure_error", "reason": "dependency_failure:ConnectError"}, "inconclusive"),
    ({"status": "cancelled"}, "inconclusive"),
])
def test_how_a_job_ending_counts_for_the_record(job, result):
    assert reuse_result(job) == result


def replay(db, job, record, verdict):
    db.mutate(job["id"], lambda j: j.update(status="queued", approval=None, attempts=[], max_attempts=1, candidate=None))
    def call(url, *args, **kwargs):
        assert not url.endswith("/propose"), "an exact replay never reaches the model"
        if kwargs["body"]["attempt"] == 0:
            return {"baseline_valid": True, "scans": [{"findings": [{"rule_id": record["context"]["rule_id"], "file": SOURCE}]}]}
        return verdict
    Engine(db, call).run(job["id"])
    return Memory(db).get(record["id"])


@pytest.mark.parametrize("verdict,result", [
    ({"passed": True, "candidate_commit": "a" * 40, "artifact_sha256": "b" * 64, "review_repository": "mock-only", "review_branch": "candidate"}, "verified"),
    ({"passed": False, "feedback": {"code": "validation_failed", "remaining_rules": [], "behavior": {"passed": False, "details": []}, "security": {"passed": True}}}, "failed"),
    ({"passed": False, "feedback": {"code": "compilation_failed", "diagnostics": []}}, "inconclusive"),
])
def test_each_reuse_is_recorded_with_its_use_and_result(job_store, verdict, result):
    db, job = job_store
    record = approved_record(db, job)
    after = replay(db, job, record, verdict)
    assert after["reuse"] == [{**after["reuse"][0], "job_id": job["id"], "use": "replay", "result": result, "review": None}]
    assert after["evidence"]["reuse"][result] == 1 and sum(after["evidence"]["reuse"][k] for k in ("verified", "failed", "inconclusive")) == 1


def test_reviewer_decision_on_a_reuse_joins_the_vector(api):
    client, db, job = api
    record = approved_record(db, job)
    verified = {"passed": True, "candidate_commit": "a" * 40, "artifact_sha256": "b" * 64, "review_repository": "mock-only", "review_branch": "candidate"}
    replay(db, job, record, verified)
    candidate = db.get(job["id"])["candidate"]
    decision = {"candidate_commit": candidate["commit"], "artifact_sha256": candidate["artifact_sha256"], "policy_version": candidate["policy_version"], "decision": "reject"}
    assert client.post(f'/v1/jobs/{job["id"]}/approval', headers=headers("reviewer"), json=decision).status_code == 200
    after = Memory(db).get(record["id"])
    assert after["reuse"][0]["review"] == "reject" and after["evidence"]["reuse"]["rejected_by_reviewer"] == 1
    assert after["evidence"]["reuse"]["verified"] == 1


def test_settling_an_unknown_record_or_job_is_harmless(job_store):
    db, job = job_store
    assert Memory(db).settle("0" * 32, job["id"], "failed") is None
    record = approved_record(db, job)
    assert Memory(db).settle(record["id"], "f" * 32, "failed")["reuse"] == []
