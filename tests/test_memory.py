import copy
import time

import pytest

from conftest import headers
from test_approval import ready
from safepatch.acceptance import check_evidence
from safepatch.common import SOURCE, canonical, digest
from safepatch.memory import Memory, adaptability, applicability, context_for
from safepatch.policy import PolicyError, validate_patch
from safepatch.repository import baseline, registry
from mock_patches import correct_patch


def approved_record(db, job, actor="SIMULATED-UNIT-REVIEWER"):
    case, files = baseline(job["case_id"], job["base_commit"])
    patch = correct_patch(case["kind"], files)
    meta = validate_patch(files, patch, allowed={SOURCE})
    ready(db, job)
    j = db.get(job["id"])
    j["candidate"].update(patch_sha256=meta["patch_sha256"], diff=meta["diff"])
    j["acceptance_manifest"]["patch_sha256"] = meta["patch_sha256"]
    j["candidate"]["evidence_sha256"] = digest(canonical(j["acceptance_manifest"]))
    j.update(status="approved", attempts=[{"proposal": {"mode": "mock-test", "patch": patch.model_dump()}, "patch_sha256": meta["patch_sha256"], "verification": {"passed": True}}])
    j["approval"] = {"decision": "approve", "candidate_commit": j["candidate"]["commit"], "artifact_sha256": j["candidate"]["artifact_sha256"], "policy_version": j["candidate"]["policy_version"], "expires_at": time.time()+300, "reviewer": actor}
    j["baseline"] = {"scans": [{"findings": [{"rule_id": "bigg.java.sql-concatenation", "file": SOURCE}]}]}
    db.mutate(j["id"], lambda x: x.update(j))
    context = context_for(case, files, j["baseline"]["scans"][0]["findings"][0])
    return Memory(db).promote(j, context, files[SOURCE], actor, "Simulated unit fixture approval")


@pytest.mark.parametrize("field", ["project", "cwe_family", "jdk"])
def test_other_project_weakness_or_runtime_is_never_used(job_store, field):
    db, job = job_store
    record = approved_record(db, job)
    changed = {**record["context"], field: "different"}
    assert applicability(record["context"], changed) == "incompatible"
    assert Memory(db).search(changed)["selected"] is None


@pytest.mark.parametrize("field", ["source_path", "build_sha256", "contract_sha256"])
def test_other_file_or_contract_is_an_example_never_a_replay(job_store, field):
    # The hashes decide only exact replay; adaptive use follows the structural signature.
    db, job = job_store
    record = approved_record(db, job)
    changed = {**record["context"], field: "different"}
    assert (applicability(record["context"], changed), adaptability(record["context"], changed)) == ("incompatible", "compatible")
    lookup = Memory(db).search(changed)
    assert lookup["use"] == "example" and lookup["selected"]["id"] == record["id"]


def test_other_signature_shape_is_never_used(job_store):
    db, job = job_store
    record = approved_record(db, job)
    assert record["context"]["signature"]["sink"] == "java.sql.Statement.executeQuery"
    changed = {**record["context"], "source_sha256": "x" * 64, "signature": {**record["context"]["signature"], "construction": "format"}}
    lookup = Memory(db).search(changed)
    assert lookup["selected"] is None and lookup["rejected"] == [{"id": record["id"], "exact": "compatible", "adaptive": "incompatible",
                                                                  "differences": ["source_sha256", "signature.construction"]}]


def test_a_record_for_another_sink_in_the_same_file_is_never_replayed(job_store):
    # Identical file and hashes, but the record fixed a different sink: no replay, no example.
    db, job = job_store
    record = approved_record(db, job)
    other_sink = {**record["context"], "signature": {**record["context"]["signature"], "sink": "java.sql.Statement.execute"}}
    lookup = Memory(db).search(other_sink)
    assert lookup["selected"] is None and lookup["rejected"][0]["exact"] == "compatible"
    # Unknown on one side keeps the exact replay: the code is byte for byte the same.
    assert Memory(db).search({**record["context"], "signature": None})["use"] == "replay"


def test_differences_name_each_fact_that_differs_or_is_unknown(job_store):
    from safepatch.memory import differences
    db, job = job_store
    record = approved_record(db, job)
    assert differences(record["context"], record["context"]) == []
    changed = {**record["context"], "build_sha256": "x", "jdk": None, "signature": {**record["context"]["signature"], "sink": "java.sql.Statement.execute"}}
    assert differences(record["context"], changed) == ["jdk:unknown", "build_sha256", "signature.sink"]
    assert differences(record["context"], {**record["context"], "signature": None})[-1] == "signature:unknown"
    assert Memory(db).search(changed)["considered"][0]["differences"] == ["jdk:unknown", "build_sha256", "signature.sink"]


def test_replay_is_preferred_to_a_newer_example(job_store):
    db, job = job_store
    record = approved_record(db, job)
    newer = copy.deepcopy(record)
    newer.update(id="e" * 32, created_at=record["created_at"] + 60, context={**record["context"], "source_path": "src/main/java/demo/Other.java"})
    with db.engine.begin() as conn:
        conn.execute(Memory(db).table.insert().values(id=newer["id"], created=time.time(), data=newer))
    lookup = Memory(db).search(record["context"])
    assert lookup["use"] == "replay" and lookup["selected"]["id"] == record["id"]
    assert {c["id"]: c["use"] for c in lookup["considered"]} == {record["id"]: "replay", newer["id"]: "example"}


def test_naive_arm_ignores_preconditions_and_never_replays(job_store):
    db, job = job_store
    record = approved_record(db, job)
    changed = {**record["context"], "jdk": "21", "signature": None}
    lookup = Memory(db).search(changed, "naive")
    assert lookup["use"] == "example" and lookup["selected"]["id"] == record["id"]
    assert Memory(db).search(record["context"], "naive")["use"] == "example"


def test_same_weakness_from_another_scanner_uses_the_record(job_store):
    db, job = job_store
    record = approved_record(db, job)
    assert record["context"]["cwe_family"] == "CWE-89"
    for rule in ("javasecurity:S3649", "SQL_INJECTION_JDBC"):
        other = {**record["context"], "rule_id": rule}
        assert applicability(record["context"], other) == "compatible"
        assert Memory(db).search(other)["selected"]["id"] == record["id"]


def test_records_from_before_week_4_get_their_family_from_the_rule():
    old = {"project": "p", "kind": "sql", "rule_id": "bigg.java.sql-concatenation", "jdk": "17", "source_path": SOURCE,
           "build_sha256": "b", "contract_sha256": "c", "source_sha256": "s"}
    new = {**{k: v for k, v in old.items() if k != "kind"}, "cwe_family": "CWE-89", "rule_id": "SQL_INJECTION_JDBC"}
    assert applicability(old, new) == "compatible"
    assert applicability({**old, "rule_id": "legacy.unmapped.rule"}, new) == "unknown"


@pytest.mark.parametrize("field,use", [("cwe_family", None), ("jdk", "example_unknown"), ("signature", "example_unknown"),
                                       ("build_sha256", "example"), ("contract_sha256", "example")])
def test_unknown_precondition_is_at_most_an_example(job_store, field, use):
    # Roadmap week 4: only `compatible` is used automatically; `unknown` may at most be a model example.
    # Different source code throughout: identical code would be an exact replay whatever the signature says.
    db, job = job_store
    record = approved_record(db, job)
    changed = {**record["context"], "source_sha256": "x" * 64, field: None}
    lookup = Memory(db).search(changed)
    assert lookup["use"] == use and (lookup["selected"] is None) == (use is None)


def test_an_example_reaches_the_model_and_is_still_verified(job_store):
    from safepatch.engine import Engine
    db, job = job_store
    record = approved_record(db, job)
    # Same weakness shape in another build: an example for the model, not a replay.
    from sqlalchemy import update
    table = Memory(db).table
    with db.engine.begin() as conn:
        changed = {**record, "context": {**record["context"], "build_sha256": "x" * 64}}
        conn.execute(update(table).where(table.c.id == record["id"]).values(data=changed))
    db.mutate(job["id"], lambda j: j.update(status="queued", approval=None, attempts=[], max_attempts=1))
    proposals = []
    def call(url, *args, **kwargs):
        body = kwargs["body"]
        if url.endswith("/propose"):
            proposals.append(body)
            return {"mode": "mock-test", "patch": record["patch"]}
        if body["attempt"] == 0:
            return {"baseline_valid": True, "scans": [{"findings": [{"rule_id": "bigg.java.sql-concatenation", "file": SOURCE, "line": 16}]}]}
        return {"passed": False, "feedback": {"code": "security_regression"}}
    Engine(db, call).run(job["id"])
    stored = db.get(job["id"])
    assert stored["memory_lookup"]["use"] == "example" and stored["memory_ids"] == [record["id"]]
    assert len(proposals) == 1 and proposals[0]["memory_data"]["patch_diff"] == record["diff"]
    assert stored["attempts"][0]["proposal"]["mode"] == "mock-test"


def test_exact_match_and_disable(job_store):
    db, job = job_store
    record = approved_record(db, job)
    lookup = Memory(db).search(record["context"])
    assert lookup["selected"]["id"] == record["id"] and lookup["use"] == "replay"
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
            return {"baseline_valid": True, "scans": [{"findings": [{"rule_id": record["context"]["rule_id"], "file": record["context"]["source_path"]}]}]}
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
            return {"baseline_valid": True, "scans": [{"findings": [{"rule_id": record["context"]["rule_id"], "file": record["context"]["source_path"]}]}]}
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
