"""Failure memory: failed candidates are kept as negative evidence, never as repair examples."""
import copy
import json
import uuid

import pytest

from conftest import headers
from test_engine import fake_initial, security_failure
from test_expert_patch import run_expert
from safepatch.common import SOURCE, canonical, digest
from safepatch.engine import Engine
from safepatch.feedback import classify
from safepatch.memory import Memory

COMPILE = {"passed": False, "feedback": {"code": "compilation_failed", "diagnostics": ["[ERROR] /w/src/main/java/demo/DemoService.java:[3,1] cannot find symbol"]}}


def another_job(db, job, **fields):
    data = {**copy.deepcopy(job), "id": uuid.uuid4().hex, **fields}
    db.create(data, "key-" + data["id"])
    return data


def run(db, job, patch_factory, source, verdicts, text="// failing idea\n"):
    db.mutate(job["id"], lambda j: j.update(max_attempts=len(verdicts)))
    verdicts = iter(verdicts)
    def call(url, method="GET", **kwargs):
        body = kwargs.get("body", {})
        if url.endswith("/propose"):
            return {"mode": "mock-test", "patch": patch_factory(source[SOURCE] + text + f"// attempt {body['attempt']}\n").model_dump()}
        return fake_initial() if body.get("attempt") == 0 else next(verdicts)
    Engine(db, call).run(job["id"])
    return db.get(job["id"])


def test_patch_caused_failure_becomes_negative_evidence(job_store, patch_factory, source):
    db, job = job_store
    stored = run(db, job, patch_factory, source, [security_failure()])
    [record] = Memory(db).failure_records()
    attempt = stored["attempts"][0]
    assert attempt["failure_memory_id"] == record["id"]
    assert record["failure"]["category"] == "security_witness_failed"
    assert (record["origin"], record["strategy"], record["patch_sha256"], record["diff"]) == ("mock-test", "v01", attempt["patch_sha256"], attempt["diff"])
    assert record["context"]["source_path"] == SOURCE and record["context"]["rule_id"] == "test.rule"
    assert record["occurrences"] == [{**record["occurrences"][0], "job_id": job["id"], "attempt": 1, "evidence_sha256": digest(canonical(attempt["verification"]))}]
    # Never a repair example: approved memory stays empty and nothing is selected.
    assert Memory(db).all() == [] and Memory(db).search(stored["memory_context"])["selected"] is None


def test_the_same_failure_in_another_job_is_one_record(job_store, patch_factory, source):
    db, job = job_store
    run(db, job, patch_factory, source, [COMPILE])
    second = run(db, another_job(db, job), patch_factory, source, [COMPILE])
    [record] = Memory(db).failure_records()
    assert [o["job_id"] for o in record["occurrences"]] == [job["id"], second["id"]]
    # The second job's lookup already saw the first failure on the same source.
    assert second["memory_lookup"]["failures"] == [{"id": record["id"], "relation": "same_source", "category": "compilation_failed",
                                                     "patch_sha256": record["patch_sha256"], "origin": "mock-test", "occurrences": 1}]


@pytest.mark.parametrize("verdict", [
    {"passed": False, "feedback": {"code": "compilation_failed", "diagnostics": []}},
    {"passed": False, "feedback": {"code": "validation_failed", "remaining_rules": [], "security": {"passed": True},
                                   "behavior": {"passed": False, "infrastructure_error": True, "reason": "missing_junit_report"}}},
    {"passed": False, "feedback": {"code": "security_witness_missing", "remaining_rules": [], "behavior": {"passed": True}, "security": {"passed": False, "missing": True}}},
    {"passed": False, "feedback": {"code": "validation_failed", "remaining_rules": ["test.rule"], "behavior": {"passed": True}, "security": {"passed": False, "missing": True}}},
    {"passed": False, "feedback": {"code": "compile"}},
], ids=["no_compiler_diagnostic", "no_junit_report", "witness_missing", "witness_missing_with_finding", "unclassified"])
def test_infrastructure_and_missing_evidence_are_not_lessons(job_store, patch_factory, source, verdict):
    db, job = job_store
    stored = run(db, job, patch_factory, source, [verdict])
    assert Memory(db).failure_records() == []
    assert "failure_memory_id" not in stored["attempts"][0]


def test_evaluation_jobs_never_write_operational_memory(job_store, patch_factory, source):
    db, job = job_store
    db.mutate(job["id"], lambda j: j.update(evaluation=True))
    run(db, job, patch_factory, source, [security_failure()])
    assert Memory(db).failure_records() == []


def test_disabled_memory_has_no_failure_lookup(job_store, patch_factory, source):
    db, job = job_store
    run(db, job, patch_factory, source, [security_failure()])
    second = run(db, another_job(db, job, memory_mode="off"), patch_factory, source, [security_failure()])
    assert second["memory_lookup"]["decision"] == "disabled" and "failures" not in second["memory_lookup"]


CONTEXT = {"project": "owned-java-demo", "kind": "sql", "rule_id": "bigg.java.sql-concatenation", "jdk": "17", "source_path": SOURCE,
           "build_sha256": "b" * 64, "contract_sha256": "t" * 64, "source_sha256": "s" * 64}


def record_direct(db, context=CONTEXT, patch="c" * 64):
    attempt = {"number": 1, "proposal": {"mode": "real-local-model", "model": {"model_digest": "d" * 64}}, "patch_sha256": patch,
               "diff": "-a\n+b\n", "changed_lines": 2, "retry": {"strategy": "guided"}, "verification": security_failure(), "failure": classify(security_failure())}
    return Memory(db).record_failure({"id": uuid.uuid4().hex}, context, attempt, "guided")


@pytest.mark.parametrize("change,relation", [
    ({}, "same_source"),
    ({"source_sha256": "x" * 64}, "same_context"),
    ({"rule_id": "other.rule"}, None),
    ({"build_sha256": "x" * 64}, None),
    ({"contract_sha256": "x" * 64}, None),
    ({"project": "other-project"}, None),
    ({"kind": None}, None),
])
def test_failure_search_needs_a_compatible_context(job_store, change, relation):
    db, _ = job_store
    record_id = record_direct(db)
    found = Memory(db).failures({**CONTEXT, **change})
    assert found == ([] if relation is None else [{**found[0], "id": record_id, "relation": relation}])


def test_failure_record_keeps_the_schema_fields(job_store):
    db, _ = job_store
    record_direct(db)
    [record] = Memory(db).failure_records()
    assert record["schema"] == "safepatch-failure/1"
    assert record["context_sha256"] == digest(canonical({k: v for k, v in CONTEXT.items() if k != "source_sha256"}))
    assert record["model"] == {"model_digest": "d" * 64} and record["strategy"] == "guided" and record["memory_ids"] == []


def test_failed_expert_patch_is_recorded_with_its_author(job_store, source):
    db, job = job_store
    stored, _ = run_expert(db, job, source, [security_failure()])
    [record] = Memory(db).failure_records()
    assert (record["origin"], record["author"], record["strategy"], record["model"]) == ("human-authored", "developer", "expert", None)
    assert stored["attempts"][-1]["failure_memory_id"] == record["id"]


def test_failure_listing_is_project_scoped(api, tmp_path):
    client, db, _ = api
    record_direct(db)
    file = tmp_path / "users.json"
    users = json.loads(file.read_text())
    users.append({"subject": "outsider", "roles": ["submit", "review"], "projects": ["other-project"], "token_sha256": digest("outsider-secret")})
    file.write_text(json.dumps(users))
    assert len(client.get("/v1/memory/failures", headers=headers("developer")).json()) == 1
    assert client.get("/v1/memory/failures", headers=headers("outsider")).json() == []
    assert client.get("/v1/memory/failures").status_code == 401
