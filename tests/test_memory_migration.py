"""Records written before week 4 are brought to the current schema; what cannot be completed stays unknown."""
import copy
import time

from mock_patches import correct_patch
from safepatch.common import SOURCE, canonical, digest
from safepatch.memory import REQUIRED, Memory, adaptability, context_for
from safepatch.policy import validate_patch
from safepatch.repository import baseline

V01_RULE = "bigg.java.sql-concatenation"


def v01_record(db, job, **change):
    """A record exactly as V0.1 wrote it: kind and rule id, no family, signature, evidence or reuse list."""
    case, files = baseline(job["case_id"], job["base_commit"])
    patch = correct_patch("sql", files)
    meta = validate_patch(files, patch, allowed={SOURCE})
    context = {"project": "owned-java-demo", "kind": "sql", "rule_id": V01_RULE, "jdk": "17", "source_path": SOURCE,
               "build_sha256": digest(files.raw("pom.xml")),
               "contract_sha256": digest(canonical({p: digest(files.raw(p)) for p in files if p.startswith("src/test/")})),
               "source_sha256": digest(files[SOURCE])}
    record = {"id": change.pop("id", "a" * 32), "state": "approved", "version": 1, "created_at": time.time(), "context": context,
              "before": files[SOURCE], "patch": patch.model_dump(), "diff": meta["diff"], "source_job": job["id"], "model": None,
              "provenance": "human-approved-local-repair", "evidence_sha256": "e" * 64,
              "approval": {"reviewer": "v01-reviewer", "approved_at": 1790000000.0}, "uses": ["1" * 32],
              "events": [{"state": "approved", "actor": "v01-reviewer", "reason": "V0.1", "at": 1790000000.0}]}
    record.update(change)
    memory = Memory(db)
    with db.engine.begin() as conn:
        conn.execute(memory.table.insert().values(id=record["id"], created=time.time(), data=record))
    return record, patch


def verified_source_job(db, job, patch):
    verification = {"passed": True, "build": {"passed": True}, "behavior": {"passed": True, "tests": 2}, "security": {"passed": True, "tests": 1},
                    "scans": [{"tool": "semgrep", "status": "ok", "findings": []}]}
    db.mutate(job["id"], lambda j: j.update(attempts=[{"number": 1, "proposal": {"mode": "real-local-model", "patch": patch.model_dump()}, "verification": verification}]))


def test_a_v01_record_gets_family_signature_and_evidence(job_store):
    db, job = job_store
    old, patch = v01_record(db, job)
    verified_source_job(db, job, patch)
    report = Memory(db).migrate()
    record = Memory(db).get(old["id"])
    assert report["memory"]["migrated"] == [old["id"]] and report["memory"]["unknown_family"] == report["memory"]["no_signature"] == report["memory"]["no_evidence"] == []
    assert record["context"]["cwe_family"] == "CWE-89"
    assert record["context"]["signature"]["sink"] == "java.sql.Statement.executeQuery" and record["context"]["signature"]["construction"] == "concatenation"
    assert record["evidence"]["behavior"] == {"passed": True, "tests": 2} and record["evidence"]["approval"] == {"reviewer": "v01-reviewer", "at": 1790000000.0}
    assert record["reuse"] == [{"job_id": "1" * 32, "use": None, "result": "unrecorded", "review": None, "at": None}]
    assert record["version"] == 2 and record["events"][-1]["previous_context"] == old["context"] and record["events"][-1]["state"] == "approved"
    # The migrated record now matches a fresh week-4 context of the same code.
    case, files = baseline(job["case_id"], job["base_commit"])
    fresh = context_for(case, files, {"rule_id": "javasecurity:S3649", "file": SOURCE, "line": 16})
    assert adaptability(record["context"], fresh) == "compatible"
    assert Memory(db).search(fresh)["use"] == "replay"


def test_dry_run_writes_nothing_and_a_second_run_changes_nothing(job_store):
    db, job = job_store
    old, _ = v01_record(db, job)
    assert Memory(db).migrate(dry_run=True)["memory"]["migrated"] == [old["id"]]
    assert Memory(db).get(old["id"]) == old
    Memory(db).migrate()
    once = Memory(db).get(old["id"])
    assert Memory(db).migrate()["memory"]["migrated"] == [] and Memory(db).get(old["id"]) == once


def test_what_cannot_be_completed_stays_unknown(job_store):
    db, job = job_store
    old, _ = v01_record(db, job, id="b" * 32, before=None, source_job="9" * 32, state="revoked",
                        context={"project": "owned-java-demo", "kind": "x", "rule_id": "vendor.unmapped.rule", "jdk": "17", "source_path": SOURCE,
                                 "build_sha256": "b", "contract_sha256": "c", "source_sha256": "s"})
    report = Memory(db).migrate()
    record = Memory(db).get(old["id"])
    assert report["memory"]["unknown_family"] == report["memory"]["no_signature"] == report["memory"]["no_evidence"] == [old["id"]]
    assert (record["context"]["cwe_family"], record["context"]["signature"], record["evidence"], record["state"]) == (None, None, None, "revoked")


def test_failure_records_get_their_family_and_a_new_signature_hash(job_store):
    db, _ = job_store
    memory = Memory(db)
    old_context = {"project": "owned-java-demo", "kind": "sql", "rule_id": V01_RULE, "jdk": "17", "source_path": SOURCE,
                   "build_sha256": "b", "contract_sha256": "c", "source_sha256": "s"}
    old = {"id": "c" * 32, "schema": "safepatch-failure/1", "context": old_context, "context_sha256": "old", "patch_sha256": "p" * 64,
           "failure": {"category": "compilation_failed"}, "occurrences": [], "origin": "real-local-model"}
    with db.engine.begin() as conn:
        conn.execute(memory.failure_table.insert().values(id=old["id"], created=time.time(), data=old))
    report = memory.migrate()
    [record] = memory.failure_records()
    assert report["failures"]["migrated"] == [old["id"]] and report["failures"]["unknown_family"] == []
    assert (record["context"]["cwe_family"], record["context"]["signature"]) == ("CWE-89", None)
    assert record["context_sha256"] == digest(canonical({k: record["context"].get(k) for k in REQUIRED}))
    assert record["migration"]["previous_context"] == old_context
