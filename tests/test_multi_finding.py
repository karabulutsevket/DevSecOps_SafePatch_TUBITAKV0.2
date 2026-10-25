"""One job per file: a scan with findings in several files becomes several jobs (week 4)."""
import pytest

from safepatch import orchestrator
from safepatch.common import SOURCE, Patch, VerifyRequest, digest
from safepatch.engine import Engine, finding_groups, primary_finding, tolerated
from safepatch.acceptance import untolerated

OTHER = "src/main/java/demo/EchoMain.java"
SQL = "bigg.java.sql-concatenation"


def finding(file, line, rule=SQL):
    return {"tool": "builtin-demo", "rule_id": rule, "cwe": "CWE-89", "file": file, "line": line, "fingerprint": digest(rule + file)}


def scan():
    return {"baseline_valid": True, "scans": [{"findings": [finding(OTHER, 3), finding(SOURCE, 16), finding(SOURCE, 9, "bigg.java.other")]}]}


def run(db, job_id, source, patch_path):
    """Run one job with mocked workers; returns the worker2 and worker1 request bodies."""
    verified, proposed = [], []
    def call(url, method="GET", **kwargs):
        body = kwargs["body"]
        if url.endswith("/propose"):
            proposed.append(body)
            edit = {"path": patch_path, "old_sha256": digest(source[patch_path]), "content": source[patch_path] + f"// try {body['attempt']}\n"}
            return {"mode": "mock-test", "patch": Patch.model_validate({"edits": [edit], "rationale": "MOCK"}).model_dump()}
        verified.append(VerifyRequest.model_validate(body))
        return scan() if body["attempt"] == 0 else {"passed": False, "feedback": {"code": "compile"}}
    Engine(db, call).run(job_id)
    return verified, proposed


def test_groups_are_per_file_with_findings_in_line_order():
    groups = finding_groups(scan())
    assert [(path, [f["line"] for f in found]) for path, found in groups] == [(SOURCE, [9, 16]), (OTHER, [3])]


def test_first_file_stays_and_each_further_file_becomes_a_queued_job(job_store, source):
    db, job = job_store
    db.mutate(job["id"], lambda j: j.update(max_attempts=1, strategy="guided"))
    verified, proposed = run(db, job["id"], source, SOURCE)
    parent = db.get(job["id"])
    assert parent["target_file"] == SOURCE and [f["line"] for f in parent["findings"]] == [9, 16]
    assert primary_finding(parent)["rule_id"] == "bigg.java.other"
    [child_id] = parent["children"]
    child = db.get(child_id)
    assert (child["status"], child["parent_job"], child["target_file"], child["baseline"]) == ("queued", job["id"], OTHER, scan())
    assert {k: child[k] for k in ("case_id", "base_commit", "owner", "scanner", "mode", "strategy", "max_attempts")} == \
           {k: parent[k] for k in ("case_id", "base_commit", "owner", "scanner", "mode", "strategy", "max_attempts")}
    assert child["attempts"] == [] and child["approval"] is None
    # The parent patches its own file; the other file's baseline finding may remain.
    assert [list(p["source"]) for p in proposed] == [[SOURCE]]
    assert [(v.attempt, v.target_file, v.tolerated) for v in verified] == [(0, None, []), (1, SOURCE, [digest(SQL + OTHER)])]


def test_a_split_job_for_a_file_the_descriptor_protects_goes_to_a_human(job_store, source):
    db, job = job_store
    db.mutate(job["id"], lambda j: j.update(max_attempts=1))
    run(db, job["id"], source, SOURCE)
    child_id = db.get(job["id"])["children"][0]
    verified, proposed = run(db, child_id, source, OTHER)     # sql-01 makes only DemoService.java editable
    child = db.get(child_id)
    assert (child["status"], child["reason"], verified, proposed) == ("needs_human", "finding_file_not_editable", [], [])


def test_a_split_job_reuses_the_scan_and_tolerates_the_other_file(job_store, source, monkeypatch):
    from safepatch import engine
    monkeypatch.setattr(engine, "allowed_files", lambda spec, files, target: {target})
    db, job = job_store
    db.mutate(job["id"], lambda j: j.update(max_attempts=1))
    run(db, job["id"], source, SOURCE)
    child_id = db.get(job["id"])["children"][0]
    verified, proposed = run(db, child_id, source, OTHER)
    assert [(v.attempt, v.target_file) for v in verified] == [(1, OTHER)]    # no second scan
    assert verified[0].tolerated == sorted({digest(SQL + SOURCE), digest("bigg.java.other" + SOURCE)})
    assert [list(p["source"]) for p in proposed] == [[OTHER]] and proposed[0]["finding"]["file"] == OTHER
    assert "children" not in db.get(child_id)


def test_a_single_finding_job_is_unchanged(job_store, source):
    db, job = job_store
    db.mutate(job["id"], lambda j: j.update(max_attempts=1))
    one = {"baseline_valid": True, "scans": [{"findings": [finding(SOURCE, 16)]}]}
    seen = []
    def call(url, method="GET", **kwargs):
        body = kwargs["body"]
        if url.endswith("/propose"):
            return {"mode": "mock-test", "patch": Patch.model_validate({"edits": [{"path": SOURCE, "old_sha256": digest(source[SOURCE]), "content": source[SOURCE] + "// x\n"}], "rationale": "MOCK"}).model_dump()}
        seen.append(body)
        return one if body["attempt"] == 0 else {"passed": False, "feedback": {"code": "compile"}}
    Engine(db, call).run(job["id"])
    assert db.get(job["id"])["children"] == [] and seen[1]["tolerated"] == []


def test_split_jobs_enter_the_queue_after_their_parent(job_store, source, monkeypatch):
    db, job = job_store
    db.mutate(job["id"], lambda j: j.update(max_attempts=1))
    run(db, job["id"], source, SOURCE)
    monkeypatch.setattr(orchestrator, "store", db)
    while not orchestrator.work.empty():
        orchestrator.work.get_nowait()
    orchestrator.enqueue_children(job["id"])
    assert orchestrator.work.get_nowait() == db.get(job["id"])["children"][0]
    db.mutate(db.get(job["id"])["children"][0], lambda j: j.update(status="cancelled"))
    orchestrator.enqueue_children(job["id"])
    assert orchestrator.work.empty()


def test_only_baseline_findings_of_other_files_are_tolerated():
    findings = [finding(SOURCE, 16), finding(OTHER, 3), finding("src/main/java/demo/New.java", 1)]
    assert tolerated(scan(), SOURCE) == [digest(SQL + OTHER)]
    assert [f["file"] for f in untolerated(findings, tolerated(scan(), SOURCE))] == [SOURCE, "src/main/java/demo/New.java"]


@pytest.mark.parametrize("value", [["a b"], ["x" * 201], [""]])
def test_tolerated_fingerprints_are_validated(value):
    with pytest.raises(ValueError):
        VerifyRequest(job_id="a" * 32, case_id="sql-01", base_commit="b" * 40, attempt=1, deadline=1.0, tolerated=value)
