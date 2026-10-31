"""The institution's own scanner findings, imported as SARIF (docs/SARIF_ICERI_ALMA.md). An import
becomes a job whose acceptance rests on the security witness, with SafePatch's own scanner run
beside it (options b and a, the project lead's decision of 31 Oct 2026)."""
import json
import uuid

import pytest
from pydantic import ValidationError

from conftest import headers
from mock_patches import correct_patch
from safepatch import orchestrator, runner
from safepatch.audit import AuditLog
from safepatch.common import SOURCE, ImportedFinding, VerifyRequest, digest
from safepatch.engine import Engine
from safepatch.memory import evidence_vector
from safepatch.policy import PolicyError
from safepatch.repository import baseline, projects, registry
from safepatch.sarif import read_sarif

SEMGREP = open("tests/fixtures/sarif/semgrep-sql-01.sarif", encoding="utf-8").read()
OTHER = "src/main/java/demo/EchoMain.java"
SUCCESS = {"passed": True, "candidate_commit": "a" * 40, "artifact_sha256": "b" * 64, "review_repository": "mock-only", "review_branch": "candidate"}


@pytest.fixture(autouse=True)
def empty_queue():
    def drain():
        while not orchestrator.work.empty():
            orchestrator.work.get_nowait()
    drain()
    yield
    drain()


def imported_findings():
    case = registry()[1]["sql-01"]
    return read_sarif(SEMGREP.encode(), case["commit"], baseline("sql-01", case["commit"])[1], [SOURCE])[0]["findings"]


def send(client, sarif=SEMGREP, role="developer", **fields):
    body = {"case_id": "sql-01", "idempotency_key": "import-" + uuid.uuid4().hex, "sarif": sarif, **fields}
    return client.post("/v1/finding-imports", headers=headers(role), json=body)


def changed(**run):
    data = json.loads(SEMGREP)
    data["runs"][0].update(run)
    return json.dumps(data)


# API: import, preview, refusals.

def test_an_import_queues_a_job_whose_findings_come_from_the_file(api):
    client, db, _ = api
    response = send(client)
    assert response.status_code == 201, response.text
    job = db.get(response.json()["id"])
    assert (job["scanner"], job["mode"], job["status"], job["owner"], job["max_attempts"]) == ("sarif+semgrep", "real-local-model", "queued", "developer", 3)
    assert job["base_commit"] == registry()[1]["sql-01"]["commit"] and job["import_sha256"] == digest(SEMGREP)
    imported = job["imported"]
    assert imported["findings"] == imported_findings() and imported["imported_by"] == "developer"
    assert imported["producers"] == [{"name": "Semgrep OSS", "version": "1.136.0"}] and imported["sarif_sha256"] == digest(SEMGREP)
    assert orchestrator.work.get_nowait() == job["id"]
    entry = AuditLog(db).entries(job["id"])[-1]
    assert (entry["actor"], entry["action"], entry["data"]["scanner"]) == ("developer", "job.created", "sarif+semgrep")
    assert (entry["data"]["sarif_sha256"], entry["data"]["findings"], entry["data"]["files"]) == (digest(SEMGREP), 1, 1)


def test_the_own_scanner_beside_the_import_is_chosen_among_safepatchs_own(api):
    client, db, _ = api
    response = send(client, scanner="semgrep+findsecbugs")
    assert response.status_code == 201 and db.get(response.json()["id"])["scanner"] == "sarif+semgrep+findsecbugs"


@pytest.mark.parametrize("role,status", [("reviewer", 403), ("deployer", 403), ("nobody", 401)])
def test_only_submitters_import(api, role, status):
    client, db, _ = api
    before = len(db.all())
    assert send(client, role=role).status_code == status
    assert len(db.all()) == before and orchestrator.work.empty()


@pytest.mark.parametrize("fields", [{"scanner": "known"}, {"scanner": "sarif+semgrep"}, {"scanner": "sonarqube+semgrep"},
                                    {"imported_by": "reviewer"}, {"sarif": ""}, {"imported": []}])
def test_malformed_requests_are_refused(api, fields):
    client, db, _ = api
    before = len(db.all())
    assert send(client, **fields).status_code == 422
    assert len(db.all()) == before


def test_a_repeated_import_returns_the_same_job_and_another_file_conflicts(api):
    client, _, _ = api
    key = "import-" + uuid.uuid4().hex
    first, again = send(client, idempotency_key=key), send(client, idempotency_key=key)
    assert first.status_code == again.status_code == 201 and again.json()["id"] == first.json()["id"]
    assert orchestrator.work.qsize() == 1
    other = send(client, changed(invocations=[{"executionSuccessful": True, "toolExecutionNotifications": [{"message": {"text": "x"}}]}]), idempotency_key=key)
    assert other.status_code == 409 and other.json()["detail"] == "idempotency_payload_conflict"


CRYPTO = {"id": "java/weak-cryptographic-algorithm", "properties": {"tags": ["external/cwe/cwe-327"]}}


@pytest.mark.parametrize("sarif,code", [
    (SEMGREP.replace('"version":"2.1.0"', '"version":"2.0.0"'), "sarif_version_unsupported"),
    (changed(versionControlProvenance=[{"revisionId": "f" * 40}]), "sarif_commit_mismatch"),
    (changed(tool={"driver": {"name": "CodeQL", "rules": [CRYPTO]}},
             results=[{"ruleId": CRYPTO["id"], "message": {"text": "m"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": SOURCE}}}]}]),
     "sarif_no_supported_findings"),
    (SEMGREP.replace('"uri":"src/main/java/demo/DemoService.java"', '"uri":"../sql-02/src/main/java/demo/DemoService.java"'), "sarif_path_outside_repository"),
])
def test_a_refused_import_stores_nothing_and_is_audited(api, sarif, code):
    client, db, _ = api
    assert sarif != SEMGREP
    before = len(db.all())
    response = send(client, sarif)
    assert response.status_code == 409 and response.json()["detail"] == code
    assert len(db.all()) == before and orchestrator.work.empty()
    entry = AuditLog(db).entries("sql-01")[-1]
    assert (entry["actor"], entry["action"], entry["data"]["reason"], entry["data"]["sarif_sha256"]) == ("developer", "finding_import.refused", code, digest(sarif))


def without_witness(monkeypatch):
    specs = projects()
    spec = specs["sql-01"]
    specs["sql-01"] = spec.model_copy(update={"tests": spec.tests.model_copy(update={"security": None})})
    monkeypatch.setattr(orchestrator, "projects", lambda: specs)
    return specs["sql-01"]


def test_a_project_without_a_security_witness_takes_no_import(api, monkeypatch):
    # The witness decides acceptance (option b): without one no candidate could ever be accepted.
    client, db, _ = api
    without_witness(monkeypatch)
    for path in ("/v1/finding-imports/preview", "/v1/finding-imports"):
        response = client.post(path, headers=headers("developer"), json={"case_id": "sql-01", "idempotency_key": "import-" + uuid.uuid4().hex, "sarif": SEMGREP}
                               if path.endswith("imports") else {"case_id": "sql-01", "sarif": SEMGREP})
        assert response.status_code == 409 and response.json()["detail"] == "imported_findings_need_security_witness"
    assert orchestrator.work.empty()


def test_preview_summarises_the_import_and_stores_nothing(api):
    client, db, _ = api
    before = db.all()
    response = client.post("/v1/finding-imports/preview", headers=headers("developer"), json={"case_id": "sql-01", "sarif": SEMGREP})
    assert response.status_code == 200
    summary = response.json()
    assert summary["files"] == [{"file": SOURCE, "findings": 1, "cwes": ["CWE-89"], "rules": ["rules.bigg.java.sql-concatenation"]}]
    assert (summary["findings"], summary["sarif_sha256"], summary["commit_declared"]) == (1, digest(SEMGREP), False)
    assert summary["other_findings"] == {"count": 0, "reasons": {}, "cwes": {}} and set(summary["skipped"].values()) == {0}
    refused = client.post("/v1/finding-imports/preview", headers=headers("developer"), json={"case_id": "sql-01", "sarif": "{"})
    assert refused.status_code == 409 and refused.json()["detail"] == "sarif_invalid_json"
    assert client.post("/v1/finding-imports/preview", headers=headers("reviewer"), json={"case_id": "sql-01", "sarif": SEMGREP}).status_code == 403
    assert client.post("/v1/finding-imports/preview", headers=headers("developer"), json={"case_id": "no-such-case", "sarif": SEMGREP}).status_code == 404
    assert db.all() == before and orchestrator.work.empty() and AuditLog(db).entries("sql-01") == []


# The engine: the imported findings go with the baseline scan only.

def run(db, job_id, source, verdicts):
    sent, verdicts = [], iter(verdicts)
    def call(url, method="GET", **kwargs):
        if url.endswith("/propose"):
            return {"mode": "real-local-model", "patch": correct_patch("sql", source).model_dump()}
        sent.append(VerifyRequest.model_validate(kwargs["body"]))
        return next(verdicts)
    Engine(db, call).run(job_id)
    return db.get(job_id), sent


def sarif_report(*findings):
    return {"tool": "sarif", "status": "ok", "findings": list(findings)}


def imported_job(api):
    client, _, _ = api
    response = send(client)
    assert response.status_code == 201, response.text
    orchestrator.work.get_nowait()
    return response.json()["id"]


def test_the_baseline_carries_the_imported_findings_and_a_patched_attempt_does_not(api, source):
    _, db, _ = api
    job_id = imported_job(api)
    finding = imported_findings()[0]
    initial = {"baseline_valid": True, "scans": [sarif_report(finding), {"tool": "semgrep", "status": "ok", "findings": []}]}
    stored, sent = run(db, job_id, source, [initial, SUCCESS])
    assert [(r.attempt, r.scanner, [f.model_dump() for f in r.imported], r.patch is None) for r in sent] == [
        (0, "sarif+semgrep", [finding], True), (1, "sarif+semgrep", [], False)]
    assert stored["status"] == "awaiting_review" and stored["target_file"] == SOURCE and stored["findings"] == [finding]


def test_each_further_file_of_the_import_becomes_its_own_job(api, source):
    _, db, _ = api
    job_id = imported_job(api)
    finding = imported_findings()[0]
    other = {**finding, "file": OTHER, "fingerprint": digest("other")}
    stored, sent = run(db, job_id, source, [{"baseline_valid": True, "scans": [sarif_report(finding, other)]}, SUCCESS])
    child = db.get(stored["children"][0])
    assert (child["scanner"], child["target_file"], child["parent_job"], "imported" in child) == ("sarif+semgrep", OTHER, job_id, False)
    assert sent[1].tolerated == [other["fingerprint"]]


# The runner: imported findings at the baseline only, SafePatch's own scanner beside them.

def lab():
    case, files = baseline("sql-01", registry()[1]["sql-01"]["commit"])
    return case["spec"], files, [ImportedFinding.model_validate(f) for f in imported_findings()]


def test_the_runner_reports_imported_findings_at_the_baseline_only():
    spec, files, imported = lab()
    report = runner.imported_findings(spec, files, "c" * 40, imported, patched=False)
    assert (report["tool"], report["status"], report["findings"]) == ("sarif", "ok", [f.model_dump() for f in imported])
    assert runner.imported_findings(spec, files, "c" * 40, imported, patched=True)["findings"] == []


def test_the_runner_refuses_imported_findings_without_a_witness_or_outside_the_files():
    spec, files, imported = lab()
    no_witness = spec.model_copy(update={"tests": spec.tests.model_copy(update={"security": None})})
    with pytest.raises(PolicyError, match="^imported_findings_need_security_witness$"):
        runner.imported_findings(no_witness, files, "c" * 40, imported, patched=False)
    elsewhere = [imported[0].model_copy(update={"file": "src/main/java/demo/Missing.java"})]
    with pytest.raises(PolicyError, match="^imported_finding_unknown_file$"):
        runner.imported_findings(spec, files, "c" * 40, elsewhere, patched=False)


def test_safepatchs_own_scanner_runs_beside_the_imported_findings(source):
    # Option a: the own scanner (here the lab's narrow builtin one) also sees the weakness, so after
    # the patch its rescan must be clean; the imported findings are not rescanned (option b).
    spec, files, imported = lab()
    before = runner.scan(None, spec, files, "c" * 40, "sarif+builtin", "a" * 32, 0, 0, imported=imported)
    assert [(r["tool"], len(r["findings"])) for r in before] == [("sarif", 1), ("builtin-demo", 1)]
    fixed = {**files, SOURCE: correct_patch("sql", source).edits[0].content}
    after = runner.scan(None, spec, fixed, "c" * 40, "sarif+builtin", "a" * 32, 1, 0, patched=True, imported=imported)
    assert [(r["tool"], len(r["findings"])) for r in after] == [("sarif", 0), ("builtin-demo", 0)]


def test_imported_findings_need_a_sarif_scanner_and_well_formed_fields():
    finding = imported_findings()[0]
    request = {"job_id": "a" * 32, "case_id": "sql-01", "base_commit": "c" * 40, "attempt": 0, "deadline": 0.0}
    assert VerifyRequest.model_validate({**request, "scanner": "sarif+semgrep", "imported": [finding]}).imported[0].file == SOURCE
    for change in ({"scanner": "semgrep"}, {"scanner": "sarif"}, {"scanner": "sarif+known"}):
        with pytest.raises(ValidationError):
            VerifyRequest.model_validate({**request, "scanner": "sarif+semgrep", "imported": [finding], **change})
    for bad in ({"file": "../x.java"}, {"cwe": None}, {"severity": "critical"}, {"fingerprint": "x"}, {"note": "extra"}):
        with pytest.raises(ValidationError):
            ImportedFinding.model_validate({**finding, **bad})


# Evidence: the institution's tool is named as not rescanned.

def test_the_imported_tool_is_named_as_not_rescanned_beside_the_own_rescan():
    verified = {"passed": True, "tolerated": [], "scans": [{"tool": "sarif", "status": "ok", "findings": []}, {"tool": "semgrep", "status": "ok", "findings": []}]}
    assert evidence_vector({}, {"verification": verified})["rescan"] == {"tools": ["sarif", "semgrep"], "remaining": 0, "tolerated": 0, "not_rescanned": ["sarif"]}
