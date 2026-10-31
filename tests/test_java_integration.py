import json
import base64
import os
from pathlib import Path
import time
import uuid

import pytest

from safepatch.common import ROOT, SOURCE, ImportedFinding, Patch, VerifyRequest, digest, evidence
from safepatch.policy import PolicyError
from safepatch.repository import baseline, checkout, registry, run_git
from safepatch.runner import execute
from safepatch.sarif import read_sarif
from safepatch.submission import submitted_patch
from mock_patches import correct_patch

pytestmark = [pytest.mark.integration, pytest.mark.skipif(os.environ.get("RUN_JAVA_INTEGRATION") != "1", reason="Set RUN_JAVA_INTEGRATION=1 after Java/Maven preparation")]


@pytest.fixture(autouse=True)
def lab_profile(monkeypatch):
    # These tests build the synthetic labs natively, which only the lab profile allows (week 8).
    monkeypatch.setenv("SAFEPATCH_PROFILE", "lab")


def run_case(case_id, patch=None, attempt=None, scanner="builtin"):
    spec = registry()[1][case_id]
    attempt = attempt if attempt is not None else (1 if patch else 0)
    return execute(VerifyRequest(job_id=uuid.uuid4().hex, case_id=case_id, base_commit=spec["commit"], attempt=attempt, deadline=time.time() + 300, scanner=scanner, patch=patch, target_file=SOURCE if patch else None))


def record(name, result):
    artifact = result.pop("artifact_b64", None)
    if artifact:
        target = ROOT / ".runtime/test-verified-artifacts"
        target.mkdir(parents=True, exist_ok=True)
        (target / (name + ".jar")).write_bytes(base64.b64decode(artifact))
    directory = evidence("java-integration")
    directory.mkdir(parents=True, exist_ok=True)
    (directory / (name + ".json")).write_text(json.dumps({"model_mode": "mock-test-reference-patch", "scanner_mode": "real-builtin-demo", "result": result}, indent=2), encoding="utf-8")


@pytest.mark.parametrize("kind", ["sql", "path", "command"])
def test_real_baseline_then_reference_fix(kind):
    case_id = kind + "-01"
    initial = run_case(case_id)
    record(case_id + "-baseline", initial)
    assert initial["baseline_valid"], initial
    _, files = baseline(case_id, registry()[1][case_id]["commit"])
    fixed = run_case(case_id, correct_patch(kind, files))
    record(case_id + "-reference-fix", fixed)
    assert fixed["passed"], fixed


def test_expert_attempt_numbers_reach_the_real_verifier():
    # Expert patches are numbered after the model's three attempts (4-6).
    _, files = baseline("sql-01", registry()[1]["sql-01"]["commit"])
    assert run_case("sql-01", correct_patch("sql", files), attempt=6)["passed"]


def test_a_submitted_git_diff_reaches_the_real_verifier(tmp_path):
    # A patch made outside SafePatch arrives as `git diff` output (docs/YAMA_DOGRULAMA.md).
    case, files = baseline("sql-01", registry()[1]["sql-01"]["commit"])
    work = tmp_path / "clone"
    checkout("sql-01", case["commit"], work)
    (work / SOURCE).write_text(correct_patch("sql", files).edits[0].content, encoding="utf-8", newline="\n")
    patch, _ = submitted_patch(case, files, run_git(work, "diff").decode("utf-8"), "Bound parameter instead of concatenating the input.")
    result = run_case("sql-01", patch)
    record("sql-01-submitted-git-diff", result)
    assert result["passed"], result


OTHER_DAO = "src/main/java/demo/OtherDao.java"
OTHER_SOURCE = 'package demo;\n\npublic class OtherDao {\n    public String query(String input) {\n        String sql = "SELECT id FROM t WHERE n = \'" + input + "\'";\n        return sql;\n    }\n}\n'


@pytest.fixture
def two_files(tmp_path, monkeypatch):
    """sql-01 plus a second vulnerable file; the whole demo package is scanned and editable."""
    import importlib.util
    import subprocess
    import yaml
    from safepatch.project import synthetic_descriptor
    spec = importlib.util.spec_from_file_location("seed_script", ROOT / "scripts/seed.py")
    seed = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(seed)
    repo = tmp_path / "multi-sql"
    for name, data in {**seed.expected_files("sql", 1), OTHER_DAO: OTHER_SOURCE.encode()}.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_bytes(data)
    git = lambda *a: subprocess.check_output(["git", "-c", "user.name=Test", "-c", "user.email=t@localhost", "-c", "core.autocrlf=false", *a], cwd=repo).decode().strip()
    git("init", "-q"); git("add", "."); git("commit", "-qm", "two vulnerable files")
    descriptor = synthetic_descriptor("multi-sql", {"kind": "sql", "split": "development", "commit": git("rev-parse", "HEAD")}, repo)
    descriptor.update(editable=["src/main/java/demo/*.java"], scan={"paths": ["src/main/java/demo"]})
    (tmp_path / "projects").mkdir()
    (tmp_path / "projects/multi-sql.yml").write_text(yaml.safe_dump(descriptor), encoding="utf-8", newline="\n")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    return descriptor["repository"]["commit"]


def test_each_file_is_verified_on_its_own_finding(two_files):
    def verify(patch=None, target=None, tolerated=()):
        return execute(VerifyRequest(job_id=uuid.uuid4().hex, case_id="multi-sql", base_commit=two_files, attempt=1 if patch else 0,
                                     deadline=time.time() + 180, scanner="builtin", patch=patch, target_file=target, tolerated=list(tolerated)))
    initial = verify()
    assert initial["baseline_valid"]
    fingerprints = {f["file"]: f["fingerprint"] for s in initial["scans"] for f in s["findings"]}
    assert sorted(fingerprints) == [SOURCE, OTHER_DAO]
    _, files = baseline("multi-sql", two_files)
    fix = correct_patch("sql", files)
    # The DemoService job: the other file's finding is tolerated, so the fix passes on its own finding.
    assert verify(fix, SOURCE, [fingerprints[OTHER_DAO]])["passed"]
    untolerated = verify(fix, SOURCE)
    assert not untolerated["passed"] and untolerated["feedback"]["remaining_rules"] == ["bigg.java.sql-concatenation"]
    # The OtherDao job: its finding is gone, but the project's single security suite still exploits
    # DemoService, so the candidate is not accepted (conservative until witnesses map to findings).
    other = Patch.model_validate({"edits": [{"path": OTHER_DAO, "old_sha256": digest(OTHER_SOURCE), "content": OTHER_SOURCE.replace("'\" + input + \"'\"", "?\"")}], "rationale": "MOCK TEST ONLY"})
    result = verify(other, OTHER_DAO, [fingerprints[SOURCE]])
    assert not result["passed"] and not result["security"]["passed"] and result["feedback"]["remaining_rules"] == []


@pytest.mark.parametrize("kind", ["sql", "path", "command"])
def test_function_disabling_patch_is_rejected(kind):
    case_id = kind + "-02"
    _, files = baseline(case_id, registry()[1][case_id]["commit"])
    patch = Patch.model_validate({"edits": [{"path": SOURCE, "old_sha256": digest(files[SOURCE]), "content": 'package demo;\npublic class DemoService {\n    public String lookup(String input) throws Exception { return ""; }\n}\n'}], "rationale": "MOCK TEST ONLY: deliberately broken behavior"})
    result = run_case(case_id, patch)
    record(case_id + "-broken-function", result)
    assert not result["passed"]
    assert not result["behavior"]["passed"]


@pytest.mark.parametrize("kind", ["sql", "path", "command"])
def test_protected_test_deletion_rejected_before_execution(kind):
    case_id = kind + "-03"
    _, files = baseline(case_id, registry()[1][case_id]["commit"])
    patch = correct_patch(kind, files)
    patch.edits[0].path = "src/test/java/demo/SecurityTest.java"
    with pytest.raises(PolicyError):
        run_case(case_id, patch)
    record(case_id + "-protected-test", {"passed": False, "reason": "policy_rejected_before_execution"})


def findsecbugs_prepared():
    from safepatch.runner import FINDSECBUGS_PLUGIN, tools_dir
    return (tools_dir() / "downloads" / FINDSECBUGS_PLUGIN[0]).is_file()


findsecbugs = pytest.mark.skipif(not findsecbugs_prepared(), reason="Run scripts/prepare_findsecbugs.py first")


def rules(result):
    return {f["rule_id"] for scan in result["scans"] for f in scan["findings"]}


@findsecbugs
@pytest.mark.parametrize("kind,rule", [("sql", "SQL_INJECTION_JDBC"), ("command", "COMMAND_INJECTION")])
def test_findsecbugs_reports_the_lab_weakness_on_the_baseline(kind, rule):
    initial = run_case(kind + "-01", scanner="findsecbugs")
    assert initial["baseline_valid"] and rule in rules(initial), initial["scans"]


@findsecbugs
def test_findsecbugs_does_not_see_the_lab_path_pattern():
    # Path.resolve(input) then Files.readString: not a FindSecBugs 1.14 sink, so no finding and no job.
    assert not run_case("path-01", scanner="findsecbugs")["baseline_valid"]


def imported(case_id):
    """The lab case's real Semgrep SARIF export, read as the institution's own findings."""
    case, files = baseline(case_id, registry()[1][case_id]["commit"])
    raw = (ROOT / f"tests/fixtures/sarif/semgrep-{case_id}.sarif").read_bytes()
    return [ImportedFinding.model_validate(f) for f in read_sarif(raw, case["commit"], files, case["spec"].scan.paths)[0]["findings"]]


def run_import(case_id, scanner, patch=None):
    """Imported findings go with the baseline only (docs/SARIF_ICERI_ALMA.md)."""
    return execute(VerifyRequest(job_id=uuid.uuid4().hex, case_id=case_id, base_commit=registry()[1][case_id]["commit"], attempt=1 if patch else 0,
                                 deadline=time.time() + 300, scanner=scanner, patch=patch, target_file=SOURCE if patch else None,
                                 imported=[] if patch else imported(case_id)))


def test_imported_findings_beside_an_own_scanner_that_sees_them_too():
    # Options b and a on sql-01: the narrow builtin scanner also reports the weakness, so after the
    # fix its rescan must be clean as well; the imported finding itself is not rescanned.
    initial = run_import("sql-01", "sarif+builtin")
    record("sql-01-sarif-baseline", initial)
    assert initial["baseline_valid"] and [(s["tool"], len(s["findings"])) for s in initial["scans"]] == [("sarif", 1), ("builtin-demo", 1)]
    _, files = baseline("sql-01", registry()[1]["sql-01"]["commit"])
    fixed = run_import("sql-01", "sarif+builtin", correct_patch("sql", files))
    record("sql-01-sarif-reference-fix", fixed)
    assert fixed["passed"] and [(s["tool"], len(s["findings"])) for s in fixed["scans"]] == [("sarif", 0), ("builtin-demo", 0)], fixed


@findsecbugs
def test_an_imported_finding_the_own_scanner_misses_is_decided_by_the_witness():
    # Option b on path-01: FindSecBugs alone sees nothing here, so no job (see above). With the
    # imported finding the baseline is valid; the witness accepts the reference fix and refuses a
    # change that only rewrites the flagged expression.
    initial = run_import("path-01", "sarif+findsecbugs")
    assert initial["baseline_valid"] and [(s["tool"], len(s["findings"])) for s in initial["scans"]] == [("sarif", 1), ("findsecbugs", 0)], initial["scans"]
    _, files = baseline("path-01", registry()[1]["path-01"]["commit"])
    fixed = run_import("path-01", "sarif+findsecbugs", correct_patch("path", files))
    record("path-01-sarif-findsecbugs-reference-fix", fixed)
    assert fixed["passed"], fixed
    disguised = Patch.model_validate({"edits": [{"path": SOURCE, "old_sha256": digest(files[SOURCE]), "content": files[SOURCE].replace("root.resolve(input)", 'root.resolve("" + input)')}],
                                      "rationale": "MOCK TEST ONLY: same traversal, other expression"})
    result = run_import("path-01", "sarif+findsecbugs", disguised)
    record("path-01-sarif-findsecbugs-disguised", result)
    assert not result["passed"] and not result["security"]["passed"] and result["behavior"]["passed"]


@findsecbugs
@pytest.mark.parametrize("kind,passes", [("sql", True), ("command", False)])
def test_findsecbugs_after_the_reference_fix(kind, passes):
    # The command fix runs a fixed program with the input as one argv element, no shell; FindSecBugs
    # still reports the request data reaching ProcessBuilder, so under today's acceptance rule the
    # correct fix stays a remaining finding (docs/FINDSECBUGS.md).
    _, files = baseline(kind + "-01", registry()[1][kind + "-01"]["commit"])
    fixed = run_case(kind + "-01", correct_patch(kind, files), scanner="findsecbugs")
    assert fixed["passed"] is passes and (fixed["security"]["passed"] if not passes else True)
    if not passes:
        assert fixed["feedback"]["remaining_rules"] == ["COMMAND_INJECTION"]
