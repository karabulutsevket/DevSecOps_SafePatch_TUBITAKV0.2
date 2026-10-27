import json
import time

import pytest

from safepatch.scanner import SonarAdapter, parse_semgrep, parse_spotbugs


@pytest.mark.parametrize("response", [{}, {"results": [], "errors": [{"type": "parse"}]}, {"results": [], "paths": {"scanned": []}}])
def test_incomplete_semgrep_rejected(response):
    with pytest.raises(RuntimeError):
        parse_semgrep(response, "a" * 40, "1.136.0", ["/workspace"])


def sonar_mock(tmp_path, override):
    report = tmp_path / "report-task.txt"
    report.write_text("projectKey=job-specific\nserverUrl=http://127.0.0.1:9000\nceTaskId=TASK1\n")
    def call(url, **kwargs):
        if "/api/ce/task" in url:
            result = {"task": {"componentKey": "job-specific", "status": "SUCCESS", "analysisId": "ANALYSIS1"}}
        elif "/api/project_analyses" in url:
            result = {"analyses": [{"key": "ANALYSIS1", "revision": "r1"}]}
        elif "/api/qualitygates" in url:
            result = {"projectStatus": {"status": "OK"}}
        elif "/api/issues" in url:
            result = {"issues": [], "paging": {"total": 0}}
        elif "/api/hotspots" in url:
            result = {"hotspots": [{"key": "HOTSPOT", "status": "TO_REVIEW"}]}
        else:
            raise AssertionError(url)
        return override(url, result)
    return SonarAdapter("http://127.0.0.1:9000", "test-token", call), report


def test_sonar_contract_keeps_hotspots_separate(tmp_path):
    adapter, report = sonar_mock(tmp_path, lambda u, r: r)
    result = adapter.collect(report, "job-specific", "r1", time.time() + 10)
    assert result["findings"] == []
    assert len(result["security_hotspots"]["hotspots"]) == 1
    assert result["analysis_id"] == "ANALYSIS1"


def test_stale_sonar_revision_rejected(tmp_path):
    adapter, report = sonar_mock(tmp_path, lambda u, r: r)
    with pytest.raises(RuntimeError, match="revision_mismatch"):
        adapter.collect(report, "job-specific", "NEW-COMMIT", time.time() + 10)


def test_sonar_failed_compute_not_green(tmp_path):
    def override(url, r):
        if "/api/ce/task" in url:
            r["task"]["status"] = "FAILED"
        return r
    adapter, report = sonar_mock(tmp_path, override)
    with pytest.raises(RuntimeError, match="compute_failed"):
        adapter.collect(report, "job-specific", "r1", time.time() + 10)


def test_sonar_wrong_project_rejected(tmp_path):
    adapter, report = sonar_mock(tmp_path, lambda u, r: r)
    with pytest.raises(RuntimeError, match="identity_mismatch"):
        adapter.collect(report, "different-job", "r1", time.time() + 10)


@pytest.mark.parametrize("raw,prefixes,expected", [
    ("/mnt/c/run/ws/src/main/java/org/x/A.java", ["/mnt/c/run/ws"], "src/main/java/org/x/A.java"),
    (r"C:\run\ws\src\main\java\A.java", [r"C:\run\ws"], "src/main/java/A.java"),
    ("src/main/java/A.java", ["/elsewhere"], "src/main/java/A.java"),
])
def test_scanner_paths_become_repository_relative(raw, prefixes, expected):
    from safepatch.scanner import relative_path
    assert relative_path(raw, prefixes) == expected


@pytest.mark.parametrize("raw", ["/etc/passwd", "/mnt/c/run/other/A.java", "../A.java"])
def test_scanner_paths_outside_the_workspace_are_rejected(raw):
    from safepatch.scanner import relative_path
    with pytest.raises(RuntimeError, match="outside_workspace"):
        relative_path(raw, ["/mnt/c/run/ws"])


def test_semgrep_findings_keep_their_real_file():
    data = {"version": "1.136.0", "errors": [], "paths": {"scanned": ["x"]}, "results": [
        {"check_id": "rules.bigg.java.sql-concatenation", "path": "/mnt/c/ws/src/main/java/org/x/Dao.java", "start": {"line": 7}, "extra": {"severity": "ERROR", "message": "m", "metadata": {"cwe": ["CWE-89"]}}}]}
    finding = parse_semgrep(data, "a" * 40, "1.136.0", ["/mnt/c/ws"])["findings"][0]
    assert finding["file"] == "src/main/java/org/x/Dao.java" and finding["rule_id"] == "bigg.java.sql-concatenation"
    from safepatch.common import digest
    assert finding["fingerprint"] == digest("bigg.java.sql-concatenation" + "src/main/java/org/x/Dao.java")


def test_builtin_scanner_uses_descriptor_paths_and_lab_kind():
    from safepatch.scanner import builtin_scan
    vulnerable = 'String sql = "SELECT name FROM t WHERE n = \'" + input + "\'"; executeQuery(sql);'
    files = {"src/main/java/a/A.java": vulnerable, "src/main/java/b/B.java": vulnerable, "src/test/java/a/T.java": vulnerable}
    found = builtin_scan(files, ["src/main/java/a"], "sql", "a" * 40)["findings"]
    assert [f["file"] for f in found] == ["src/main/java/a/A.java"]
    assert builtin_scan(files, ["src/main/java"], None, "a" * 40)["findings"] == []


SPOTBUGS = {name: json.loads(open(f"tests/fixtures/spotbugs/{name}.sarif", encoding="utf-8").read()) for name in ("sql-01", "command-01", "path-01")}
LAB = {"src/main/java/demo/DemoService.java": "", "src/main/java/demo/Application.java": "", "src/main/java/demo/EchoMain.java": ""}


@pytest.mark.parametrize("case,expected", [
    # SpotBugs 4.9.8 + FindSecBugs 1.14.0 on the synthetic lab (recorded 27 Oct 2026). Path-01 reads
    # through Path.resolve and Files.readString, which FindSecBugs does not treat as sinks: no finding.
    ("sql-01", {("SQL_INJECTION_JDBC", "CWE-89", 17), ("SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE", "CWE-89", 17)}),
    ("command-01", {("COMMAND_INJECTION", "CWE-78", 16)}),
    ("path-01", set()),
])
def test_spotbugs_findings_are_security_results_with_a_cwe(case, expected):
    report = parse_spotbugs(SPOTBUGS[case], "a" * 40, LAB, ["src/main/java/demo/DemoService.java"])
    assert {(f["rule_id"], f["cwe"], f["line"]) for f in report["findings"]} == expected
    assert all(f["file"] == "src/main/java/demo/DemoService.java" and f["tool"] == "findsecbugs" for f in report["findings"])


def test_spotbugs_notes_and_style_results_are_not_findings():
    # SPRING_ENDPOINT is tagged SECURITY but names no CWE; THROWS_METHOD... names CWE-397 but is BAD_PRACTICE.
    report = parse_spotbugs(SPOTBUGS["command-01"], "a" * 40, LAB, ["src/main/java/demo"])
    assert {f["rule_id"] for f in report["findings"]} == {"COMMAND_INJECTION"}


def test_spotbugs_results_outside_the_scan_paths_or_ambiguous_are_unmapped():
    two = {**LAB, "other/src/main/java/demo/DemoService.java": ""}
    report = parse_spotbugs(SPOTBUGS["sql-01"], "a" * 40, two, ["src/main/java", "other/src/main/java"])
    assert report["findings"] == [] and report["unmapped_results"] == 2


@pytest.mark.parametrize("change", [
    lambda d: d["runs"][0]["tool"]["driver"].update(version="4.10.5"),
    lambda d: d["runs"][0]["invocations"][0].update(executionSuccessful=False),
])
def test_spotbugs_other_versions_and_failed_runs_are_refused(change):
    data = json.loads(json.dumps(SPOTBUGS["sql-01"]))
    change(data)
    with pytest.raises(RuntimeError):
        parse_spotbugs(data, "a" * 40, LAB, ["src/main/java"])


def test_spotbugs_findings_of_unsupported_families_are_kept_apart():
    # VUL4J-79 and OWASP Benchmark: log injection (CWE-117) and trust boundary (CWE-807) results
    # would stay after any fix of the supported weakness in the same file.
    data = json.loads(json.dumps(SPOTBUGS["sql-01"]))
    run = data["runs"][0]
    extension = run["tool"]["extensions"][-1]
    for rule_id, cwe in (("CRLF_INJECTION_LOGS", "117"), ("SERVLET_HEADER", "807")):
        extension.setdefault("rules", []).append({"id": rule_id, "properties": {"tags": ["SECURITY"]},
                                                  "relationships": [{"target": {"id": cwe, "toolComponent": {"name": "CWE"}}}]})
        run["results"].append({"ruleId": rule_id, "level": "warning", "message": {"text": rule_id},
                               "locations": [{"physicalLocation": {"artifactLocation": {"uri": "demo/DemoService.java"}, "region": {"startLine": 12}}}]})
    report = parse_spotbugs(data, "a" * 40, LAB, ["src/main/java"])
    assert {f["cwe"] for f in report["findings"]} == {"CWE-89"}
    assert {(f["rule_id"], f["cwe"]) for f in report["other_findings"]} == {("CRLF_INJECTION_LOGS", "CWE-117"), ("SERVLET_HEADER", "CWE-807")}
