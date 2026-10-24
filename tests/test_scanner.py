import json
import time

import pytest

from safepatch.scanner import SonarAdapter, parse_semgrep


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
