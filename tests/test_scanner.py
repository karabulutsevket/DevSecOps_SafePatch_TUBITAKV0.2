import json
import time

import pytest

from safepatch.scanner import SonarAdapter, parse_semgrep


@pytest.mark.parametrize("response", [{}, {"results": [], "errors": [{"type": "parse"}]}, {"results": [], "paths": {"scanned": []}}])
def test_incomplete_semgrep_rejected(response):
    with pytest.raises(RuntimeError):
        parse_semgrep(response, "a" * 40, "1.136.0", "b" * 64)


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
