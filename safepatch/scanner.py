"""Real narrow fixture scanner + external adapters. Modes are never conflated."""
import json
from pathlib import Path
import re
import time
import uuid

from safepatch.common import SOURCE, digest, request, remaining

RULES = {
    "sql": ("bigg.java.sql-concatenation", "CWE-89", r'(?:String\s+\w+\s*=\s*"SELECT[^;]+\+\s*input|executeQuery\([^;]+\+\s*input)'),
    "path": ("bigg.java.path-resolution", "CWE-22", r'\.resolve\(input\)'),
    "command": ("bigg.java.shell-command", "CWE-78", r'new\s+ProcessBuilder\(shell,\s*flag,\s*\w+\)'),
}


def builtin_scan(files, kind, commit):
    """Pattern-limited fallback, NOT SonarQube/Semgrep and not a general Java analyzer."""
    code = files[SOURCE]
    rule, cwe, pattern = RULES[kind]
    match = re.search(pattern, code)
    if kind == "path" and all(s in code for s in ("toRealPath()", ".startsWith(", "throw ")):
        match = None
    findings = []
    if match:
        findings = [{"tool": "builtin-demo", "rule_id": rule, "cwe": cwe, "type": "VULNERABILITY", "file": SOURCE, "line": code[:match.start()].count("\n") + 1, "fingerprint": digest(rule + SOURCE), "severity": "HIGH"}]
    return {"tool": "builtin-demo", "version": "1.0.0", "coverage": "three owned synthetic patterns only", "status": "ok", "analysis_id": uuid.uuid4().hex, "commit": commit, "source_sha256": digest(code), "findings": findings}


def parse_semgrep(data, commit, version, source_sha):
    if data.get("errors") or "results" not in data or not data.get("paths", {}).get("scanned"):
        raise RuntimeError("semgrep_incomplete_scan")
    findings = [{"tool": "semgrep", "rule_id": r["check_id"][r["check_id"].find("bigg.java."):] if "bigg.java." in r["check_id"] else r["check_id"], "raw_rule_id": r["check_id"], "type": "VULNERABILITY", "file": SOURCE, "line": r["start"]["line"], "severity": r["extra"]["severity"], "message": r["extra"].get("message", "")[:300], "cwe": r["extra"].get("metadata", {}).get("cwe")} for r in data["results"]]
    for finding in findings:
        finding["fingerprint"] = digest(finding["rule_id"] + SOURCE)
    return {"tool": "semgrep", "version": version, "status": "ok", "analysis_id": uuid.uuid4().hex, "commit": commit, "source_sha256": source_sha, "findings": findings}


class SonarAdapter:
    """Fresh unique project per scan; never query a shared project's moving HEAD."""
    def __init__(self, url, token, call=request):
        self.url, self.token, self.call = url.rstrip("/"), token, call

    def get(self, path):
        return self.call(self.url + path, token=self.token)

    def preflight(self, expected_version, required_rule):
        status = self.get("/api/system/status")
        if status.get("status") != "UP" or status.get("version") != expected_version:
            raise RuntimeError("sonar_unavailable_or_version_mismatch")
        # Unsupported rules cannot be represented as a clean scan.
        rule = self.get("/api/rules/show?key=" + required_rule)["rule"]
        if rule.get("type") != "VULNERABILITY" or rule.get("status") == "REMOVED":
            raise RuntimeError("sonar_required_vulnerability_rule_unsupported")
        return {"server_version": status["version"], "required_rule": required_rule, "rule_type": rule["type"]}

    def collect(self, report: Path, project_key, revision, deadline):
        # report path is fixed by trusted runner and removed/created in a clean workspace.
        props = dict(line.split("=", 1) for line in report.read_text().splitlines() if "=" in line)
        if props.get("projectKey") != project_key or props.get("serverUrl", "").rstrip("/") != self.url:
            raise RuntimeError("sonar_report_identity_mismatch")
        task_id = props.get("ceTaskId", "")
        if not re.fullmatch(r"[A-Za-z0-9_-]+", task_id):
            raise RuntimeError("sonar_missing_task_id")
        while True:
            remaining(deadline)
            task = self.get("/api/ce/task?id=" + task_id)["task"]
            if task.get("componentKey") != project_key:
                raise RuntimeError("sonar_wrong_project")
            status = task["status"]
            if status in ("FAILED", "CANCELED"):
                raise RuntimeError("sonar_compute_failed")
            if status == "SUCCESS":
                break
            if status not in ("PENDING", "IN_PROGRESS"):
                raise RuntimeError("sonar_unknown_status")
            time.sleep(min(1, remaining(deadline)))
        analysis_id = task.get("analysisId")
        if not analysis_id:
            raise RuntimeError("sonar_missing_analysis_id")
        analyses = self.get(f"/api/project_analyses/search?project={project_key}&ps=100")["analyses"]
        if not any(a.get("key") == analysis_id and a.get("revision") == revision for a in analyses):
            raise RuntimeError("sonar_revision_mismatch")
        gate = self.get("/api/qualitygates/project_status?analysisId=" + analysis_id)["projectStatus"]
        if gate.get("status") not in ("OK", "ERROR"):
            raise RuntimeError("sonar_quality_gate_unknown")
        issues = []
        page = 1
        while True:
            result = self.get(f"/api/issues/search?componentKeys={project_key}&resolved=false&types=VULNERABILITY&ps=100&p={page}")
            issues.extend(result["issues"])
            if len(issues) >= result["paging"]["total"]:
                break
            page += 1
            remaining(deadline)
        hotspots = self.get(f"/api/hotspots/search?projectKey={project_key}&ps=100")
        # A second check catches concurrent replacement even on a unique project.
        latest = self.get(f"/api/project_analyses/search?project={project_key}&ps=1")["analyses"]
        if not latest or latest[0]["key"] != analysis_id:
            raise RuntimeError("sonar_analysis_replaced")
        return {"tool": "sonarqube", "status": "ok", "analysis_id": analysis_id, "commit": revision, "project_key": project_key, "quality_gate": gate["status"], "findings": [{"tool": "sonarqube", "rule_id": i["rule"], "type": i["type"], "file": i["component"], "line": i.get("line"), "severity": i["severity"], "fingerprint": i["key"]} for i in issues], "security_hotspots": hotspots, "coverage": "Edition/profile dependent; hotspots are not vulnerabilities"}
