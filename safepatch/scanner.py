"""Real narrow fixture scanner + external adapters. Modes are never conflated."""
import json
from pathlib import Path
import re
import time
import uuid

from safepatch.common import digest, request, remaining, safe_path

RULES = {
    "sql": ("bigg.java.sql-concatenation", "CWE-89", r'(?:String\s+\w+\s*=\s*"SELECT[^;]+\+\s*input|executeQuery\([^;]+\+\s*input)'),
    "path": ("bigg.java.path-resolution", "CWE-22", r'\.resolve\(input\)'),
    "command": ("bigg.java.shell-command", "CWE-78", r'new\s+ProcessBuilder\(shell,\s*flag,\s*\w+\)'),
}


def in_scope(path, paths):
    return any(path == p or path.startswith(p.rstrip("/") + "/") for p in paths)


def builtin_scan(files, paths, kind, commit):
    """Pattern-limited fallback for the synthetic cases, NOT SonarQube/Semgrep and not a general
    Java analyzer. `kind` is the synthetic lab label; without it no rule applies."""
    findings = []
    if kind in RULES:
        rule, cwe, pattern = RULES[kind]
        for path in sorted(p for p in files if p.endswith(".java") and in_scope(p, paths)):
            code = files[path]
            match = re.search(pattern, code)
            if kind == "path" and all(s in code for s in ("toRealPath()", ".startsWith(", "throw ")):
                match = None
            if match:
                findings.append({"tool": "builtin-demo", "rule_id": rule, "cwe": cwe, "type": "VULNERABILITY", "file": path, "line": code[:match.start()].count("\n") + 1, "fingerprint": digest(rule + path), "severity": "HIGH"})
    return {"tool": "builtin-demo", "version": "1.0.0", "coverage": "three owned synthetic patterns only", "status": "ok", "analysis_id": uuid.uuid4().hex, "commit": commit, "findings": findings}


def relative_path(raw, prefixes):
    """Map a scanner-reported path back to a repository-relative path."""
    path = raw.replace("\\", "/")
    for prefix in prefixes:
        prefix = prefix.replace("\\", "/").rstrip("/") + "/"
        if path.startswith(prefix):
            path = path[len(prefix):]
            break
    if not safe_path(path):
        raise RuntimeError("scanner_path_outside_workspace")
    return path


def parse_semgrep(data, commit, version, prefixes):
    if data.get("errors") or "results" not in data or not data.get("paths", {}).get("scanned"):
        raise RuntimeError("semgrep_incomplete_scan")
    findings = [{"tool": "semgrep", "rule_id": r["check_id"][r["check_id"].find("bigg.java."):] if "bigg.java." in r["check_id"] else r["check_id"], "raw_rule_id": r["check_id"], "type": "VULNERABILITY", "file": relative_path(r["path"], prefixes), "line": r["start"]["line"], "severity": r["extra"]["severity"], "message": r["extra"].get("message", "")[:300], "cwe": r["extra"].get("metadata", {}).get("cwe")} for r in data["results"]]
    for finding in findings:
        finding["fingerprint"] = digest(finding["rule_id"] + finding["file"])
    return {"tool": "semgrep", "version": version, "status": "ok", "analysis_id": uuid.uuid4().hex, "commit": commit, "findings": findings}


SPOTBUGS_VERSION = "4.9.8"


def spotbugs_cwe(rule):
    """The CWE a SpotBugs SARIF rule names in its relationships (FindSecBugs fills them)."""
    for relation in rule.get("relationships", []):
        if relation.get("target", {}).get("toolComponent", {}).get("name") == "CWE":
            return "CWE-" + str(relation["target"]["id"])
    return None


def parse_spotbugs(data, commit, files, paths):
    """SpotBugs SARIF (FindSecBugs plugin) -> findings. Only security results whose rule names a
    CWE (in the SARIF, else in weakness.TOOL_RULES) are findings: style and bad-practice results
    and informational notes (SPRING_ENDPOINT) would otherwise count as weaknesses never fixed.
    SARIF paths are relative to a source root; each maps to the one repository file in the scan
    paths that ends with it, else the result is counted as unmapped. Weaknesses outside the
    supported families are kept apart as other_findings: reported, never a job."""
    from safepatch.weakness import FAMILY, SUPPORTED, TOOL_RULES
    run = data["runs"][0]
    driver = run["tool"]["driver"]
    if driver.get("name") != "SpotBugs" or driver.get("version") != SPOTBUGS_VERSION:
        raise RuntimeError("spotbugs_version_mismatch")
    if not all(i.get("executionSuccessful") for i in run.get("invocations", [])):
        raise RuntimeError("spotbugs_incomplete_scan")
    rules = {r["id"]: r for component in [driver, *run["tool"].get("extensions", [])] for r in component.get("rules", [])}
    findings, other, unmapped = [], [], 0
    for result in run["results"]:
        rule = rules.get(result["ruleId"], {})
        cwe = spotbugs_cwe(rule) or TOOL_RULES.get(result["ruleId"])
        if "SECURITY" not in rule.get("properties", {}).get("tags", []) or not cwe:
            continue
        location = result["locations"][0]["physicalLocation"]
        uri = location["artifactLocation"]["uri"].replace("\\", "/")
        matches = [p for p in files if p.endswith("/" + uri) and in_scope(p, paths)]
        if len(matches) != 1:
            unmapped += 1
            continue
        finding = {"tool": "findsecbugs", "rule_id": result["ruleId"], "type": "VULNERABILITY", "file": matches[0],
                   "line": location.get("region", {}).get("startLine"), "severity": result.get("level", "warning"),
                   "message": result["message"]["text"][:300], "cwe": cwe, "fingerprint": digest(result["ruleId"] + matches[0])}
        (findings if FAMILY.get(cwe, cwe) in SUPPORTED else other).append(finding)
    return {"tool": "findsecbugs", "version": f"spotbugs-{SPOTBUGS_VERSION}+findsecbugs-1.14.0", "status": "ok", "analysis_id": uuid.uuid4().hex,
            "commit": commit, "unmapped_results": unmapped, "findings": findings, "other_findings": other}


def sonar_path(component, project_key):
    """A Sonar component key ('<project>:src/...') as the repository-relative path the other scanners give."""
    return component[len(project_key) + 1:] if component.startswith(project_key + ":") else component


class SonarAdapter:
    """Fresh unique project per scan; never query a shared project's moving HEAD."""
    def __init__(self, url, token, call=request):
        self.url, self.token, self.call = url.rstrip("/"), token, call

    def get(self, path, **params):
        """A Web API call; an HTTP error becomes a named failure the runner reports (live test, 30 Oct 2026)."""
        try:
            return self.call(self.url + path, token=self.token, params=params or None)
        except Exception as exc:
            status = getattr(getattr(exc, "response", None), "status_code", None)
            if status is None:
                raise
            raise RuntimeError(f"sonar_http_{status}") from exc

    def preflight(self, expected_version, required_rule):
        status = self.get("/api/system/status")
        if status.get("status") != "UP" or status.get("version") != expected_version:
            raise RuntimeError("sonar_unavailable_or_version_mismatch")
        # Unsupported rules cannot be represented as a clean scan. An edition without the rule
        # (the Community Build has no taint rules) answers 404.
        try:
            rule = self.get("/api/rules/show", key=required_rule)["rule"]
        except RuntimeError as exc:
            if str(exc) == "sonar_http_404":
                raise RuntimeError("sonar_required_vulnerability_rule_unsupported") from exc
            raise
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
            task = self.get("/api/ce/task", id=task_id)["task"]
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
        analyses = self.get("/api/project_analyses/search", project=project_key, ps=100)["analyses"]
        if not any(a.get("key") == analysis_id and a.get("revision") == revision for a in analyses):
            raise RuntimeError("sonar_revision_mismatch")
        gate = self.get("/api/qualitygates/project_status", analysisId=analysis_id)["projectStatus"]
        if gate.get("status") not in ("OK", "ERROR"):
            raise RuntimeError("sonar_quality_gate_unknown")
        issues = []
        page = 1
        while True:
            result = self.get("/api/issues/search", componentKeys=project_key, resolved="false", types="VULNERABILITY", ps=100, p=page)
            issues.extend(result["issues"])
            if len(issues) >= result["paging"]["total"]:
                break
            page += 1
            remaining(deadline)
        # 26.x names the parameter `project`; the older `projectKey` is refused with 400 (live, 30 Oct 2026).
        hotspots = self.get("/api/hotspots/search", project=project_key, ps=100)
        # A second check catches concurrent replacement even on a unique project.
        latest = self.get("/api/project_analyses/search", project=project_key, ps=1)["analyses"]
        if not latest or latest[0]["key"] != analysis_id:
            raise RuntimeError("sonar_analysis_replaced")
        return {"tool": "sonarqube", "status": "ok", "analysis_id": analysis_id, "commit": revision, "project_key": project_key, "quality_gate": gate["status"], "findings": [{"tool": "sonarqube", "rule_id": i["rule"], "type": i["type"], "file": sonar_path(i["component"], project_key), "line": i.get("line"), "severity": i["severity"], "fingerprint": i["key"]} for i in issues], "security_hotspots": hotspots, "coverage": "Edition/profile dependent; hotspots are not vulnerabilities"}
