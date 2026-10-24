import base64
from collections import ChainMap
import json
import os
from pathlib import Path
import re
import shutil
import threading
import time
import uuid
import xml.etree.ElementTree as ET

from fastapi import Depends, FastAPI, HTTPException

from safepatch.common import ROOT, VerifyRequest, digest, remaining, require_service, runtime, secret, setting
from safepatch.policy import PolicyError, validate_patch
from safepatch.process import run
from safepatch.repository import allowed_files, baseline, checkout, commit_candidate, tracked_changes
from safepatch.scanner import SonarAdapter, builtin_scan, parse_semgrep

app = FastAPI(title="SafePatch restricted runner")
lock = threading.Lock()


def maven(workspace, args, deadline, extra=None, online=False, limit=240):
    executable = shutil.which("mvn")
    if not executable:
        raise RuntimeError("maven_missing")
    cache = setting("MAVEN_CACHE", str(ROOT / ".runtime/m2"))
    argv = [executable, "-B", "-ntp", "-Dmaven.repo.local=" + cache, "-Dstyle.color=never", "-DargLine=-Xmx512m -Dfile.encoding=UTF-8"]
    if not online:
        argv.append("-o")
    return run(argv + args, workspace, remaining(deadline, limit), extra)


# A project without a security witness never passes (decision 3, 25 Oct 2026).
MISSING_WITNESS = {"passed": False, "missing": True, "tests": 0, "failures": 0, "errors": 0, "skipped": 0, "details": []}


def tests(workspace, selection, deadline, limit=240):
    """Run one descriptor test selection and read every Surefire report it produced."""
    reports_dir = workspace / "target/surefire-reports"
    shutil.rmtree(reports_dir, ignore_errors=True)
    result = maven(workspace, ["-Dtest=" + ",".join(selection.selectors), "test"], deadline, limit=limit)
    reports = sorted(reports_dir.glob("TEST-*.xml")) if reports_dir.exists() else []
    if not reports:
        return {"passed": False, "infrastructure_error": True, "reason": "missing_junit_report", "exit_code": result["exit_code"], "duration_seconds": result["duration_seconds"]}
    count = errors = failures = skipped = 0
    details = []
    for report in reports:
        root = ET.parse(report).getroot()
        count += int(root.get("tests", 0))
        errors += int(root.get("errors", 0))
        failures += int(root.get("failures", 0))
        skipped += int(root.get("skipped", 0))
        # Only named assertions from trusted tests are provided back to the model.
        details += [{"name": t.get("name"), "type": f.tag, "assertion": next((m for m in selection.markers if m in f.get("message", "")), "BEHAVIOR_REGRESSION")} for t in root.findall("testcase") for f in list(t) if f.tag in ("failure", "error")]
    return {"passed": result["exit_code"] == 0 and count > 0 and errors + failures + skipped == 0, "tests": count, "failures": failures, "errors": errors, "skipped": skipped, "details": details, "exit_code": result["exit_code"], "duration_seconds": result["duration_seconds"], "junit_sha256": digest(b"".join(r.read_bytes() for r in reports))}


def wsl_path(path):
    path = str(Path(path).resolve())
    if len(path) < 3 or path[1:3] != ":\\":
        raise ValueError("Expected Windows drive path")
    return "/mnt/" + path[0].lower() + "/" + path[3:].replace("\\", "/")


def scan(workspace, spec, files, commit, scanner, job_id, attempt, deadline):
    paths, kind = spec.scan.paths, spec.labels.get("kind")
    if scanner == "builtin":
        return [builtin_scan(files, paths, kind, commit)]
    output = workspace / "semgrep.json"
    rules = Path(setting("RULES_FILE", str(ROOT / "rules/java.yml")))
    if os.name == "nt":
        executable = setting("SEMGREP_WSL", wsl_path(ROOT / ".runtime/semgrep-venv/bin/semgrep"))
        command = ["wsl", "-d", setting("WSL_DISTRO", "Debian"), "--", "env", "SEMGREP_SEND_METRICS=off", "SEMGREP_ENABLE_VERSION_CHECK=0", executable]
        command += ["scan", "--config", wsl_path(rules), "--json", "--output", wsl_path(output), "--metrics=off", "--disable-version-check", "--no-git-ignore", "--strict", *[wsl_path(workspace / p) for p in paths]]
        prefixes = [wsl_path(workspace)]
    else:
        command = [setting("SEMGREP_BIN", "semgrep"), "scan", "--config", str(rules), "--json", "--output", str(output), "--metrics=off", "--disable-version-check", "--no-git-ignore", "--strict", *[str(workspace / p) for p in paths]]
        prefixes = [str(workspace.resolve()), str(workspace)]
    result = run(command, workspace, remaining(deadline, 90))
    if result["exit_code"] != 0 or not output.exists():
        raise RuntimeError("semgrep_scan_failed")
    data = json.loads(output.read_text(encoding="utf-8"))
    version = data.get("version", "unknown")
    if version != "1.136.0":
        raise RuntimeError("semgrep_version_mismatch")
    reports = [parse_semgrep(data, commit, version, prefixes)]
    if scanner == "sonarqube+semgrep":
        rule = {"sql": "javasecurity:S3649", "path": "javasecurity:S2083", "command": "javasecurity:S2076"}.get(kind)
        if rule is None:
            raise RuntimeError("sonar_rule_mapping_missing")
        token = secret("SONAR_TOKEN")
        url = setting("SONAR_URL", "http://127.0.0.1:9000")
        adapter = SonarAdapter(url, token)
        coverage = adapter.preflight(setting("SONAR_VERSION", "25.9.0.112764"), rule)
        # Unique key prevents another scan's issues from being mistaken for this scan.
        key = f"bigg-{job_id}-{attempt}-{uuid.uuid4().hex[:8]}"
        result = maven(workspace, ["org.sonarsource.scanner.maven:sonar-maven-plugin:5.1.0.4751:sonar", "-Dsonar.projectKey=" + key, "-Dsonar.scm.revision=" + commit, "-Dsonar.host.url=" + url, "-Dsonar.scanner.skipJreProvisioning=true"], deadline, {"SONAR_TOKEN": token, "SONAR_USER_HOME": str(runtime("sonar-cache"))})
        if result["exit_code"]:
            raise RuntimeError("sonar_scanner_failed")
        report = adapter.collect(workspace / "target/sonar/report-task.txt", key, commit, deadline)
        report["version"] = coverage["server_version"]
        report["coverage_check"] = coverage
        reports.append(report)
    return reports


def execute(req: VerifyRequest):
    started = time.monotonic()
    remaining(req.deadline)
    case, files = baseline(req.case_id, req.base_commit)
    spec = case["spec"]
    workspace = runtime("runner-work") / f"{req.job_id}-{req.attempt}-{uuid.uuid4().hex[:8]}"
    checkout(req.case_id, req.base_commit, workspace)
    patch_meta, view, revision = None, files, req.base_commit
    if req.patch:
        patch_meta = validate_patch(files, req.patch, workspace, allowed_files(spec, files, req.target_file))
        # This source revision is the exact patched content; never label it as base HEAD.
        revision = commit_candidate(workspace, req.base_commit, req.patch.edits, patch_meta["diff"])
        view = ChainMap({edit.path: edit.content for edit in req.patch.edits}, files)
    compile_result = maven(workspace, spec.build.package_goals, req.deadline, limit=spec.limits.build_seconds)
    if compile_result["exit_code"]:
        errors = re.findall(r"\[ERROR\] .*?\.java:\[\d+,\d+\][^\n]*", compile_result["output"])
        return {"passed": False, "feedback": {"code": "compilation_failed", "diagnostics": [e[-400:] for e in errors[:4]]}, "patch": patch_meta, "build": {"passed": False, "duration_seconds": compile_result["duration_seconds"]}}
    witness = spec.tests.security
    behavior = tests(workspace, spec.tests.behavior, req.deadline, spec.limits.test_seconds)
    security = tests(workspace, witness, req.deadline, spec.limits.test_seconds) if witness else dict(MISSING_WITNESS)
    reports = scan(workspace, spec, view, revision, req.scanner, req.job_id, req.attempt, req.deadline)
    if tracked_changes(workspace):
        raise PolicyError("tracked_file_changed_during_execution")
    findings = [f for report in reports for f in report["findings"]]
    gate_ok = all(r.get("quality_gate", "OK") == "OK" for r in reports)
    witness_fails = bool(witness) and security.get("failures", 0) >= 1 and security.get("errors") == 0 and security.get("skipped") == 0 and (not witness.markers or any(d["assertion"] in witness.markers for d in security.get("details", [])))
    baseline_valid = bool(not req.patch and behavior["passed"] and findings and (witness_fails or not witness))
    passed = bool(req.patch and witness and behavior["passed"] and security["passed"] and not findings and gate_ok)
    code = "verified" if passed else "security_witness_missing" if req.patch and not witness and behavior["passed"] and not findings and gate_ok else "validation_failed"
    response = {"passed": passed, "baseline_valid": baseline_valid, "base_commit": req.base_commit, "source_revision": revision, "build": {"passed": True, "duration_seconds": compile_result["duration_seconds"]}, "behavior": behavior, "security": security, "scans": reports, "patch": patch_meta, "feedback": {"code": code, "behavior": behavior, "security": security, "remaining_rules": [f["rule_id"] for f in findings]}, "duration_seconds": round(time.monotonic() - started, 3), "runner_profile": setting("RUNNER_PROFILE", "native-same-user"), "versions": {"java": setting("JAVA_VERSION_LABEL", "17; inspect preparation evidence"), "maven": setting("MAVEN_VERSION_LABEL", "3.9.16")}}
    if passed:
        if not spec.build.artifact:
            raise PolicyError("artifact_not_configured")
        artifact = (workspace / spec.build.artifact).read_bytes()
        if len(artifact) > 64 * 1024**2:
            raise PolicyError("artifact_size_budget")
        response["artifact_b64"] = base64.b64encode(artifact).decode()
        response["artifact_sha256"] = digest(artifact)
    return response


@app.get("/health")
def health():
    return {"service": "runner", "status": "ok", "profile": setting("RUNNER_PROFILE", "native-same-user")}


@app.post("/execute", dependencies=[Depends(require_service("RUNNER_TOKEN"))])
def execute_route(req: VerifyRequest):
    if not lock.acquire(blocking=False):
        raise HTTPException(503, "runner_busy")
    try:
        return execute(req)
    except PolicyError as exc:
        raise HTTPException(422, str(exc)) from exc
    except (RuntimeError, TimeoutError, OSError) as exc:
        raise HTTPException(503, type(exc).__name__ + ":" + str(exc)[:160]) from exc
    finally:
        lock.release()
