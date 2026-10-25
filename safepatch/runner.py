import base64
from collections import ChainMap
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import threading
import time
import uuid
import xml.etree.ElementTree as ET

from fastapi import Depends, FastAPI, HTTPException

from safepatch.acceptance import untolerated
from safepatch.common import ROOT, VerifyRequest, digest, known_findings_enabled, safe_path, remaining, require_service, runtime, secret, setting
from safepatch.policy import PolicyError, validate_patch
from safepatch.process import run
from safepatch.repository import allowed_files, baseline, checkout, commit_candidate, tracked_changes
from safepatch.scanner import SonarAdapter, builtin_scan, parse_semgrep

app = FastAPI(title="SafePatch restricted runner")
lock = threading.Lock()


# Docker sandbox (roadmap weeks 5–6): build and tests run project code, so a real project is
# only ever built in a container with no network, a read-only root, no capabilities, a
# non-root user and resource limits. Dependencies come from a read-only copy of the offline
# Maven cache inside WSL (on /mnt/c a build takes ~8x longer).
SANDBOX_IMAGE = "maven:3.9.16-eclipse-temurin-17@sha256:1a352420f7aba21f5ad08df31bab55f74c013fb491f1ae8ab1dd7ff9ed698584"
# The descriptor's `java` picks the image: old projects (most Vul4J cases) cannot build on JDK 17.
SANDBOX_IMAGES = {"17": SANDBOX_IMAGE, "8": "maven:3.9.16-eclipse-temurin-8@sha256:0f402712b7a469189cfea5ec69cdcadcb32b22aaf1ea62777ab925c3d8470175"}
ARG_LINE = "-Xmx512m -Dfile.encoding=UTF-8"
MAVEN_FLAGS = ["-B", "-ntp", "-Dstyle.color=never", "-DargLine=" + ARG_LINE]
# The test JVM gets its own temp dir. Java's default is /tmp, and a traversal witness aimed at
# /tmp cannot tell a fix apart when the extraction dir is /tmp itself (VUL4J-79). Like /tmp it
# is a noexec tmpfs; Maven's local repository and HOME stay in /tmp.
TEST_TMP = "/jvmtmp"


def sandbox_mode(spec):
    """'docker' or 'native'. Only the owned synthetic labs may still build natively."""
    mode = setting("RUNNER_SANDBOX", "native")
    if mode not in ("docker", "native"):
        raise PolicyError("unknown_runner_sandbox")
    if mode != "docker" and spec.labels.get("source") != "safepatch-synthetic":
        raise PolicyError("sandbox_required_for_real_projects")
    return mode


def wsl(*argv):
    return ["wsl", "-d", setting("WSL_DISTRO", "Debian"), "--exec", *argv]


def sandbox_image(java="17"):
    image = setting("SANDBOX_IMAGE_" + java) or (setting("SANDBOX_IMAGE") if java == "17" else None) or SANDBOX_IMAGES.get(java)
    if not image:
        raise PolicyError("no_sandbox_image_for_java_" + java)
    return image


def sandboxed(argv, workspace, name, java="17"):
    """The docker command running argv for this workspace inside the sandbox."""
    cache = setting("SANDBOX_MAVEN_CACHE")
    if not cache or not cache.startswith("/"):
        raise RuntimeError("sandbox_maven_cache_missing")
    return wsl("docker", "run", "--rm", "--name", name, "--network", "none", "--read-only", "--tmpfs", "/tmp:rw,size=1g", "--tmpfs", TEST_TMP + ":rw,size=512m",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "1024",
               "--memory", setting("SANDBOX_MEMORY", "2g"), "--cpus", setting("SANDBOX_CPUS", "2"), "--user", setting("SANDBOX_USER", "1000:1000"),
               "-e", "HOME=/tmp", "-e", "MAVEN_OPTS=-Xmx512m -Dfile.encoding=UTF-8",
               "-v", wsl_path(workspace) + ":/workspace", "-w", "/workspace", "-v", cache + ":/m2:ro",
               # The image's entrypoint script copies settings into a home it cannot write; skip it.
               "--entrypoint", argv[0], sandbox_image(java), *argv[1:])


def profile(sandbox, java="17"):
    return "docker:" + sandbox_image(java) if sandbox == "docker" else setting("RUNNER_PROFILE", "native-same-user")


def maven(workspace, args, deadline, extra=None, online=False, limit=240, sandbox="native", java="17"):
    if sandbox == "docker":
        if online or extra:
            raise PolicyError("sandbox_runs_offline_without_secrets")
        name = "safepatch-" + uuid.uuid4().hex[:12]
        flags = [f for f in MAVEN_FLAGS if not f.startswith("-DargLine=")] + [f"-DargLine={ARG_LINE} -Djava.io.tmpdir={TEST_TMP}"]
        argv = ["mvn", *flags, "-o", "-Dmaven.repo.local=/tmp/m2", "-Dmaven.repo.local.tail=/m2", *args]
        try:
            return run(sandboxed(argv, workspace, name, java), workspace, remaining(deadline, limit))
        except TimeoutError:
            # Stopping the wsl client does not stop the container.
            subprocess.run(wsl("docker", "kill", name), capture_output=True, timeout=30)
            raise
    executable = shutil.which("mvn")
    if not executable:
        raise RuntimeError("maven_missing")
    cache = setting("MAVEN_CACHE", str(ROOT / ".runtime/m2"))
    argv = [executable, *MAVEN_FLAGS, "-Dmaven.repo.local=" + cache]
    if not online:
        argv.append("-o")
    return run(argv + args, workspace, remaining(deadline, limit), extra)


# A project without a security witness never passes (decision 3, 25 Oct 2026).
MISSING_WITNESS = {"passed": False, "missing": True, "tests": 0, "failures": 0, "errors": 0, "skipped": 0, "details": []}


def tests(workspace, selection, deadline, limit=240, sandbox="native", java="17"):
    """Run one descriptor test selection and read every Surefire report it produced."""
    reports_dir = workspace / "target/surefire-reports"
    shutil.rmtree(reports_dir, ignore_errors=True)
    result = maven(workspace, ["-Dtest=" + ",".join(selection.selectors), "test"], deadline, limit=limit, sandbox=sandbox, java=java)
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


DIAGNOSTIC = re.compile(r"\[ERROR\] (.*?\.java):\[(\d+),(\d+)\]([^\n]*)")
IDENTIFIER = re.compile(r"[A-Za-z_$][\w$]*")


def symbol_at(workspace, relative, line, column):
    """The identifier at a compiler position; plugins report 0- or 1-based columns."""
    file = Path(workspace) / relative
    if not safe_path(relative) or not file.is_file():
        return None
    lines = file.read_text(encoding="utf-8", errors="replace").splitlines()
    text = lines[line - 1] if 1 <= line <= len(lines) else ""
    for index in (column, column - 1):
        if 0 <= index < len(text) and (index == 0 or not (text[index - 1].isalnum() or text[index - 1] in "_$")):
            match = IDENTIFIER.match(text, index)
            if match:
                return match.group()[:80]
    return None


def diagnostics(output, workspace):
    """Compiler errors with repository-relative paths: the workspace path never reaches a prompt.
    For "cannot find symbol" the name is read from the source, because old compiler plugins
    (zt-zip's 2.3.2) drop javac's "symbol:" line (VUL4J-79, 25 Oct 2026)."""
    base = Path(workspace).resolve().as_posix()
    prefixes = ("/workspace/", "/" + base + "/", base + "/")
    out = []
    for path, line, column, message in DIAGNOSTIC.findall(output):
        relative = next((path[len(p):] for p in prefixes if path.startswith(p)), path.rsplit("/", 1)[-1])
        message = message.strip()
        if "cannot find symbol" in message and (name := symbol_at(workspace, relative, int(line), int(column))):
            message += ": " + name
        entry = f"[ERROR] {relative}:[{line},{column}] {message}"[-400:]
        if entry not in out:
            out.append(entry)
    return out[:4]


def known_findings(spec, commit, patched):
    """Findings from the answer key. Lab and evaluation profiles only; after a patch nothing is
    rescanned, so acceptance rests on the security witness (roadmap week 6)."""
    if not known_findings_enabled():
        raise PolicyError("known_findings_only_in_lab_profile")
    if not spec.scan.known or not spec.tests.security:
        raise PolicyError("known_findings_need_answer_key_and_witness")
    findings = [] if patched else [{"tool": "known-finding", "rule_id": "known:" + k.id, "cwe": k.cwe, "type": "VULNERABILITY", "file": k.file,
                                    "line": k.line, "severity": "HIGH", "source": k.source, "fingerprint": digest("known:" + k.id + k.file)} for k in spec.scan.known]
    return [{"tool": "known-finding", "version": "answer-key", "status": "ok", "commit": commit, "findings": findings,
             "coverage": "answer key; a patched revision is not rescanned, the security witness decides"}]


def scan(workspace, spec, files, commit, scanner, job_id, attempt, deadline, patched=False):
    paths, kind = spec.scan.paths, spec.labels.get("kind")
    if scanner == "known":
        return known_findings(spec, commit, patched)
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
    sandbox = sandbox_mode(spec)
    if sandbox == "docker" and req.scanner == "sonarqube+semgrep":
        # The Sonar Maven goal needs the Sonar server on the network; refuse before building anything.
        raise PolicyError("sonar_scan_needs_network_not_sandboxed")
    if req.scanner == "known":
        known_findings(spec, req.base_commit, True)   # profile and answer-key checks before anything runs
    workspace = runtime("runner-work") / f"{req.job_id}-{req.attempt}-{uuid.uuid4().hex[:8]}"
    checkout(req.case_id, req.base_commit, workspace)
    patch_meta, view, revision = None, files, req.base_commit
    if req.patch:
        patch_meta = validate_patch(files, req.patch, workspace, allowed_files(spec, files, req.target_file))
        # This source revision is the exact patched content; never label it as base HEAD.
        revision = commit_candidate(workspace, req.base_commit, req.patch.edits, patch_meta["diff"])
        view = ChainMap({edit.path: edit.content for edit in req.patch.edits}, files)
    compile_result = maven(workspace, spec.build.package_goals, req.deadline, limit=spec.limits.build_seconds, sandbox=sandbox, java=spec.java)
    if compile_result["exit_code"]:
        return {"passed": False, "feedback": {"code": "compilation_failed", "diagnostics": diagnostics(compile_result["output"], workspace)}, "patch": patch_meta, "build": {"passed": False, "duration_seconds": compile_result["duration_seconds"]}}
    witness = spec.tests.security
    behavior = tests(workspace, spec.tests.behavior, req.deadline, spec.limits.test_seconds, sandbox, spec.java)
    security = tests(workspace, witness, req.deadline, spec.limits.test_seconds, sandbox, spec.java) if witness else dict(MISSING_WITNESS)
    reports = scan(workspace, spec, view, revision, req.scanner, req.job_id, req.attempt, req.deadline, patched=bool(req.patch))
    if tracked_changes(workspace):
        raise PolicyError("tracked_file_changed_during_execution")
    findings = [f for report in reports for f in report["findings"]]
    # Baseline findings in other files may stay (only the target file changed); the rest must be gone.
    remaining_findings = untolerated(findings, req.tolerated)
    gate_ok = all(r.get("quality_gate", "OK") == "OK" for r in reports)
    witness_fails = bool(witness) and security.get("failures", 0) >= 1 and security.get("errors") == 0 and security.get("skipped") == 0 and (not witness.markers or any(d["assertion"] in witness.markers for d in security.get("details", [])))
    baseline_valid = bool(not req.patch and behavior["passed"] and findings and (witness_fails or not witness))
    passed = bool(req.patch and witness and behavior["passed"] and security["passed"] and not remaining_findings and gate_ok)
    code = "verified" if passed else "security_witness_missing" if req.patch and not witness and behavior["passed"] and not remaining_findings and gate_ok else "validation_failed"
    response = {"passed": passed, "baseline_valid": baseline_valid, "base_commit": req.base_commit, "source_revision": revision, "build": {"passed": True, "duration_seconds": compile_result["duration_seconds"]}, "behavior": behavior, "security": security, "scans": reports, "tolerated": req.tolerated, "patch": patch_meta, "feedback": {"code": code, "behavior": behavior, "security": security, "remaining_rules": [f["rule_id"] for f in remaining_findings]}, "duration_seconds": round(time.monotonic() - started, 3), "runner_profile": profile(sandbox, spec.java), "versions": {"java": setting("JAVA_VERSION_LABEL", "17; inspect preparation evidence"), "maven": setting("MAVEN_VERSION_LABEL", "3.9.16")}}
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
    return {"service": "runner", "status": "ok", "profile": profile(setting("RUNNER_SANDBOX", "native"))}


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
