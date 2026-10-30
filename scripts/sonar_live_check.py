"""Week 10: the SonarQube adapter against a live SonarQube Community Build (docs/OLCUM_SONAR.md).

The server runs in WSL's Docker, bound to 127.0.0.1:9000, telemetry and update centre off.
- `setup`: replaces the server's default admin password with a random one and makes a user token
  (both in .secrets, never printed), and test identities for the job through the services.
- `check`: server version, whether the taint rules the adapter needs exist, what the Community
  Build offers for the three weakness families instead, and the adapter's preflight per rule.
- `job`: one sql-01 job with scanner sonarqube+semgrep through the running services: how a job
  stops when the edition lacks the rule.
- `scan`: the adapter's collection path outside the product (the preflight would stop it): sql-01
  built, the Maven Sonar goal run against the live server, the report collected by the adapter.
Each step writes its own record under EVIDENCE_DIR/canli and never overwrites one.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import sys
import time
import uuid

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from safepatch.common import digest, evidence, request, runtime, secret, setting

URL = setting("SONAR_URL", "http://127.0.0.1:9000")
RULES = {"sql": "javasecurity:S3649", "path": "javasecurity:S2083", "command": "javasecurity:S2076"}   # as in safepatch/runner.py
FAMILIES = {"sql": "89", "path": "22", "command": "78"}
FOLDER = ROOT / ".runtime" / "sonar"
os.environ.setdefault("SONAR_TOKEN_FILE", str(ROOT / ".secrets" / "sonar_token"))


LABEL = ""


def record(name, data):
    name += "-" + LABEL if LABEL else ""
    out = evidence("canli")
    out.mkdir(parents=True, exist_ok=True)
    target = out / (name + ".json")
    if target.exists():
        raise SystemExit("evidence is never overwritten; use a fresh EVIDENCE_DIR")
    target.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(data, indent=1, ensure_ascii=False)[:3000], "\nwritten:", target)


def setup():
    secrets_dir = ROOT / ".secrets"
    password_file, token_file = secrets_dir / "sonar_admin_password", secrets_dir / "sonar_token"
    if token_file.exists():
        raise SystemExit("already set up: " + str(token_file))
    # A local test server's own admin account; the default password must change before any use.
    with httpx.Client(base_url=URL, trust_env=False, timeout=30) as client:
        if not password_file.exists():
            password = secrets.token_urlsafe(24) + "aA1!"
            client.post("/api/users/change_password", auth=("admin", "admin"),
                        data={"login": "admin", "previousPassword": "admin", "password": password}).raise_for_status()
            password_file.write_text(password, encoding="utf-8")
        password = password_file.read_text(encoding="utf-8")
        # 26.x makes tokens only in a signed-in session (cookie and XSRF header), not with a password.
        client.post("/api/authentication/login", data={"login": "admin", "password": password}).raise_for_status()
        answer = client.post("/api/user_tokens/generate", headers={"X-XSRF-TOKEN": client.cookies.get("XSRF-TOKEN", "")},
                             data={"name": "safepatch-live-check-" + uuid.uuid4().hex[:6]})
        answer.raise_for_status()
        token_file.write_text(answer.json()["token"], encoding="utf-8")
    FOLDER.mkdir(parents=True, exist_ok=True)
    roles = {"developer": "submit", "reviewer": "review"}
    tokens = {role: secrets.token_hex(32) for role in roles}
    (FOLDER / "users.json").write_text(json.dumps([{"subject": "SIMULATED-sonar-" + role, "roles": [permission], "token_sha256": digest(tokens[role]),
                                                    "projects": ["owned-java-demo"]} for role, permission in roles.items()]), encoding="utf-8")
    (FOLDER / "tokens.json").write_text(json.dumps(tokens), encoding="utf-8")
    print("admin password and token written to", secrets_dir, "and test identities to", FOLDER, "- no value printed")


def outcome(call):
    try:
        return {"ok": True, "result": call()}
    except Exception as exc:   # the point is how each call fails
        status = getattr(getattr(exc, "response", None), "status_code", None)
        return {"ok": False, "error": type(exc).__name__, "message": str(exc)[:200], "http_status": status}


def check():
    from safepatch.scanner import SonarAdapter
    token = secret("SONAR_TOKEN")
    get = lambda path, **params: request(URL + path, token=token, params=params or None)
    status = get("/api/system/status")
    rules = {kind: outcome(lambda rule=rule: {k: get("/api/rules/show", key=rule)["rule"].get(k) for k in ("key", "type", "status", "name")}) for kind, rule in RULES.items()}
    offered = {}
    for kind, cwe in FAMILIES.items():
        found = get("/api/rules/search", languages="java", cwe=cwe, ps=100)
        offered[kind] = sorted({(r["key"], r.get("type"), r.get("status")) for r in found["rules"]})
    repositories = sorted({r["key"] for r in get("/api/rules/repositories", language="java")["repositories"]})
    adapter = SonarAdapter(URL, token)
    preflight = {kind: outcome(lambda rule=rule: adapter.preflight(status["version"], rule)) for kind, rule in RULES.items()}
    record("check", {"server": status, "required_rules": rules, "java_rule_repositories": repositories,
                     "offered_for_family": {k: [{"key": r[0], "type": r[1], "status": r[2]} for r in v] for k, v in offered.items()},
                     "adapter_preflight": preflight, "checked_at": time.time()})


def job():
    tokens = json.loads((FOLDER / "tokens.json").read_text(encoding="utf-8"))
    base = setting("SAFEPATCH_URL", "http://127.0.0.1:8100")
    started = time.time()
    j = request(base + "/v1/jobs", "POST", token=tokens["developer"], body={"case_id": "sql-01", "scanner": "sonarqube+semgrep", "max_attempts": 1,
                                                                             "memory_mode": "off", "idempotency_key": uuid.uuid4().hex})
    while j["status"] in ("queued", "scanning", "patching", "verifying") and time.time() - started < 900:
        time.sleep(3)
        j = request(base + "/v1/jobs/" + j["id"], token=tokens["developer"])
    record("job", {"job": j["id"], "status": j["status"], "reason": j.get("reason"), "attempts": len(j.get("attempts", [])),
                   "events": [e["status"] for e in j.get("events", [])], "seconds": round(time.time() - started, 1)})


def scan(server_jre=False):
    from safepatch.repository import baseline, registry
    from safepatch.runner import checkout, maven
    from safepatch.scanner import SonarAdapter
    token = secret("SONAR_TOKEN")
    case = registry()[1]["sql-01"]
    spec = baseline("sql-01", case["commit"])[0]["spec"]
    workspace = runtime("sonar-live") / uuid.uuid4().hex[:12]
    checkout("sql-01", case["commit"], workspace)
    deadline = time.time() + 900
    build = maven(workspace, [*spec.build.reactor(), *spec.build.package_goals], deadline)
    key = f"bigg-live-{uuid.uuid4().hex[:8]}"
    # The first run fetches the pinned Sonar Maven plugin into the offline cache (approved 30 Oct).
    goal = ["org.sonarsource.scanner.maven:sonar-maven-plugin:5.1.0.4751:sonar", "-Dsonar.projectKey=" + key, "-Dsonar.scm.revision=" + case["commit"],
            "-Dsonar.host.url=" + URL, "-Dsonar.scanner.skipJreProvisioning=" + ("false" if server_jre else "true")]
    # 26.x scanners need Java 21; with server_jre the scanner takes it from the Sonar server itself
    # (the image ships the JREs in /opt/sonarqube/jres), never from the internet.
    online = not (Path(setting("MAVEN_CACHE", str(ROOT / ".runtime/m2"))) / "org/sonarsource/scanner/maven/sonar-maven-plugin/5.1.0.4751").exists()
    started = time.time()
    result = maven(workspace, goal, deadline, {"SONAR_TOKEN": token, "SONAR_USER_HOME": str(runtime("sonar-cache"))}, online=online, limit=600)
    collected = outcome(lambda: SonarAdapter(URL, token).collect(workspace / "target/sonar/report-task.txt", key, case["commit"], deadline)) if not result["exit_code"] else None
    tail = [line for line in result["output"].splitlines() if "ERROR" in line or "WARN" in line][-15:]
    summary = None
    if collected and collected["ok"]:
        c = collected["result"]
        summary = {"quality_gate": c["quality_gate"], "vulnerabilities": len(c["findings"]), "findings": c["findings"],
                   "hotspots": [{k: h.get(k) for k in ("ruleKey", "securityCategory", "vulnerabilityProbability", "line", "component")} for h in c["security_hotspots"].get("hotspots", [])]}
    record("scan", {"project_key": key, "build_exit": build["exit_code"], "plugin_fetched_online": online, "jre_from_sonar_server": server_jre,
                    "sonar_goal_exit": result["exit_code"],
                    "sonar_goal_seconds": round(time.time() - started, 1), "maven_warnings_and_errors": tail,
                    "collect": {k: v for k, v in (collected or {}).items() if k != "result"} if collected else None, "collected": summary})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("action", choices=("setup", "check", "job", "scan"))
    parser.add_argument("--label", default="", help="a second record of the same step, e.g. after a fix")
    parser.add_argument("--server-jre", action="store_true", help="scan: let the scanner take Java 21 from the Sonar server")
    args = parser.parse_args(argv)
    global LABEL
    LABEL = args.label
    if args.action == "scan":
        return scan(args.server_jre)
    {"setup": setup, "check": check, "job": job}[args.action]()


if __name__ == "__main__":
    main()
