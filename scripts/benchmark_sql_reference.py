"""Reference fixes for the OWASP Benchmark SQL cases whose answer echoes the query (L3; ROADMAP.md week 6).

BenchmarkTest00196 and BenchmarkTest01097 write the query they ran into every answer to the
behaviour test's input, so before 26 October the behaviour test refused any parameterised fix
there. Each gets a plain parameterised fix, built here from one-line replacements (Benchmark's
code stays out of this repository), verified like a candidate (policy, sandbox build, behaviour,
witness) and then given the hidden tests. Both must pass.

Needs PROJECTS_DIR=.runtime/l3/projects SAFEPATCH_PROFILE=evaluation RUNNER_SANDBOX=docker
SANDBOX_MAVEN_CACHE=<wsl path>. Writes benchmark-sql-reference.json to EVIDENCE_DIR.
"""
import json
from pathlib import Path
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from safepatch import runner
from safepatch.common import Patch, VerifyRequest, digest, evidence, setting
from safepatch.repository import baseline, project, registry
from l3_hidden import hidden_result

# case -> [(line of the original, its parameterised replacement)]
FIXES = {
    "owasp-benchmark-01097": [
        ("""        String sql = "INSERT INTO users (username, password) VALUES ('foo','" + bar + "')";\n""",
         """        String sql = "INSERT INTO users (username, password) VALUES ('foo',?)";\n"""),
        ("""            java.sql.Statement statement =\n                    org.owasp.benchmark.helpers.DatabaseHelper.getSqlStatement();\n"""
         """            int count = statement.executeUpdate(sql);\n""",
         """            java.sql.PreparedStatement statement =\n                    org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection().prepareStatement(sql);\n"""
         """            statement.setString(1, bar);\n            int count = statement.executeUpdate();\n"""),
    ],
    "owasp-benchmark-00196": [
        ("""            String sql = "SELECT * from USERS where USERNAME='foo' and PASSWORD='" + bar + "'";\n""",
         """            String sql = "SELECT * from USERS where USERNAME='foo' and PASSWORD=?";\n"""),
        ("""            org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.execute(sql);\n""",
         """            org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.queryForList(sql, bar);\n"""),
    ],
}


def fixed(source, replacements):
    for old, new in replacements:
        if source.count(old) != 1:
            raise SystemExit("the original line is not where the fix expects it: " + old.strip()[:60])
        source = source.replace(old, new)
    return source


def suites(result):
    return {s: {k: (result.get(s) or {}).get(k) for k in ("tests", "failures", "errors")} for s in ("behavior", "security")}


def main():
    for name, value in (("SAFEPATCH_PROFILE", "evaluation"), ("RUNNER_SANDBOX", "docker")):
        if setting(name) != value:
            raise SystemExit(f"set {name}={value}")
    out = evidence("benchmark-sql-reference.json")
    if out.exists():
        raise SystemExit("Use a fresh EVIDENCE_DIR; evidence is never overwritten")
    rows = []
    for case, replacements in FIXES.items():
        commit = registry()[1][case]["commit"]
        target = project(case, commit).scan.known[0].file
        _, tracked = baseline(case, commit)
        content = fixed(tracked[target], replacements)
        patch = Patch.model_validate({"edits": [{"path": target, "old_sha256": digest(tracked[target]), "content": content}],
                                      "rationale": "reference parameterised fix"})
        result = runner.execute(VerifyRequest(job_id=uuid.uuid4().hex, case_id=case, base_commit=commit, attempt=1,
                                              deadline=time.time() + 1800, scanner="known", patch=patch, target_file=target))
        hidden = hidden_result(case, commit, {target: content})
        row = {"case": case, "commit": commit, "fix_sha256": digest(content), "passed": result["passed"], "code": result["feedback"]["code"],
               **suites(result), "hidden": {k: hidden.get(k) for k in ("passed", "tests", "failures", "errors")}}
        row["as_expected"] = bool(row["passed"] and row["hidden"]["passed"])
        rows.append(row)
        print(json.dumps({k: row[k] for k in ("case", "passed", "code", "behavior", "security", "hidden")}), flush=True)
    out.write_text(json.dumps({"cases": len(rows), "as_expected": sum(r["as_expected"] for r in rows), "rows": rows}, indent=2) + "\n", encoding="utf-8")
    print("as expected", sum(r["as_expected"] for r in rows), "of", len(rows), "; written:", out)


if __name__ == "__main__":
    main()
