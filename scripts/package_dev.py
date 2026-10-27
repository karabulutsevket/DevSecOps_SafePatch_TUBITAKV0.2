"""Package-shaped development cases (ROADMAP.md week 6): a small file in a large package.

OWASP Benchmark keeps each test servlet (about 3 KB) among 2 740 siblings in one package: the
engine's read-only context for a Benchmark job is two unrelated, themselves vulnerable
servlets, and its helpers sit in another package. The L3 run of 26 October 2026 could not show
what that context does, since the old prompt budget dropped it in every attempt. These owned
cases recreate the shape on the development side, where measuring and tuning are allowed:
DemoService (2.6-3.3 KB: a header, an entry point writing an HTML answer, the input routed
through a helper, one vulnerable call) among 40 generated handlers (Case001-Case040, each with
its own vulnerable pattern), so the context the engine picks is the application class and two
unrelated handlers, not the EchoMain helper. The lab's API and tests (samples/tests/<kind>) are
kept, so behaviour and witness are the lab's.

`--prepare` writes repositories and descriptors under .runtime/package-dev (answer-key findings,
lab profile). `--check` verifies natively that each baseline is valid, its reference fix
(samples/package/fixed) passes and the engine's context is the intended one, and writes
package-dev-check.json to EVIDENCE_DIR.
"""
import argparse
import json
from pathlib import Path
import shutil
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from safepatch.common import SOURCE, evidence, setting
from safepatch.engine import read_only_context
from safepatch.project import ProjectSpec, synthetic_descriptor
from safepatch.repository import baseline, registry
from variants_dev import seed_module, verify

FOLDER = ROOT / ".runtime/package-dev"
SAMPLES = ROOT / "samples/package"
PROJECT = "safepatch-package-dev"
# case -> (kind, sink statement, CWE)
CASES = {
    "package-sql-1": ("sql", 'String sql = "SELECT name FROM accounts WHERE name = \'" + bar + "\'";', "CWE-89"),
    "package-sql-2": ("sql", 'String sql = "SELECT name FROM accounts WHERE name = \'" + bar + "\' ORDER BY name";', "CWE-89"),
    "package-path-1": ("path", "Path target = root.resolve(bar);", "CWE-22"),
    "package-path-2": ("path", "File fileTarget = new File(base, bar);", "CWE-22"),
    "package-command-1": ("command", 'String command = "echo echo:" + bar;', "CWE-78"),
    "package-command-2": ("command", "builder.environment().put(VARIABLE, bar);", "CWE-78"),
}
SIBLINGS = 40
# Sized so that the application class and two handlers fill the engine's 8 000-character context.
SIBLING_CHARS = 3600
CONTEXT = ["src/main/java/demo/Application.java", "src/main/java/demo/Case001.java", "src/main/java/demo/Case002.java"]

SIBLING_SINKS = {
    "sql": ('import java.sql.Connection;\nimport java.sql.DriverManager;\nimport java.sql.ResultSet;\nimport java.sql.Statement;\n',
            '        try (Connection conn = DriverManager.getConnection("jdbc:h2:mem:case{n};DB_CLOSE_DELAY=-1");\n'
            '                Statement statement = conn.createStatement()) {{\n'
            '            statement.execute("CREATE TABLE IF NOT EXISTS notes(id INT, body VARCHAR)");\n'
            '            String sql = "SELECT body FROM notes WHERE body = \'" + bar + "\'";\n'
            '            try (ResultSet rows = statement.executeQuery(sql)) {{\n'
            '                return rows.next() ? rows.getString(1) : "";\n'
            '            }}\n'
            '        }}\n'),
    "path": ('import java.nio.file.Files;\nimport java.nio.file.Path;\n',
             '        Path base = Path.of(System.getProperty("java.io.tmpdir"), "case{n}");\n'
             '        return Files.readString(base.resolve(bar));\n'),
    "command": ('import java.nio.charset.StandardCharsets;\n',
                '        Process child = new ProcessBuilder("/bin/sh", "-c", "echo case{n}:" + bar).start();\n'
                '        return new String(child.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();\n'),
}


def sibling(number):
    """Handler CaseNNN: unrelated to DemoService, with a vulnerable call of its own kind."""
    n = f"{number:03d}"
    imports, sink = SIBLING_SINKS[("sql", "path", "command")[number % 3]]
    text = (f"package demo;\n\n{imports}import java.util.Map;\n\n"
            f"// Generated handler {n} of the demo package (SafePatch development case, MIT); unrelated to DemoService.\n"
            f"public class Case{n} {{\n\n"
            f"    public void serve(Map<String, String> request, StringBuilder response) {{\n"
            f"        response.append(\"<!DOCTYPE html>\\n<html>\\n<body>\\n<p>\");\n"
            f"        String value = request.getOrDefault(\"Case{n}\", \"\");\n"
            f"        if (!valid(value)) {{\n"
            f"            response.append(\"Invalid request.</p>\\n</body>\\n</html>\");\n"
            f"            return;\n"
            f"        }}\n"
            f"        try {{\n"
            f"            response.append(\"case{n}: \").append(escape(handle(value)));\n"
            f"        }} catch (Exception e) {{\n"
            f"            response.append(\"Error processing request.\");\n"
            f"        }}\n"
            f"        response.append(\"</p>\\n</body>\\n</html>\");\n"
            f"    }}\n\n"
            f"    public String handle(String input) throws Exception {{\n"
            f"        String bar = doSomething(input == null ? \"\" : input.trim());\n"
            + sink.format(n=n) +
            f"    }}\n\n"
            f"    private static String doSomething(String param) {{\n"
            f"        java.util.HashMap<String, Object> map{n} = new java.util.HashMap<>();\n"
            f"        map{n}.put(\"keyA-{n}\", \"a-Value\");\n"
            f"        map{n}.put(\"keyB-{n}\", param);\n"
            f"        map{n}.put(\"keyC\", \"another-Value\");\n"
            f"        return (String) map{n}.get(\"keyB-{n}\");\n"
            f"    }}\n\n"
            f"    public java.util.List<String> handleAll(java.util.List<String> inputs) {{\n"
            f"        java.util.List<String> answers = new java.util.ArrayList<>();\n"
            f"        for (String input : inputs) {{\n"
            f"            try {{\n"
            f"                answers.add(handle(input));\n"
            f"            }} catch (Exception e) {{\n"
            f"                answers.add(\"\");\n"
            f"            }}\n"
            f"        }}\n"
            f"        return answers;\n"
            f"    }}\n\n"
            f"    public String report(Map<String, String> request) {{\n"
            f"        StringBuilder text = new StringBuilder(\"case{n}\");\n"
            f"        for (Map.Entry<String, String> entry : new java.util.TreeMap<>(request).entrySet()) {{\n"
            f"            text.append(\"; \").append(entry.getKey()).append(\"=\").append(weight(entry.getValue()) % {97 + number});\n"
            f"        }}\n"
            f"        return text.toString();\n"
            f"    }}\n\n"
            f"    private static boolean valid(String value) {{\n"
            f"        return value.length() <= {200 + number} && weight(value) != {number};\n"
            f"    }}\n\n"
            f"    private static int weight(String value) {{\n"
            f"        int total = {number};\n"
            f"        for (char c : value.toCharArray()) {{\n"
            f"            total = total * 31 + c;\n"
            f"        }}\n"
            f"        return total;\n"
            f"    }}\n\n"
            f"    private static String escape(String text) {{\n"
            f"        StringBuilder out = new StringBuilder();\n"
            f"        for (char c : text.toCharArray()) {{\n"
            f"            switch (c) {{\n"
            f"                case '<':\n"
            f"                    out.append(\"&lt;\");\n"
            f"                    break;\n"
            f"                case '>':\n"
            f"                    out.append(\"&gt;\");\n"
            f"                    break;\n"
            f"                case '&':\n"
            f"                    out.append(\"&amp;\");\n"
            f"                    break;\n"
            f"                default:\n"
            f"                    out.append(c);\n"
            f"            }}\n"
            f"        }}\n"
            f"        return out.toString();\n"
            f"    }}\n")
    tail = "}\n"
    missing = SIBLING_CHARS - len(text) - len(tail)
    if missing < 8:
        raise ValueError(f"Case{n} is longer than {SIBLING_CHARS} characters")
    # Notes fill the handler to its fixed size, so the context selection is the same in every case.
    filler, line = "", 0
    while missing - len(filler) >= 87:      # 80-character lines, then one of 7 to 86 characters
        line += 1
        note = f"    // handler {n} note {line:02d}: kept for the package's own bookkeeping, not used by DemoService."
        filler += note[:79] + "\n"
    rest = missing - len(filler)
    filler += "    //" + "-" * (rest - 7) + "\n"
    assert len(text + filler + tail) == SIBLING_CHARS
    return text + filler + tail


def source_name(case):
    return case[len("package-"):] + ".java"


def files(case):
    kind = CASES[case][0]
    template = ROOT / "samples/template"
    out = {p.relative_to(template).as_posix(): p.read_bytes() for p in sorted(template.rglob("*")) if p.is_file()}
    out[SOURCE] = (SAMPLES / source_name(case)).read_bytes()
    for test in sorted((ROOT / "samples/tests" / kind).glob("*.java")):
        out["src/test/java/demo/" + test.name] = test.read_bytes()
    for number in range(1, SIBLINGS + 1):
        out[f"src/main/java/demo/Case{number:03d}.java"] = sibling(number).encode("utf-8")
    return out


def prepare():
    seed = seed_module()
    if FOLDER.exists():
        shutil.rmtree(FOLDER, onerror=seed.writable)
    for case, (kind, sink, cwe) in CASES.items():
        repo = FOLDER / "repos" / case
        repo.mkdir(parents=True)
        content = files(case)
        for path, data in content.items():
            (repo / path).parent.mkdir(parents=True, exist_ok=True)
            (repo / path).write_bytes(data)
        seed.git(repo, "init", "-q")
        seed.git(repo, "add", ".")
        seed.git(repo, "-c", f"user.name={seed.AUTHOR}", "-c", "user.email=synthetic@localhost", "commit", "-qm", f"Package development case {case}")
        commit = seed.git(repo, "rev-parse", "HEAD").decode().strip()
        data = synthetic_descriptor(case, {"kind": kind, "split": "development", "commit": commit, "project": PROJECT}, repo.resolve())
        lines = [i for i, line in enumerate(content[SOURCE].decode("utf-8").splitlines(), 1) if line.strip() == sink]
        assert len(lines) == 1, case
        data["scan"]["known"] = [{"id": f"{case}.1", "file": SOURCE, "line": lines[0], "cwe": cwe, "source": "safepatch-synthetic answer key"}]
        ProjectSpec.model_validate(data)
        (FOLDER / "projects").mkdir(exist_ok=True)
        (FOLDER / "projects" / f"{case}.yml").write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        print(case, "line", lines[0])
    print(f"$env:PROJECTS_DIR = '{(FOLDER / 'projects').resolve()}'; $env:SAFEPATCH_PROFILE = 'lab'")


def check():
    if setting("SAFEPATCH_PROFILE") != "lab" or any(case not in registry()[1] for case in CASES):
        raise SystemExit("set SAFEPATCH_PROFILE=lab and a PROJECTS_DIR registering the package cases (.runtime/package-dev/projects)")
    out = evidence("package-dev-check.json")
    if out.exists():
        raise SystemExit("Use a fresh EVIDENCE_DIR; evidence is never overwritten")
    rows = []
    for case in CASES:
        context = sorted(read_only_context(baseline(case, registry()[1][case]["commit"])[1], SOURCE))
        fixed = (SAMPLES / "fixed" / source_name(case)).read_text(encoding="utf-8")
        row = {"case": case, "context": context, "baseline": verify(case), "reference_fix": verify(case, fixed)}
        row["as_expected"] = bool(row["baseline"]["baseline_valid"] and row["reference_fix"]["passed"] and context == CONTEXT)
        rows.append(row)
        print(json.dumps({"case": case, "as_expected": row["as_expected"]}), flush=True)
    out.write_text(json.dumps({"cases": len(rows), "as_expected": sum(r["as_expected"] for r in rows), "rows": rows}, indent=2) + "\n", encoding="utf-8")
    print("as expected", sum(r["as_expected"] for r in rows), "of", len(rows), "; written:", out)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.prepare:
        prepare()
    if args.check:
        check()


if __name__ == "__main__":
    main()
