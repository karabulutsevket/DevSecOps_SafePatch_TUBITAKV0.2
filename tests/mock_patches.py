"""Known repairs ONLY for deterministic tests. Never mount in worker1/model image."""
from safepatch.common import SOURCE, Patch, digest


def correct_patch(kind, files):
    old = files[SOURCE]
    if kind == "sql":
        content = old.replace('"SELECT name FROM accounts WHERE name = \'" + input + "\'"', '"SELECT name FROM accounts WHERE name = ?"')
        content = content.replace('try (Statement statement = conn.createStatement(); ResultSet rows = statement.executeQuery(sql)) {\n                while (rows.next()) names.add(rows.getString(1));\n            }', 'try (PreparedStatement statement = conn.prepareStatement(sql)) {\n                statement.setString(1, input);\n                try (ResultSet rows = statement.executeQuery()) {\n                    while (rows.next()) names.add(rows.getString(1));\n                }\n            }')
    elif kind == "path":
        content = old.replace('Path.of(System.getProperty("demo.root"))', 'Path.of(System.getProperty("demo.root")).toRealPath()').replace('root.resolve(input);', 'root.resolve(input).toRealPath();\n        if (!target.startsWith(root)) { throw new SecurityException("outside root"); }')
    else:
        content = old.replace('new ProcessBuilder(shell, flag, command)', 'new ProcessBuilder(java, "-cp", System.getProperty("java.class.path"), "demo.EchoMain", input)')
    return Patch.model_validate({"edits": [{"path": SOURCE, "old_sha256": digest(old), "content": content}], "rationale": "MOCK TEST ONLY: known reference repair"})
