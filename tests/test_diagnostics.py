"""Compiler diagnostics as the model sees them after a failed build (runner.diagnostics)."""
from safepatch import runner

SOURCE = "src/main/java/demo/DemoService.java"
CODE = "package demo;\npublic class DemoService {\n    void x() {\n        Path path = Paths.get(name);\n    }\n}\n"


def workspace(tmp_path):
    file = tmp_path / SOURCE
    file.parent.mkdir(parents=True)
    file.write_text(CODE, encoding="utf-8")
    return tmp_path


def test_old_plugins_lose_the_symbol_so_it_is_read_from_the_source(tmp_path):
    # maven-compiler-plugin 2.3.2 in the JDK 8 sandbox: no "symbol:" line, 0-based columns.
    output = (f"[ERROR] /workspace/{SOURCE}:[4,8] error: cannot find symbol\n[ERROR]  class DemoService\n"
              f"/workspace/{SOURCE}:[4,20] error: cannot find symbol\n")
    assert runner.diagnostics(output, workspace(tmp_path)) == [f"[ERROR] {SOURCE}:[4,8] error: cannot find symbol: Path"]


def test_native_paths_become_repository_relative_and_repeats_are_dropped(tmp_path):
    ws = workspace(tmp_path)
    native = "/" + ws.resolve().as_posix() + "/" + SOURCE
    output = f"[ERROR] {native}:[4,21] cannot find symbol\r\n[ERROR] {native}:[4,21] cannot find symbol\r\n[ERROR] {native}:[5,1] ';' expected\n"
    found = runner.diagnostics(output, ws)
    assert found == [f"[ERROR] {SOURCE}:[4,21] cannot find symbol: Paths", f"[ERROR] {SOURCE}:[5,1] ';' expected"]
    assert not any(ws.resolve().as_posix() in line for line in found)


def test_an_unknown_path_keeps_only_its_file_name_and_no_symbol_outside_the_workspace(tmp_path):
    output = "[ERROR] /elsewhere/secret/Other.java:[1,1] cannot find symbol\n[ERROR] /workspace/../x/Y.java:[1,1] cannot find symbol\n"
    assert runner.diagnostics(output, workspace(tmp_path)) == ["[ERROR] Other.java:[1,1] cannot find symbol", "[ERROR] ../x/Y.java:[1,1] cannot find symbol"]


def test_at_most_four_diagnostics(tmp_path):
    output = "".join(f"[ERROR] /workspace/{SOURCE}:[{n},1] error {n}\n" for n in range(1, 9))
    assert len(runner.diagnostics(output, workspace(tmp_path))) == 4
