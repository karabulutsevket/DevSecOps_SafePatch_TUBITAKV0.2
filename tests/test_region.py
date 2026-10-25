"""Region-based editing (roadmap week 5): the model sees the methods holding the findings of a
file too large to show whole; trusted code puts its answer back into the whole file."""
import pytest

from safepatch.policy import PolicyError
from safepatch.region import RegionPatch, region_view, splice

PATH = "src/main/java/demo/Archive.java"
SOURCE = """package demo;

import java.io.File;
import java.io.IOException;

public class Archive {
    private final File root = new File("x");

    public static class Unpacker {
        private final File outputDir;

        Unpacker(File outputDir) {
            this.outputDir = outputDir;
        }

        public File target(String name) throws IOException {
            File file = new File(outputDir, name);
            return file;
        }
    }

    public File other(String name) {
        Runnable task = new Runnable() {
            public void run() {
                new File(root, name).delete();
            }
        };
        task.run();
        return new File(root, name);
    }
}
"""
LINES = SOURCE.splitlines()


def line(text):
    return next(i for i, value in enumerate(LINES, 1) if text in value)


def answer(*regions, imports=()):
    return RegionPatch.model_validate({"regions": [{"region": r, "content": c} for r, c in regions], "imports": list(imports), "rationale": "MOCK TEST ONLY"})


def test_the_view_is_the_method_holding_the_finding():
    view = region_view(PATH, SOURCE, [line("File file = new File(outputDir")])
    [region] = view["regions"]
    assert (region["start_line"], region["end_line"]) == (line("public File target"), line("return file;") + 1)
    assert (region["enclosing"], region["member"]) == ("Archive > Unpacker", "target")
    assert region["content"].startswith("        public File target") and region["content"].endswith("}\n")
    assert view["imports"] == ["import java.io.File;", "import java.io.IOException;"]


def test_findings_in_one_method_share_a_region_and_regions_follow_the_file():
    view = region_view(PATH, SOURCE, [line("return new File(root"), line("File file = new File"), line("return file;")])
    assert [(r["id"], r["member"]) for r in view["regions"]] == [(1, "target"), (2, "other")]


def test_a_finding_in_an_anonymous_class_takes_the_enclosing_method():
    [region] = region_view(PATH, SOURCE, [line("new File(root, name).delete()")])["regions"]
    assert region["member"] == "other" and region["start_line"] == line("public File other")


@pytest.mark.parametrize("lines", [[line("private final File root")], [], [None], [999], [line("File file"), line("private final File root")]])
def test_no_view_outside_methods_or_without_lines(lines):
    assert region_view(PATH, SOURCE, lines) is None


def test_no_view_of_a_file_that_does_not_parse():
    assert region_view(PATH, SOURCE.replace("public File other(String name) {", "public File other(String name) {{{"), [line("File file")]) is None


def test_splice_replaces_only_the_region_and_adds_imports_after_the_last_one():
    view = region_view(PATH, SOURCE, [line("File file = new File(outputDir"), line("return new File(root")])
    fixed = view["regions"][0]["content"].replace("return file;", "return Path.of(file.getPath()).normalize().toFile();")
    result = splice(SOURCE, view, answer((1, fixed), imports=["import java.nio.file.Path;", "import java.io.File;"]))
    expected = SOURCE.replace("return file;", "return Path.of(file.getPath()).normalize().toFile();").replace(
        "import java.io.IOException;\n", "import java.io.IOException;\nimport java.nio.file.Path;\n")
    assert result == expected


def test_splice_adds_a_final_newline_and_may_grow_a_region():
    view = region_view(PATH, SOURCE, [line("return new File(root")])
    helper = view["regions"][0]["content"] + "\n    private static boolean inside(File f) {\n        return true;\n    }"
    result = splice(SOURCE, view, answer((1, helper)))
    assert result.endswith("    }\n}\n") and "private static boolean inside" in result and result.count("\n") == SOURCE.count("\n") + 4


@pytest.mark.parametrize("bad,code", [
    (lambda: answer((3, "x")), "region_answer_invalid"),
    (lambda: answer((1, "x"), (1, "y")), "region_answer_invalid"),
    (lambda: answer((1, "x"), imports=["import java.io.File; class Evil {}"]), "region_import_invalid"),
    (lambda: answer((1, "x"), imports=["static { System.exit(0); }"]), "region_import_invalid"),
])
def test_splice_refuses_unknown_regions_and_anything_but_import_lines(bad, code):
    view = region_view(PATH, SOURCE, [line("File file = new File(outputDir"), line("return new File(root")])
    with pytest.raises(PolicyError, match=code):
        splice(SOURCE, view, bad())


def test_jdk_types_the_regions_use_are_imported():
    from safepatch.region import complete_imports
    used = 'Path p = Paths.get(name).normalize(); // Files\nString s = "Pattern"; File f = null;'
    content, added = complete_imports(SOURCE, used)
    assert added == ["import java.nio.file.Path;", "import java.nio.file.Paths;"]
    assert content == SOURCE.replace("import java.io.IOException;\n", "import java.io.IOException;\nimport java.nio.file.Path;\nimport java.nio.file.Paths;\n")


@pytest.mark.parametrize("header,used", [
    ("import java.nio.file.*;\n", "Path p;"),                         # wildcard of the package
    ("import org.example.Path;\n", "Path p;"),                        # another type of that name
    ("", "Path p; } class Path {"),                                   # declared in the file
    ("", "Widget w; java.util.List<String> l;"),                      # not a known JDK type; qualified use
])
def test_nothing_is_imported_that_the_file_already_resolves(header, used):
    from safepatch.region import complete_imports
    source = SOURCE.replace("import java.io.File;\n", "import java.io.File;\n" + header)
    if "class Path" in used:
        source = source.replace("public class Archive {", "public class Archive {\n    static class Path {}")
    assert complete_imports(source, used)[1] == []
