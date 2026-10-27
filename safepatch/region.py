"""Region-based editing (roadmap week 5): how the model sees a file too large to show whole.

The view is the methods (or constructors, initializers) that contain the job's findings, in
file order, with their line range, enclosing classes and the file's imports. The model returns
the new text of the regions it changes and any import lines it adds; `splice` puts them back
into the whole file. Policy and verification then judge that whole-file patch like any other:
regions are about what fits in the model's context, not a security boundary.
"""
import re

from pydantic import Field

from safepatch.common import MODEL_REGION_CHARS, Strict
from safepatch.policy import PolicyError
from safepatch.signature import PARSER

MEMBERS = ("method_declaration", "constructor_declaration", "compact_constructor_declaration", "static_initializer")
TYPES = ("class_declaration", "interface_declaration", "enum_declaration", "record_declaration")
IMPORT = re.compile(r"import (static )?[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*(\.\*)?;")


class Region(Strict):
    id: int = Field(ge=1, le=8)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    enclosing: str = Field(max_length=300)
    member: str = Field(max_length=200)
    content: str = Field(max_length=MODEL_REGION_CHARS)


class RegionSource(Strict):
    path: str = Field(max_length=300)
    imports: list[str] = Field(default_factory=list, max_length=200)
    regions: list[Region] = Field(min_length=1, max_length=8)


class RegionEdit(Strict):
    region: int = Field(ge=1, le=8)
    content: str = Field(max_length=24000)


class RegionPatch(Strict):
    """The model's answer in region mode: only the regions it changes."""
    regions: list[RegionEdit] = Field(min_length=1, max_length=8)
    imports: list[str] = Field(default_factory=list, max_length=5)
    rationale: str = Field(max_length=1600)


def member_at(root, text, line):
    """The outermost method-like member containing `line` (1-based), or None."""
    content = text[line - 1]
    column = len(content[:len(content) - len(content.lstrip())].encode("utf-8"))
    node, found = root.descendant_for_point_range((line - 1, column), (line - 1, column)), None
    while node is not None:
        if node.type in MEMBERS:
            found = node
        node = node.parent
    return found


def enclosing(node):
    names = []
    while (node := node.parent) is not None:
        if node.type in TYPES and node.child_by_field_name("name") is not None:
            names.append(node.child_by_field_name("name").text.decode("utf-8"))
    return " > ".join(reversed(names))


def region_view(path, source, lines):
    """{"path", "imports", "regions"} for the members containing `lines`, or None when a line lies
    outside every member (a field initializer, say), two regions share a line, or the file does
    not parse."""
    text = source.splitlines(True)
    lines = sorted({line for line in lines if line})
    tree = PARSER.parse(source.encode("utf-8"))
    if not lines or tree.root_node.has_error or not all(1 <= line <= len(text) for line in lines):
        return None
    spans = {}
    for line in lines:
        node = member_at(tree.root_node, text, line)
        if node is None:
            return None
        spans[(node.start_point[0] + 1, node.end_point[0] + 1)] = node
    regions, end = [], 0
    for number, ((first, last), node) in enumerate(sorted(spans.items()), 1):
        if first <= end:
            return None
        name = node.child_by_field_name("name")
        regions.append({"id": number, "start_line": first, "end_line": last, "enclosing": enclosing(node),
                        "member": name.text.decode("utf-8") if name else node.type, "content": "".join(text[first - 1:last])})
        end = last
    if len(regions) > 8:
        return None
    return {"path": path, "imports": [line.strip() for line in text if line.startswith("import ")], "regions": regions}


def splice(source, view, answer):
    """The whole file with the answer's regions and imports put in; anything else is refused."""
    regions = {r["id"]: r for r in view["regions"]}
    numbers = [edit.region for edit in answer.regions]
    if len(set(numbers)) != len(numbers) or not set(numbers) <= set(regions):
        raise PolicyError("region_answer_invalid")
    added = []
    for line in (line.strip() for line in answer.imports):
        if not IMPORT.fullmatch(line):
            raise PolicyError("region_import_invalid")
        if line not in view["imports"] and line + "\n" not in added:
            added.append(line + "\n")
    text = source.splitlines(True)
    for edit in sorted(answer.regions, key=lambda e: regions[e.region]["start_line"], reverse=True):
        region = regions[edit.region]
        content = edit.content if edit.content.endswith("\n") else edit.content + "\n"
        text[region["start_line"] - 1:region["end_line"]] = content.splitlines(True)
    return insert_imports(text, added)


def insert_imports(text, lines):
    """Lines (with newlines) put after the last import, else after the package line."""
    anchor = max((i for i, line in enumerate(text) if line.startswith("import ")), default=None)
    if anchor is None:
        anchor = next((i for i, line in enumerate(text) if line.startswith("package ")), -1)
    text[anchor + 1:anchor + 1] = lines
    return "".join(text)


# JDK types a repair commonly needs, by simple name. Import completion adds only these: the
# 7B model leaves the answer's `imports` empty (region-mode development cases, 25 Oct 2026).
JDK_TYPES = {name: package + "." + name for package, names in {
    "java.io": ("File", "IOException", "UncheckedIOException", "InputStream", "OutputStream", "FileInputStream", "FileOutputStream",
                "Writer", "OutputStreamWriter", "BufferedReader", "InputStreamReader"),
    "java.nio.file": ("Path", "Paths", "Files", "LinkOption", "StandardCopyOption", "StandardOpenOption", "NoSuchFileException",
                      "InvalidPathException", "AccessDeniedException"),
    "java.nio.charset": ("StandardCharsets", "Charset"),
    "java.sql": ("Connection", "DriverManager", "PreparedStatement", "ResultSet", "SQLException", "Statement"),
    "java.util": ("List", "ArrayList", "Arrays", "Collections", "Map", "HashMap", "LinkedHashMap", "Set", "HashSet", "Objects", "Optional", "Locale"),
    "java.util.regex": ("Pattern", "Matcher"),
    "java.util.concurrent": ("TimeUnit",),
}.items() for name in names}
NOISE = re.compile(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])+\'|//[^\n]*|/\*.*?\*/', re.S)


def complete_imports(content, changed):
    """`content` with imports added for JDK types that `changed` uses but the file does not
    resolve: no import of that name or of its package's wildcard, and no type of that name
    declared in the file. Returns (content, added)."""
    imports = [line.strip() for line in content.splitlines() if line.startswith("import ")]
    # A name after a dot is qualified (java.util.List) or nested (Outer.Inner): not imported.
    used = set(re.findall(r"(?<![.\w])[A-Z][A-Za-z0-9_]*\b", NOISE.sub(" ", changed)))
    added = []
    for name in sorted(used & set(JDK_TYPES)):
        qualified = JDK_TYPES[name]
        if any(line.endswith("." + name + ";") or line == "import " + qualified.rsplit(".", 1)[0] + ".*;" for line in imports):
            continue
        if re.search(r"\b(class|interface|enum|record)\s+" + name + r"\b", NOISE.sub(" ", content)):
            continue
        added.append("import " + qualified + ";")
    return insert_imports(content.splitlines(True), [line + "\n" for line in added]), added
