"""Structural signature of a finding, read from the code rather than from the scanner.

What memory compares when the code differs (roadmap week 4): which call is the sink,
how the value reaching it was built, where that value came from, and which library
provides the sink, with the library's version from pom.xml. Syntax only
(tree-sitter-java): names are qualified through the file's imports, nothing is
type-checked. A finding whose sink cannot be found has no signature, and memory
treats it as `unknown`.
"""
import re
import xml.etree.ElementTree as ET

import tree_sitter_java
from tree_sitter import Language, Parser

PARSER = Parser(Language(tree_sitter_java.language()))
SCHEMA = "safepatch-signature/1"

# Sink calls per CWE family: method names, and "<init>" entries for constructors.
SINKS = {
    "CWE-89": {"executeQuery", "executeUpdate", "execute", "executeLargeUpdate", "addBatch", "prepareStatement", "prepareCall",
               "query", "queryForObject", "queryForList", "queryForMap", "queryForRowSet", "update", "batchUpdate",
               "createQuery", "createNativeQuery", "createSQLQuery"},
    "CWE-22": {"readString", "readAllBytes", "readAllLines", "lines", "newInputStream", "newBufferedReader", "newOutputStream",
               "newBufferedWriter", "write", "writeString", "delete", "copy", "move",
               "File.<init>", "FileInputStream.<init>", "FileReader.<init>", "FileOutputStream.<init>", "FileWriter.<init>"},
    "CWE-78": {"exec", "command", "ProcessBuilder.<init>"},
    "CWE-330": {"Random.<init>", "random"},
}
# Simple type name -> package, for wildcard imports and java.lang. Unknown names stay unqualified.
KNOWN_TYPES = {
    "java.sql": {"Statement", "PreparedStatement", "CallableStatement", "Connection", "DriverManager", "ResultSet"},
    "java.nio.file": {"Files", "Path", "Paths"},
    "java.io": {"File", "FileInputStream", "FileReader", "FileOutputStream", "FileWriter"},
    "java.util": {"Random"},
    "java.lang": {"ProcessBuilder", "Runtime", "Process", "String", "StringBuilder", "Math", "System"},
    "org.springframework.jdbc.core": {"JdbcTemplate", "NamedParameterJdbcTemplate"},
    "jakarta.persistence": {"EntityManager"}, "javax.persistence": {"EntityManager"},
}
# Package prefix -> library label and the Maven artifacts whose version identifies it.
LIBRARIES = [
    ("org.springframework.jdbc", "spring-jdbc", ("org.springframework:spring-jdbc", "org.springframework.boot:spring-boot-starter-jdbc")),
    ("jakarta.persistence", "jpa", ("jakarta.persistence:jakarta.persistence-api", "org.hibernate.orm:hibernate-core")),
    ("javax.persistence", "jpa", ("javax.persistence:javax.persistence-api", "org.hibernate:hibernate-core")),
    ("org.hibernate", "hibernate", ("org.hibernate.orm:hibernate-core", "org.hibernate:hibernate-core")),
    ("java.sql", "jdbc", ()), ("java.nio.file", "java-io", ()), ("java.io", "java-io", ()),
    ("java.lang.ProcessBuilder", "java-process", ()), ("java.lang.Runtime", "java-process", ()), ("java.util.Random", "java-random", ()),
]
DECLARATIONS = ("local_variable_declaration", "field_declaration", "resource", "formal_parameter")


def text(node):
    return node.text.decode("utf-8", "replace") if node is not None else ""


def walk(node):
    yield node
    for child in node.children:
        yield from walk(child)


def imports(root):
    """Explicit imports by simple name, and wildcard packages."""
    explicit, wildcard = {}, ["java.lang"]
    for node in root.children:
        if node.type == "import_declaration" and "static" not in text(node).split():
            name = next((text(c) for c in node.named_children if c.type in ("scoped_identifier", "identifier")), "")
            if any(c.type == "asterisk" for c in node.children):
                wildcard.append(name)
            elif name:
                explicit[name.rsplit(".", 1)[-1]] = name
    return explicit, wildcard


def qualify(simple, explicit, wildcard):
    simple = simple.split("<", 1)[0]
    if simple in explicit:
        return explicit[simple]
    package = next((p for p in wildcard if simple in KNOWN_TYPES.get(p, ())), None)
    return package + "." + simple if package else simple


def declarations(method):
    """Name -> (type text, value node, kind) for parameters and variables of one method."""
    found = {}
    for node in walk(method):
        if node.type == "formal_parameter":
            found[text(node.child_by_field_name("name"))] = (text(node.child_by_field_name("type")), None, "parameter")
        elif node.type == "resource":
            found[text(node.child_by_field_name("name"))] = (text(node.child_by_field_name("type")), node.child_by_field_name("value"), "variable")
        elif node.type == "local_variable_declaration":
            kind = text(node.child_by_field_name("type"))
            for declarator in node.children_by_field_name("declarator"):
                found[text(declarator.child_by_field_name("name"))] = (kind, declarator.child_by_field_name("value"), "variable")
        elif node.type == "method_invocation" and text(node.child_by_field_name("name")) in ("append", "insert"):
            # Builders receive their content after the declaration: sb.append(name).append("'").
            target = node.child_by_field_name("object")
            while target is not None and target.type == "method_invocation":
                target = target.child_by_field_name("object")
            if target is not None and target.type == "identifier":
                found.setdefault(("appended", text(target)), []).append(node.child_by_field_name("arguments"))
    return found


def fields(root):
    found = {}
    for node in walk(root):
        if node.type == "field_declaration":
            for declarator in node.children_by_field_name("declarator"):
                found[text(declarator.child_by_field_name("name"))] = (text(node.child_by_field_name("type")), declarator.child_by_field_name("value"), "field")
    return found


def method_of(node):
    while node is not None and node.type not in ("method_declaration", "constructor_declaration", "lambda_expression"):
        node = node.parent
    return node


def call_name(node):
    """'executeQuery' for a method call, 'ProcessBuilder.<init>' for a constructor call."""
    if node.type == "method_invocation":
        return text(node.child_by_field_name("name"))
    return text(node.child_by_field_name("type")).split("<", 1)[0].rsplit(".", 1)[-1] + ".<init>"


def receiver_type(node, scope, explicit, wildcard):
    if node.type == "object_creation_expression":
        return qualify(text(node.child_by_field_name("type")), explicit, wildcard)
    receiver = node.child_by_field_name("object")
    if receiver is None:
        return None
    if receiver.type == "identifier" and text(receiver) in scope:
        return qualify(scope[text(receiver)][0], explicit, wildcard)
    if receiver.type == "identifier" and text(receiver)[:1].isupper():
        return qualify(text(receiver), explicit, wildcard)          # static call on a type
    if receiver.type == "method_invocation" and text(receiver.child_by_field_name("name")) == "getRuntime":
        return "java.lang.Runtime"
    return None


def construction(node, scope, depth=0):
    """How a value was built, following local variables a few steps back."""
    if node is None or depth > 4:
        return "other"
    if node.type == "parenthesized_expression":
        return construction(node.named_children[0], scope, depth)
    if node.type == "identifier":
        name = text(node)
        if name in scope:
            kind, value, origin = scope[name]
            return "direct" if origin == "parameter" or value is None else construction(value, scope, depth + 1)
        return "other"
    if node.type == "binary_expression" and text(node.child_by_field_name("operator")) == "+":
        return "concatenation"
    if node.type == "string_literal":
        return "literal"
    if node.type == "method_invocation":
        name, target = text(node.child_by_field_name("name")), node.child_by_field_name("object")
        if name in ("format", "formatted"):
            return "format"
        if name == "toString" and target is not None and "StringBuilder" in text(target) + construction_hint(target, scope):
            return "string_builder"
        if name in ("resolve", "get", "of"):
            return "resolve"
    if node.type == "object_creation_expression" and "StringBuilder" in text(node.child_by_field_name("type")):
        return "string_builder"
    return "other"


def construction_hint(node, scope):
    """The declared type of an identifier, e.g. a StringBuilder variable later turned into a String."""
    return scope[text(node)][0] if node.type == "identifier" and text(node) in scope else ""


SOURCES = {"getParameter": "http_request", "getHeader": "http_request", "getQueryString": "http_request", "getCookies": "http_request",
           "getenv": "environment", "getProperty": "system_property"}
# Most attacker-controllable first: a value built from several sources is labelled by the strongest.
RANK = ("http_request", "method_parameter", "environment", "system_property")


def is_method_name(node):
    name = node.parent.child_by_field_name("name") if node.parent is not None and node.parent.type == "method_invocation" else None
    return name is not None and name.start_byte == node.start_byte


def sources(node, scope, depth=0):
    """Every external origin a value depends on, following local variables a few steps back."""
    found = set()
    if node is None or depth > 4:
        return found
    for child in walk(node):
        if child.type == "identifier" and text(child) in scope and not is_method_name(child):
            kind, value, origin = scope[text(child)]
            found |= {"method_parameter"} if origin == "parameter" else sources(value, scope, depth + 1)
            for appended in scope.get(("appended", text(child)), []):
                found |= sources(appended, scope, depth + 1)
        elif child.type == "method_invocation" and text(child.child_by_field_name("name")) in SOURCES:
            found.add(SOURCES[text(child.child_by_field_name("name"))])
    return found


def source(node, scope):
    found = sources(node, scope)
    return next((s for s in RANK if s in found), None)


def tainted_argument(node, scope):
    """The argument fed by the most attacker-controllable source (the first one when none is)."""
    arguments = node.child_by_field_name("arguments")
    candidates = arguments.named_children if arguments is not None else []
    rank = lambda a: RANK.index(source(a, scope)) if source(a, scope) else len(RANK)
    return min(candidates, key=rank) if candidates else None


def library(sink):
    return next(((label, artifacts) for prefix, label, artifacts in LIBRARIES if sink.startswith(prefix)), (None, ()))


def pom_versions(pom):
    """groupId:artifactId -> version from a pom.xml (direct versions and ${property} references)."""
    try:
        root = ET.fromstring(pom)
    except (ET.ParseError, TypeError):
        return {}
    ns = {"m": root.tag[1:].split("}")[0]} if root.tag.startswith("{") else {}
    tag = lambda name: ("m:" + name) if ns else name
    properties = {child.tag.split("}")[-1]: (child.text or "").strip() for child in root.findall(tag("properties") + "/*", ns)}
    versions = {}
    for dependency in root.iter(("{%s}dependency" % ns["m"]) if ns else "dependency"):
        group, artifact, version = (dependency.findtext(tag(n), default="", namespaces=ns).strip() for n in ("groupId", "artifactId", "version"))
        if version.startswith("${"):
            version = properties.get(version[2:-1], "")
        versions[group + ":" + artifact] = version or "managed"
    return versions


def signature(source_text, family, line=None, pom=None):
    """Structural signature of the sink nearest to `line`, or None when no sink is found."""
    sinks = SINKS.get(family)
    if not sinks or not source_text:
        return None
    root = PARSER.parse(source_text.encode("utf-8")).root_node
    explicit, wildcard = imports(root)
    calls = [n for n in walk(root) if n.type in ("method_invocation", "object_creation_expression") and call_name(n) in sinks]
    # Scanners point at slightly different lines (the sink, or the line building its argument), so the
    # reported line picks the method; within it a sink fed from outside wins over one fed by literals.
    if line:
        here = [n for n in calls if (m := method_of(n)) is not None and m.start_point[0] + 1 <= line <= m.end_point[0] + 1]
        calls = here or calls
    if not calls:
        return None
    scopes = {n.start_byte: {**fields(root), **(declarations(method_of(n)) if method_of(n) is not None else {})} for n in calls}
    call = min(calls, key=lambda n: (source(tainted_argument(n, scopes[n.start_byte]), scopes[n.start_byte]) is None,
                                     abs(n.start_point[0] + 1 - line) if line else 0, n.start_byte))
    scope = scopes[call.start_byte]
    owner = receiver_type(call, scope, explicit, wildcard)
    name = call_name(call)
    sink = (owner + "." + name.rsplit(".", 1)[-1]) if owner else name
    if call.type == "object_creation_expression":
        sink = owner + ".<init>"
    argument = tainted_argument(call, scope)
    label, artifacts = library(sink)
    versions = pom_versions(pom) if pom else {}
    version = next((versions[a] for a in artifacts if a in versions), None)
    return {"schema": SCHEMA, "sink": sink, "construction": construction(argument, scope) if argument is not None else "none",
            "source": source(argument, scope) or "unknown", "library": label, "library_version": version}
