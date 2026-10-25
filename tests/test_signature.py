"""Structural signatures are read from the code: sink, construction, source, library and version."""
import importlib.util
from pathlib import Path

import pytest

from safepatch.signature import pom_versions, signature

ROOT = Path(__file__).resolve().parents[1]
FAMILY = {"sql": "CWE-89", "path": "CWE-22", "command": "CWE-78"}
EXPECTED = {
    "sql": ("java.sql.Statement.executeQuery", "concatenation", "method_parameter", "jdbc"),
    "path": ("java.nio.file.Files.readString", "resolve", "method_parameter", "java-io"),
    "command": ("java.lang.ProcessBuilder.<init>", "concatenation", "method_parameter", "java-process"),
}


def seeded(kind, number):
    spec = importlib.util.spec_from_file_location("seed_script", ROOT / "scripts/seed.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.expected_files(kind, number)


@pytest.mark.parametrize("kind", ["sql", "path", "command"])
@pytest.mark.parametrize("number", [1, 2, 3])
@pytest.mark.parametrize("line", [None, 11, 14, 16])
def test_synthetic_cases_have_one_signature_whatever_line_the_scanner_reports(kind, number, line):
    files = seeded(kind, number)
    found = signature(files["src/main/java/demo/DemoService.java"].decode(), FAMILY[kind], line, files["pom.xml"])
    assert (found["sink"], found["construction"], found["source"], found["library"], found["library_version"]) == (*EXPECTED[kind], None)


POM = """<project xmlns="http://maven.apache.org/POM/4.0.0"><properties><spring.version>6.1.14</spring.version></properties>
<dependencies>
  <dependency><groupId>org.springframework</groupId><artifactId>spring-jdbc</artifactId><version>${spring.version}</version></dependency>
  <dependency><groupId>org.postgresql</groupId><artifactId>postgresql</artifactId><version>42.7.4</version></dependency>
  <dependency><groupId>org.hibernate.orm</groupId><artifactId>hibernate-core</artifactId></dependency>
</dependencies></project>"""

CASES = {
    "spring_format_http": ("CWE-89", """package app;
import org.springframework.jdbc.core.JdbcTemplate;
import jakarta.servlet.http.HttpServletRequest;
public class Accounts {
    private final JdbcTemplate jdbc;
    Accounts(JdbcTemplate jdbc) { this.jdbc = jdbc; }
    public Object find(HttpServletRequest request) {
        String name = request.getParameter("name");
        String sql = String.format("SELECT * FROM a WHERE n = '%s'", name);
        return jdbc.queryForList(sql);
    }
}""", ("org.springframework.jdbc.core.JdbcTemplate.queryForList", "format", "http_request", "spring-jdbc", "6.1.14")),
    "prepare_with_concatenation": ("CWE-89", """import java.sql.*;
class Repo {
    ResultSet byId(Connection conn, String id) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM t WHERE id = " + id);
        return ps.executeQuery();
    }
}""", ("java.sql.Connection.prepareStatement", "concatenation", "method_parameter", "jdbc", None)),
    "string_builder": ("CWE-89", """import java.sql.Statement;
class Repo {
    void find(Statement stmt, String name) throws Exception {
        StringBuilder sb = new StringBuilder("SELECT * FROM t WHERE n = '");
        sb.append(name).append("'");
        stmt.executeQuery(sb.toString());
    }
}""", ("java.sql.Statement.executeQuery", "string_builder", "method_parameter", "jdbc", None)),
    "runtime_exec": ("CWE-78", """class Ping {
    Process ping(String host) throws Exception {
        String cmd = "ping -c 1 " + host;
        return Runtime.getRuntime().exec(cmd);
    }
}""", ("java.lang.Runtime.exec", "concatenation", "method_parameter", "java-process", None)),
    "nio_paths_get": ("CWE-22", """import java.nio.file.*;
class Store {
    byte[] read(String name) throws Exception {
        return Files.newInputStream(Paths.get("/srv/data", name)).readAllBytes();
    }
}""", ("java.nio.file.Files.newInputStream", "resolve", "method_parameter", "java-io", None)),
    "file_input_stream": ("CWE-22", """import java.io.*;
class Store {
    InputStream open(String base, String name) throws IOException {
        return new FileInputStream(base + "/" + name);
    }
}""", ("java.io.FileInputStream.<init>", "concatenation", "method_parameter", "java-io", None)),
    "weak_random": ("CWE-330", """import java.util.Random;
class Tokens {
    int next() { return new Random().nextInt(); }
}""", ("java.util.Random.<init>", "none", "unknown", "java-random", None)),
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_signature_of_common_java_shapes(name):
    family, code, expected = CASES[name]
    found = signature(code, family, None, POM)
    assert (found["sink"], found["construction"], found["source"], found["library"], found["library_version"]) == expected
    assert found["schema"] == "safepatch-signature/1"


@pytest.mark.parametrize("family,code", [
    ("CWE-89", "class A { int f(int x) { return x + 1; } }"),          # no sink in the code
    ("CWE-79", "class A { void f(String s) { System.out.println(s); } }"),  # no sink table for the family
    (None, "class A {}"),
    ("CWE-89", ""),
])
def test_no_sink_means_no_signature(family, code):
    assert signature(code, family, None, None) is None


def test_pom_versions_resolve_properties_and_mark_managed():
    assert pom_versions(POM) == {"org.springframework:spring-jdbc": "6.1.14", "org.postgresql:postgresql": "42.7.4", "org.hibernate.orm:hibernate-core": "managed"}
    assert pom_versions(b"not xml") == {} and pom_versions(None) == {}
