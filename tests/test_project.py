import copy

import pytest
from pydantic import ValidationError
import yaml

from safepatch.common import SOURCE
from safepatch.project import ProjectSpec, glob_regex, is_protected, load_project, load_registry, synthetic_descriptor
from safepatch.repository import registry


@pytest.fixture
def descriptor():
    root, cases = registry()
    return synthetic_descriptor("sql-01", cases["sql-01"], root / "sql-01")


def test_seeded_descriptors_reproduce_todays_scope():
    root, cases = registry()
    projects = load_registry(root.parent / "projects")
    assert set(projects) == set(cases)
    for case_id, spec in projects.items():
        assert spec.repository.commit == cases[case_id]["commit"]
        assert spec.is_editable(SOURCE)
        assert not spec.is_editable("src/main/java/demo/EchoMain.java")
        assert spec.labels["kind"] == cases[case_id]["kind"]


@pytest.mark.parametrize("path", ["pom.xml", "module/pom.xml", "src/test/java/demo/SecurityTest.java", "core/src/test/A.java",
                                  ".github/workflows/ci.yml", ".gitlab-ci.yml", "Jenkinsfile", "mvnw", ".mvn/wrapper/x.jar",
                                  "build.gradle", "app/build.gradle.kts", ".git/config", ".semgrep.yml", "sonar-project.properties"])
def test_protection_wins_over_broad_editable_patterns(descriptor, path):
    spec = ProjectSpec.model_validate({**descriptor, "editable": ["**"]})
    assert is_protected(path) and not spec.is_editable(path)
    assert spec.is_editable("src/main/java/org/x/Service.java")


@pytest.mark.parametrize("path", ["../outside.java", "/etc/passwd", "C:/x.java", "a\\b.java", ""])
def test_unsafe_paths_are_never_editable(descriptor, path):
    assert not ProjectSpec.model_validate({**descriptor, "editable": ["**"]}).is_editable(path)


def test_glob_segments():
    assert glob_regex("src/main/java/*.java").match("src/main/java/A.java")
    assert not glob_regex("src/main/java/*.java").match("src/main/java/x/A.java")
    assert glob_regex("src/main/java/**/*.java").match("src/main/java/A.java")
    assert glob_regex("src/main/java/**/*.java").match("src/main/java/x/y/A.java")
    assert not glob_regex("src/main/java/**/*.java").match("src/main/resources/A.java")


@pytest.mark.parametrize("field,value", [
    ("editable", ["../x/**"]), ("editable", ["/abs/**"]), ("scan", {"paths": ["C:/x"]}),
    ("build", {"package_goals": ["-Dmaven.repo.local=/tmp/m2", "package"]}),
    ("build", {"package_goals": ["-DargLine=-javaagent:x.jar", "package"]}),
    ("build", {"package_goals": ["exec:exec"]}), ("build", {"package_goals": ["-s", "settings.xml"]}),
    ("build", {"artifact": "../x.jar"}),
    ("tests", {"behavior": {"selectors": ["demo.A; rm -rf /"]}}),
    ("tests", {"behavior": {"selectors": ["$(id)"]}}), ("tests", {"behavior": {"selectors": ["a b"]}}),
    ("tests", {"behavior": {"selectors": ["demo.A"], "markers": ["lower case"]}}),
    ("java", "99"), ("id", "Has Space"), ("unknown_field", "x"), ("schema", "safepatch-project/2"),
])
def test_invalid_descriptors_are_rejected(descriptor, field, value):
    with pytest.raises(ValidationError):
        ProjectSpec.model_validate({**descriptor, field: value})


@pytest.mark.parametrize("selector", ["demo.BehaviorTest", "org.x.*Test", "org.x.ParserTest#testXxe", "Test*"])
def test_valid_test_selectors(descriptor, selector):
    spec = ProjectSpec.model_validate({**descriptor, "tests": {"behavior": {"selectors": [selector]}}})
    assert spec.tests.security is None


def test_registry_requires_matching_file_name(tmp_path, descriptor):
    (tmp_path / "other-name.yml").write_text(yaml.safe_dump(descriptor), encoding="utf-8")
    with pytest.raises(ValueError, match="does not match"):
        load_registry(tmp_path)


def test_loader_uses_safe_yaml(tmp_path):
    file = tmp_path / "x.yml"
    file.write_text("!!python/object/apply:os.system ['echo unsafe']\n", encoding="utf-8")
    with pytest.raises(yaml.YAMLError):
        load_project(file)


def test_descriptor_round_trips_through_yaml(tmp_path, descriptor):
    file = tmp_path / "sql-01.yml"
    file.write_text(yaml.safe_dump(copy.deepcopy(descriptor), sort_keys=False), encoding="utf-8")
    assert load_project(file) == ProjectSpec.model_validate(descriptor)
