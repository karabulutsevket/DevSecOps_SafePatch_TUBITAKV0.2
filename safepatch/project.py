"""Trusted project descriptors (safepatch-project/1); see docs/GERCEK_DEPO_TASARIMI.md.

A descriptor is administrator configuration, never repository content: nothing inside
a customer repository can widen what is editable or change how it is built and tested.
Used by safepatch/repository.py since roadmap week 3.
"""
from pathlib import Path
import re
from typing import Literal

from pydantic import ConfigDict, Field, field_validator
import yaml

from safepatch.common import PROJECT_ID, SOURCE, Strict, safe_path

# Always protected, whatever the descriptor says: tests, build and CI configuration.
PROTECTED = ("pom.xml", "**/pom.xml", "*.gradle", "**/*.gradle", "*.gradle.kts", "**/*.gradle.kts",
             "gradlew*", "mvnw*", ".mvn/**", "src/test/**", "**/src/test/**", ".github/**",
             ".gitlab-ci.yml", "Jenkinsfile", ".git/**", ".semgrep*", "**/.semgrep*", "sonar-project.properties")
# A safe subset of Maven -Dtest syntax: Class, pkg.Class, pkg.*Test, pkg.Class#method.
SELECTOR = re.compile(r"^[A-Za-z_*][A-Za-z0-9_.*$]*(#[A-Za-z_*][A-Za-z0-9_*]*)?$")
MARKER = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
PHASES = {"validate", "compile", "test-compile", "package", "verify"}
PROPERTY = re.compile(r"^-D([A-Za-z0-9_.-]+)(=[A-Za-z0-9_.,-]*)?$")
# Properties SafePatch itself controls (offline cache, JVM arguments, test selection).
RESERVED_PROPERTIES = {"maven.repo.local", "argLine", "test", "surefire.failIfNoSpecifiedTests", "skip", "maven.test.skip"}
SYNTHETIC_MARKERS = {"sql": "SQL_INJECTION_REGRESSION", "path": "PATH_TRAVERSAL_REGRESSION", "command": "COMMAND_INJECTION_REGRESSION"}


def glob_regex(pattern):
    """'*' and '?' stay within one path segment; '**/' spans zero or more directories."""
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out, i = out + "(?:[^/]+/)*", i + 3
        elif pattern.startswith("**", i):
            out, i = out + ".*", i + 2
        elif pattern[i] == "*":
            out, i = out + "[^/]*", i + 1
        elif pattern[i] == "?":
            out, i = out + "[^/]", i + 1
        else:
            out, i = out + re.escape(pattern[i]), i + 1
    return re.compile(out + r"\Z")


def matches(path, patterns):
    return any(glob_regex(p).match(path) for p in patterns)


def is_protected(path):
    return matches(path, PROTECTED)


def _paths(values):
    for value in values:
        if not safe_path(value.replace("*", "x")):
            raise ValueError(f"unsafe path or pattern: {value!r}")
    return values


class Repository(Strict):
    path: str = Field(min_length=1, max_length=400)
    commit: str = Field(pattern=r"^[a-f0-9]{40}$")


class Build(Strict):
    tool: Literal["maven"] = "maven"
    package_goals: list[str] = Field(default_factory=lambda: ["-DskipTests", "package"], min_length=1, max_length=12)
    artifact: str | None = Field(default=None, max_length=200)

    @field_validator("package_goals")
    @classmethod
    def goals(cls, values):
        for value in values:
            prop = PROPERTY.match(value)
            if not (value in PHASES or (prop and prop.group(1) not in RESERVED_PROPERTIES)):
                raise ValueError(f"build goal not allowed: {value!r}")
        return values

    @field_validator("artifact")
    @classmethod
    def artifact_path(cls, value):
        return value if value is None else _paths([value])[0]


class SuiteSelection(Strict):
    selectors: list[str] = Field(min_length=1, max_length=50)
    markers: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("selectors")
    @classmethod
    def selector_syntax(cls, values):
        for value in values:
            if not SELECTOR.fullmatch(value) or len(value) > 200:
                raise ValueError(f"test selector not allowed: {value!r}")
        return values

    @field_validator("markers")
    @classmethod
    def marker_syntax(cls, values):
        for value in values:
            if not MARKER.fullmatch(value):
                raise ValueError(f"marker not allowed: {value!r}")
        return values


class Suites(Strict):
    behavior: SuiteSelection
    security: SuiteSelection | None = None   # no witness: never "ready for review"; needs_human / security_witness_missing (decision 3, 25 Oct 2026)


class Scan(Strict):
    paths: list[str] = Field(min_length=1, max_length=20)

    @field_validator("paths")
    @classmethod
    def scan_paths(cls, values):
        return _paths(values)


class Limits(Strict):
    build_seconds: int = Field(default=240, ge=30, le=3600)
    test_seconds: int = Field(default=240, ge=30, le=3600)


class ProjectSpec(Strict):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    schema_version: Literal["safepatch-project/1"] = Field(alias="schema")
    id: str = Field(pattern=PROJECT_ID)
    scope: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    repository: Repository
    java: Literal["8", "11", "17", "21"]
    build: Build = Field(default_factory=Build)
    tests: Suites
    editable: list[str] = Field(min_length=1, max_length=20)
    scan: Scan
    limits: Limits = Field(default_factory=Limits)
    labels: dict[str, str] = Field(default_factory=dict, max_length=10)

    @field_validator("editable")
    @classmethod
    def editable_patterns(cls, values):
        return _paths(values)

    def is_editable(self, path):
        """Protection always wins over the descriptor's editable patterns."""
        return safe_path(path) and not is_protected(path) and matches(path, self.editable)


def load_project(file):
    text = Path(file).read_text(encoding="utf-8")
    if len(text) > 64_000:
        raise ValueError("project descriptor too large")
    return ProjectSpec.model_validate(yaml.safe_load(text))


def load_registry(directory):
    """All descriptors in a trusted directory; the file name must equal the project id."""
    projects = {}
    for file in sorted(Path(directory).glob("*.yml")):
        spec = load_project(file)
        if spec.id != file.stem:
            raise ValueError(f"descriptor id {spec.id!r} does not match file name {file.name!r}")
        projects[spec.id] = spec
    return projects


def synthetic_descriptor(case_id, entry, repository):
    """Descriptor that reproduces today's behaviour for one seeded synthetic case."""
    return {"schema": "safepatch-project/1", "id": case_id, "scope": entry.get("project", "owned-java-demo"),
            "repository": {"path": str(repository), "commit": entry["commit"]}, "java": "17",
            "build": {"tool": "maven", "package_goals": ["-DskipTests", "package"], "artifact": "target/demo.jar"},
            "tests": {"behavior": {"selectors": ["demo.BehaviorTest"]},
                      "security": {"selectors": ["demo.SecurityTest"], "markers": [SYNTHETIC_MARKERS[entry["kind"]]]}},
            "editable": [SOURCE], "scan": {"paths": [SOURCE]},
            "labels": {"kind": entry["kind"], "split": entry["split"], "source": "safepatch-synthetic"}}
