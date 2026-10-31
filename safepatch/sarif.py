"""The institution's own scanner findings, imported as SARIF 2.1.0 (docs/SARIF_ICERI_ALMA.md).

A customer exports CodeQL, Semgrep, Checkmarx, Fortify or SonarQube results as SARIF; SafePatch
cannot run those tools itself (closed network, licences). The export is untrusted data, read
strictly: SARIF 2.1.0 only, bounded in size and counts, every location a repository-relative file
of the pinned commit, every text kept short and checked like other untrusted text. Weaknesses
outside the supported CWE families are kept apart as other findings: reported, never a job.
The import (POST /v1/finding-imports) turns the findings into a job; that tool is not rerun after
a patch, so the security witness decides, with SafePatch's own scanner beside it (decided 31 Oct 2026).
"""
import json
from pathlib import PurePosixPath
import re
from urllib.parse import unquote
import uuid

from safepatch.common import canonical, digest, safe_path
from safepatch.feedback import imitates_note
from safepatch.policy import PolicyError
from safepatch.scanner import in_scope
from safepatch.weakness import FAMILY, SUPPORTED, cwe_id, family

VERSION = "2.1.0"
MAX_BYTES = 32 * 1024 * 1024
MAX_RUNS = 20
MAX_RESULTS = 10_000
# Distinct supported findings (rule and file): a job's verify request carries at most 500
# fingerprints of other files' findings (`tolerated`).
MAX_FINDINGS = 500
MAX_ID = 200
MAX_MESSAGE = 300
KINDS = ("notApplicable", "pass", "fail", "review", "open", "informational")
LEVELS = ("none", "note", "warning", "error")
STATES = ("new", "unchanged", "updated", "absent")
SUPPRESSIONS = ("inSource", "external")
STATUSES = ("accepted", "underReview", "rejected")
SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")


def need(condition, code="sarif_malformed"):
    if not condition:
        raise PolicyError(code)


def mapping(value, required=True):
    if value is None and not required:
        return {}
    need(isinstance(value, dict))
    return value


def array(value):
    if value is None:
        return []
    need(isinstance(value, list))
    return value


def text(value, limit):
    """A short label (rule id, tool name): printable, so no line break or bidirectional control."""
    need(isinstance(value, str) and 0 < len(value) <= limit and value.isprintable())
    return value


def enum(value, allowed, default):
    """A SARIF enumeration value. SpotBugs on a Turkish-locale machine writes "warnıng" (dotless ı,
    tests/fixtures/spotbugs): that locale's lower-casing is undone before the check."""
    if value is None:
        return default
    need(isinstance(value, str) and value.replace("ı", "i") in allowed)
    return value.replace("ı", "i")


def strict_json(raw):
    """UTF-8 JSON (a byte order mark is tolerated) without duplicate keys or NaN/Infinity."""
    def unique(pairs):
        need(len({key for key, _ in pairs}) == len(pairs))
        return dict(pairs)

    def constant(name):
        raise PolicyError("sarif_invalid_json")
    try:
        return json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique, parse_constant=constant)
    except (ValueError, RecursionError):
        raise PolicyError("sarif_invalid_json") from None


def absolute(uri):
    return bool(SCHEME.match(uri)) or uri.startswith("/")


def under_root(uri, bases):
    """The part of an absolute URI below the outermost absolute base the run declares: the
    folder the producer scanned, taken as the repository root."""
    roots = sorted((b["uri"] for b in bases.values() if b.get("uri") and absolute(b["uri"])), key=len)
    root = next((r for r in roots if uri.startswith(r)), None)
    if root is None:
        raise PolicyError("sarif_path_outside_repository")
    return uri[len(root):]


def base_prefix(name, bases, depth=0):
    """The repository folder a uriBaseId stands for. A base the run does not declare (Semgrep
    names %SRCROOT% without declaring it) or declares without a URI is the repository root."""
    if name is None or bases.get(name, {}).get("uri") is None:
        return ""
    need(depth < 8)
    base = bases[name]
    if absolute(base["uri"]):
        return under_root(base["uri"], bases)
    return base_prefix(base.get("uriBaseId"), bases, depth + 1) + base["uri"]


def repository_path(location, bases):
    """A location as a repository path; one that could point outside the repository is refused.
    A relative URI is read from its uriBaseId's folder, an absolute one (file:///..., /...) only
    under an absolute base the run declares. Percent-encoding is decoded once, then the path
    must be plain and relative: no '..', drive letter, backslash or NUL."""
    uri = location.get("uri")
    need(isinstance(uri, str) and 0 < len(uri) <= 1000 and "?" not in uri and "#" not in uri)
    relative = under_root(uri, bases) if absolute(uri) else base_prefix(location.get("uriBaseId"), bases) + uri
    try:
        path = unquote(relative, errors="strict")
    except UnicodeDecodeError:
        raise PolicyError("sarif_malformed") from None
    if "\x00" in path or not safe_path(path):
        raise PolicyError("sarif_path_outside_repository")
    return "/".join(PurePosixPath(path).parts)


def same_commit(revision, commit):
    """A declared revision names the pinned commit, in full or abbreviated to 7+ hex digits."""
    return isinstance(revision, str) and bool(re.fullmatch(r"[0-9a-f]{7,40}", revision.lower())) and commit.startswith(revision.lower())


def rule_of(result, components):
    """(rule id, rule definition or {}) of a result: the definition by index where the result
    gives one (CodeQL points into a query pack, SpotBugs into the driver), else by id."""
    reference = mapping(result.get("rule"), required=False)
    ids = {value for value in (result.get("ruleId"), reference.get("id")) if value is not None}
    need(len(ids) <= 1)
    index = reference.get("index", result.get("ruleIndex"))
    component = mapping(reference.get("toolComponent"), required=False)
    # An index points into the driver's rules, or into the extension the reference numbers;
    # an extension named only by name or guid is searched by id instead.
    if index is not None and (not component or "index" in component):
        which = component.get("index", -1)
        need(type(index) is int and type(which) is int and -1 <= which < len(components) - 1)
        need(0 <= index < len(components[which + 1]))
        definition = components[which + 1][index]
    else:
        definition = next((r for rules in components for r in rules if r["id"] in ids), {})
    rule_id = text(next(iter(ids), definition.get("id")), MAX_ID)
    need(not definition or rule_id == definition["id"] or rule_id.startswith(definition["id"] + "/"))
    return rule_id, definition


def taxon_cwe(reference):
    """'CWE-89' from a reference into the CWE taxonomy, else None."""
    reference = mapping(reference)
    component = mapping(reference.get("toolComponent"), required=False)
    value = reference.get("id")
    if str(component.get("name", "")).casefold() != "cwe" or not isinstance(value, str):
        return None
    return cwe_id("CWE-" + value if value.isdigit() else value)


def tags(holder):
    found = array(mapping(holder.get("properties"), required=False).get("tags"))
    need(all(isinstance(tag, str) for tag in found))
    return found


def weaknesses(rule, result):
    """CWE ids named by the rule's CWE relationships (SpotBugs) and tags (CodeQL's
    external/cwe/cwe-089, Semgrep's CWE-89), then by the result's own taxa and tags."""
    found = [taxon_cwe(mapping(relation).get("target")) for relation in array(rule.get("relationships"))]
    found += [taxon_cwe(taxon) for taxon in array(result.get("taxa"))]
    found += [cwe_id(tag) for tag in tags(rule) + tags(result)]
    return list(dict.fromkeys(cwe for cwe in found if cwe))


def classify(rule_id, cwes):
    """(cwe, None) when the result names exactly one supported family, else (cwe or None, why
    it is kept apart). A rule naming no CWE may still be known by id (weakness.family)."""
    if not cwes and (known := family({"rule_id": rule_id})):
        cwes = [known]
    supported = {FAMILY.get(cwe, cwe) for cwe in cwes} & SUPPORTED
    if len(supported) == 1:
        return next(cwe for cwe in cwes if FAMILY.get(cwe, cwe) in supported), None
    return (cwes[0] if cwes else None), ("ambiguous_family" if supported else "unsupported_family" if cwes else "no_cwe")


def skip_reason(result):
    """Why a result is not a current failure: another kind, fixed since the baseline the
    producer compared with, or suppressed (in source or in the producer's triage)."""
    if enum(result.get("kind"), KINDS, "fail") != "fail":
        return "not_failure"
    if enum(result.get("baselineState"), STATES, None) == "absent":
        return "absent"
    statuses = []
    for suppression in map(mapping, array(result.get("suppressions"))):
        need(enum(suppression.get("kind"), SUPPRESSIONS, None) is not None)
        # Without a status a suppression is in effect; one under review or rejected is not.
        statuses.append(enum(suppression.get("status"), STATUSES, "accepted"))
    return "suppressed" if "accepted" in statuses else None


def message(result):
    """The result's text as one short line, data for the reviewer: line breaks, control and
    bidirectional characters, which could disguise it, become spaces."""
    value = mapping(result.get("message")).get("text")
    need(value is None or isinstance(value, str))
    return " ".join("".join(c if c.isprintable() else " " for c in (value or "")[:4 * MAX_MESSAGE]).split())[:MAX_MESSAGE]


def read_run(run, number, commit, files, paths, sha256):
    tool = mapping(run.get("tool"))
    driver = mapping(tool.get("driver"))
    name = text(driver.get("name"), 100)
    version = driver.get("semanticVersion", driver.get("version"))
    need(version is None or (isinstance(version, str) and len(version) <= 100 and version.isprintable()))
    for invocation in array(run.get("invocations")):
        need(mapping(invocation).get("executionSuccessful") is True, "sarif_incomplete_scan")
    revisions = [mapping(p).get("revisionId") for p in array(run.get("versionControlProvenance"))]
    need(all(r is None or same_commit(r, commit) for r in revisions), "sarif_commit_mismatch")
    bases = mapping(run.get("originalUriBaseIds"), required=False)
    for base in bases.values():
        uri, parent = mapping(base).get("uri"), base.get("uriBaseId")
        need((uri is None or (isinstance(uri, str) and uri.endswith("/") and "?" not in uri and "#" not in uri))
             and (parent is None or isinstance(parent, str)))
    artifacts = [mapping(a) for a in array(run.get("artifacts"))]
    components = [[mapping(r) for r in array(c.get("rules"))] for c in [driver, *map(mapping, array(tool.get("extensions")))]]
    need(all(isinstance(r.get("id"), str) for rules in components for r in rules))
    findings, other, seen = [], [], set()
    skipped = dict.fromkeys(("not_failure", "absent", "suppressed", "unmapped", "outside_scan_paths", "duplicate"), 0)
    for result in run["results"]:
        result = mapping(result)
        rule_id, rule = rule_of(result, components)
        default = enum(mapping(rule.get("defaultConfiguration"), required=False).get("level"), LEVELS, "warning")
        level = enum(result.get("level"), LEVELS, default)
        reason = skip_reason(result)
        locations = array(result.get("locations"))
        physical = mapping(mapping(locations[0]).get("physicalLocation"), required=False) if locations else {}
        artifact = mapping(physical.get("artifactLocation"), required=False)
        if "uri" not in artifact and "index" in artifact:
            need(type(artifact["index"]) is int and 0 <= artifact["index"] < len(artifacts))
            artifact = mapping(artifacts[artifact["index"]].get("location"))
        path = repository_path(artifact, bases) if not reason and "uri" in artifact else None
        line = mapping(physical.get("region"), required=False).get("startLine")
        need(line is None or (type(line) is int and line >= 1))
        if not reason and (path is None or path not in files):
            reason = "unmapped"
        if not reason and not in_scope(path, paths):
            reason = "outside_scan_paths"
        # Same rule, same file: one weakness for the rescan whatever its line (as for Semgrep).
        fingerprint = digest(canonical(["sarif", name, rule_id, path]))
        if not reason and (fingerprint, line) in seen:
            reason = "duplicate"
        if reason:
            skipped[reason] += 1
            continue
        seen.add((fingerprint, line))
        cwe, apart = classify(rule_id, weaknesses(rule, result))
        finding = {"tool": "sarif", "producer": name, "rule_id": rule_id, "type": "VULNERABILITY", "file": path, "line": line,
                   "severity": level, "message": message(result), "cwe": cwe, "fingerprint": fingerprint}
        if apart:
            other.append({**finding, "kept_apart": apart})
        else:
            findings.append(finding)
    return {"tool": "sarif", "version": VERSION, "producer": {"name": name, "version": version}, "status": "ok",
            "analysis_id": uuid.uuid4().hex, "commit": commit, "commit_declared": any(r is not None for r in revisions),
            "run": number, "sarif_sha256": sha256, "findings": findings, "other_findings": other, "skipped": skipped}


def read_sarif(raw, commit, files, paths):
    """One report per run of an exported SARIF file (`raw`, its bytes) for the project pinned at
    `commit`: `files` are its tracked files, `paths` its descriptor's scan paths."""
    if len(raw) > MAX_BYTES:
        raise PolicyError("sarif_too_large")
    data = mapping(strict_json(raw))
    schema = data.get("$schema")
    need(data.get("version") == VERSION and (schema is None or (isinstance(schema, str) and VERSION in schema)), "sarif_version_unsupported")
    runs = data.get("runs")
    # A run without a results array did not finish; an empty array means it found nothing.
    need(isinstance(runs, list) and runs and all(isinstance(run, dict) and isinstance(run.get("results"), list) for run in runs),
         "sarif_run_without_results")
    need(len(runs) <= MAX_RUNS, "sarif_too_many_runs")
    need(sum(len(run["results"]) for run in runs) <= MAX_RESULTS, "sarif_too_many_results")
    sha256 = digest(raw)
    reports = [read_run(run, number, commit, files, paths, sha256) for number, run in enumerate(runs)]
    need(len({f["fingerprint"] for r in reports for f in r["findings"]}) <= MAX_FINDINGS, "sarif_too_many_findings")
    texts = [r["producer"][k] for r in reports for k in ("name", "version")]
    texts += [f[k] for r in reports for f in r["findings"] + r["other_findings"] for k in ("rule_id", "message", "file")]
    # Finding fields reach the model as data; one that imitates the trusted note never gets that far.
    if imitates_note(*texts):
        raise PolicyError("suspected_prompt_injection")
    return reports
