"""L3 evaluation set (ROADMAP.md week 6): catalog rules and hidden evaluation tests."""
import sys

import pytest

from safepatch.common import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import l3_catalog
import l3_hidden
import prepare_benchmark

READY_EVAL = {"id": "ext-1", "source": "vul4j", "project": "org/lib", "cwe": "CWE-22", "split": "evaluation", "license": "Apache-2.0",
              "hidden": {"path": "l3/hidden/ext-1", "selectors": ["org.lib.HiddenTest"]}, "status": "ready"}
OWNED = {"id": "own-1", "source": "safepatch-synthetic", "project": "safepatch-synthetic-lab", "cwe": "CWE-89", "split": "development",
         "license": "MIT", "status": "ready"}


def catalog(*cases):
    return l3_catalog.Catalog.model_validate({"schema": "safepatch-l3/1", "targets": {"development": 20, "evaluation": 40}, "cases": list(cases)})


def hidden_root(tmp_path, *names):
    for name in names:
        (tmp_path / "l3/hidden" / name).mkdir(parents=True)
    return tmp_path


def test_the_repository_catalog_keeps_every_rule():
    assert l3_catalog.problems(l3_catalog.load()) == []


def test_a_valid_catalog_has_no_problems(tmp_path):
    assert l3_catalog.problems(catalog(OWNED, READY_EVAL), hidden_root(tmp_path, "ext-1")) == []


@pytest.mark.parametrize("cases,folders,problem", [
    ([{**READY_EVAL, "split": "development"}], ["ext-1"], "evaluation only"),
    ([OWNED, {**OWNED, "id": "own-2", "split": "evaluation", "hidden": READY_EVAL["hidden"]}], ["ext-1"], "on both sides"),
    ([{**READY_EVAL, "hidden": None}], [], "needs hidden tests"),
    ([READY_EVAL], [], "is missing"),
    ([OWNED], ["stray"], "belongs to no case"),
    ([OWNED, OWNED], [], "duplicate case id"),
])
def test_broken_rules_are_reported(tmp_path, cases, folders, problem):
    found = l3_catalog.problems(catalog(*cases), hidden_root(tmp_path, *folders))
    assert any(problem in p for p in found), found


def test_a_planned_evaluation_case_may_wait_for_hidden_tests(tmp_path):
    assert l3_catalog.problems(catalog({**READY_EVAL, "hidden": None, "status": "planned"}), tmp_path) == []


@pytest.mark.parametrize("profile", [None, "product"])
def test_hidden_tests_never_run_in_the_product_profile(monkeypatch, profile):
    if profile:
        monkeypatch.setenv("SAFEPATCH_PROFILE", profile)
    else:
        monkeypatch.delenv("SAFEPATCH_PROFILE", raising=False)
    monkeypatch.setattr(l3_hidden, "checkout", lambda *a: pytest.fail("nothing is checked out"))
    with pytest.raises(SystemExit, match="lab and evaluation profiles only"):
        l3_hidden.hidden_result("vul4j-79", "0" * 40, {})


def test_the_accepted_attempt_supplies_the_edits():
    job = {"attempts": [
        {"number": 1, "verification": {"passed": False}, "proposal": {"patch": {"edits": [{"path": "A.java", "content": "first"}]}}},
        {"number": 2, "verification": {"passed": True}, "proposal": {"patch": {"edits": [{"path": "A.java", "content": "second"}]}}},
    ]}
    assert l3_hidden.accepted_edits(job) == ({"A.java": "second"}, 2)


ROW = {"visible": "climb: read the file outside; ", "nested": "", "benign_1": "a", "benign_2": "a", "dots_1": "b", "dots_2": "b"}


@pytest.mark.parametrize("real,row,usable,reason", [
    (True, ROW, True, None),
    (False, {**ROW, "visible": ""}, True, None),                       # a safe case: nothing escapes, the job returns to a human
    (True, {**ROW, "visible": ""}, False, "no input shape"),          # never redrawn, excluded with its reason
    (False, ROW, False, "marks it safe"),
    (True, {**ROW, "benign_2": "c"}, False, "changes from run to run"),
    (True, {**ROW, "dots_1": "error: java.lang.NoClassDefFoundError", "visible": "error: x"}, False, "failed under the witness harness"),
])
def test_the_recording_decides_whether_a_sampled_benchmark_case_is_usable(real, row, usable, reason):
    assert prepare_benchmark.verdict(real, row)[0] is usable
    assert reason is None or reason in prepare_benchmark.verdict(real, row)[1]


@pytest.mark.parametrize("category,method", [("pathtraver", "traversal"), ("sqli", "sqlInjection"), ("cmdi", "commandInjection")])
def test_generated_tests_name_the_case_and_carry_no_placeholder(category, method):
    call = prepare_benchmark.calls(category, "BenchmarkTest00011")
    text = prepare_benchmark.java(prepare_benchmark.WITNESS_TEST, name="BenchmarkTest00011", n="00011", marker="X_REGRESSION", witness=call["witness"]).decode()
    assert "class SafePatchWitness00011" in text and f"WitnessSupport.{method}(org.owasp.benchmark.testcode.BenchmarkTest00011.class" in text
    assert "{" not in text.replace("Witness00011 {", "").replace("throws Exception {", "")


def test_every_development_variant_has_one_sink_and_a_reference_fix():
    import variants_dev
    for case, (kind, sink, cwe) in variants_dev.CASES.items():
        source = (variants_dev.SAMPLES / variants_dev.source_name(case)).read_text(encoding="utf-8")
        fixed = (variants_dev.SAMPLES / "fixed" / variants_dev.source_name(case)).read_text(encoding="utf-8")
        assert [line.strip() for line in source.splitlines()].count(sink) == 1, case
        assert sink not in [line.strip() for line in fixed.splitlines()], case
