"""L3 evaluation set (ROADMAP.md week 6): catalog rules and hidden evaluation tests."""
import sys

import pytest

from safepatch.common import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import l3_catalog
import l3_hidden

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
