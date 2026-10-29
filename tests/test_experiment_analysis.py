"""Week 10 analysis (scripts/experiment_analysis.py): paired tests and intervals on stored rows."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import experiment_analysis as analysis


def row(arm, case, seed, correct, use=None, warnings=0, vulnerable=True):
    return {"arm": arm, "case": case, "seed": seed, "cwe": "CWE-89", "vulnerable": vulnerable, "correct": correct if vulnerable else None,
            "accepted": bool(correct), "false_acceptance": False if correct else None, "accepted_attempt": 1 if correct else None,
            "wall_seconds": 60.0, "reason": None if correct else "attempt_budget_exhausted", "infrastructure_retry": [],
            "attempts": [{"passed": bool(correct), "failure": None if correct else {"category": "compilation_failed"}}] if vulnerable else [],
            "memory": {"use": use, "tier": "L1" if use else None, "selected_id": "r" if use else None, "same_shape": None, "warnings_sent": warnings}}


def test_the_exact_mcnemar_test_and_holm():
    assert analysis.mcnemar(0, 0) == 1.0 and analysis.mcnemar(7, 8) == 1.0
    assert analysis.mcnemar(0, 7) == pytest.approx(2 / 2**7) and analysis.mcnemar(4, 10) == pytest.approx(2 * 1471 / 2**14)
    assert analysis.holm([0.01, 0.04, 0.5]) == pytest.approx([0.03, 0.08, 0.5])
    assert analysis.holm([0.04, 0.01]) == pytest.approx([0.04, 0.02])


def test_pairs_are_the_same_case_and_seed_and_safe_cases_stay_out():
    outcome = analysis.correct([row("C", "a", 1, True), row("A", "a", 1, False), row("C", "b", 1, False), row("A", "b", 1, True),
                                row("C", "c", 1, True), row("A", "c", 1, True), row("C", "s", 1, None, vulnerable=False)])
    result = analysis.paired(outcome, "C", "A", {("a", 1), ("b", 1), ("c", 1)})
    assert (result["both"], result["only_C"], result["only_A"], result["neither"], result["difference"]) == (1, 1, 1, 0, 0.0)
    assert ("C", "s", 1) not in outcome


def test_the_bootstrap_resamples_cases_and_is_reproducible():
    keys = {(c, s) for c in "abcd" for s in (1, 2, 3)}
    same = {(arm, c, s): c in "ab" for arm in ("x", "y") for c, s in keys}
    assert analysis.bootstrap(same, "x", "y", keys) == [0.0, 0.0]
    better = {**same, **{("x", c, s): True for c, s in keys}}
    first = analysis.bootstrap(better, "x", "y", keys, iterations=500)
    assert first == analysis.bootstrap(better, "x", "y", keys, iterations=500) and 0 <= first[0] <= 0.5 <= first[1] <= 1
    assert analysis.bootstrap(better, "x", "y", set()) is None


def test_memory_classes_follow_what_was_sent():
    sent = (("example", 2), ("example", 0), (None, 1), (None, 0))
    assert [analysis.memory_class(row("C", "a", 1, True, use=u, warnings=w)) for u, w in sent] == \
        ["example_and_warnings", "example_only", "warnings_only", "neither"]


def test_a_withheld_warning_counts_only_in_the_found_split():
    withheld = row("C", "a", 1, True)
    withheld["memory"]["warnings_withheld"] = 2
    assert analysis.memory_class(withheld) == "neither"
    assert analysis.memory_class(withheld, found=True) == "warnings_only"
    assert analysis.memory_class(row("C", "a", 1, True, warnings=1), found=True) == "warnings_only"


def test_warning_kinds_come_from_the_arms_databases_as_counts_only(tmp_path):
    from safepatch.store import Store
    warned = {"warnings_sent": [{"id": "f1", "relation": "same_shape", "failure": "compilation_failed"}]}
    jobs = {"42-C": [("j1", {**warned, "selected_id": None}), ("j2", {**warned, "selected_id": "r"}), ("j3", {**warned, "selected_id": None})],
            "42-A": [("j4", {**warned, "selected_id": None})]}
    for name, entries in jobs.items():
        store = Store("sqlite:///" + (tmp_path / f"{name}.db").as_posix())
        for job_id, lookup in entries:
            store.create({"id": job_id, "memory_lookup": lookup}, job_id)
        store.engine.dispose()
    rows = [{"job": j, "vulnerable": j != "j3"} for j in ("j1", "j2", "j3", "j4")]
    result = analysis.warning_kinds(rows, tmp_path)
    # j3 is a safe case and arm A sends no warnings by design: neither is counted.
    assert result["kinds"] == {"C": {"warnings_only": {"same_shape/compilation_failed": 1}, "with_example": {"same_shape/compilation_failed": 1}}}
    assert list(result["databases_sha256"]) == ["42-C.db"]


def test_a_finished_run_is_analysed_once_and_bound_to_its_rows(tmp_path, monkeypatch):
    run, rows = tmp_path / "experiment", []
    for arm in analysis.ARMS:
        for seed in (42, 43):
            for case, ok in (("c1", arm != "A"), ("c2", True), ("c3", False)):
                rows.append(row(arm, case, seed, ok, use="example" if arm != "A" and case == "c1" else None,
                                warnings=1 if arm == "C" and case == "c3" else 0))
            rows.append(row(arm, "safe", seed, None, vulnerable=False))
    for r in rows:
        folder = run / "runs" / f"{r['seed']}-{r['arm']}"
        folder.mkdir(parents=True, exist_ok=True)
        (folder / f"{r['case']}.json").write_text(json.dumps(r), encoding="utf-8")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["experiment_analysis.py"])
    with pytest.raises(SystemExit, match="no finished run"):
        analysis.main()
    (run / "summary.json").write_text("{}", encoding="utf-8")
    analysis.main()
    result = json.loads((tmp_path / "analiz" / "analysis.json").read_text(encoding="utf-8"))
    total = result["declared"]["C-A"]["total"]
    assert result["inputs"]["rows"] == 32 and (total["only_C"], total["only_A"], total["pairs"]) == (2, 0, 6)
    assert result["arms"]["A"]["safe_stopped_before_model"] == 2 and result["arms"]["C"]["memory_used"] == 2
    split = result["memory_split_exploratory"]["C"]
    assert split["example_only"]["only_C"] == 2 and split["warnings_only"]["pairs"] == 2
    assert split["warnings_only"]["attempt_outcomes_C"] == {"compilation_failed": 2}
    assert result["ceiling"] == {"cases": 3, "never_repaired": 1, "always_repaired": 1, "sometimes": 1, "always_cases": ["c2"]}
    with pytest.raises(SystemExit, match="never overwritten"):
        analysis.main()
    _, before = analysis.load(run)
    (run / "runs" / "42-A" / "c3.json").write_text(json.dumps({**rows[2], "correct": True}), encoding="utf-8")
    assert analysis.load(run)[1] != before


def test_a_rerun_is_compared_arm_by_arm_with_the_earlier_run():
    def rows(c_correct, a_patch):
        out = []
        for seed in (42, 43):
            out.append({**row("A", "c1", seed, True), "attempts": [{"passed": True, "patch_sha256": a_patch}]})
            out.append(row("C", "c1", seed, c_correct))
            out.append(row("C", "safe", seed, None, vulnerable=False))
        return out
    result = analysis.cross_run(rows(True, "same"), rows(False, "same"))
    assert (result["C"]["pairs"], result["C"]["only_C@run"], result["C"]["only_C@previous"]) == (2, 2, 0)
    assert result["A"]["only_A@run"] == result["A"]["only_A@previous"] == 0 and result["A"]["same_attempt_patches"] == 2
    assert analysis.cross_run(rows(True, "other"), rows(True, "same"))["A"]["same_attempt_patches"] == 0
    assert set(result) == {"A", "C"}
