"""Failure-warning experiment (docs/DENEY_UYARI.md): arms, job fields and the pre-declared analysis."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import main_experiment
import warning_experiment as experiment


def row(arm, case, accepted, example=None, sent=0, withheld=0, cwe="CWE-89"):
    return {"arm": arm, "case": case, "seed": 42, "cwe": cwe, "accepted": accepted, "status": "awaiting_review" if accepted else "needs_human",
            "infrastructure_retry": [], "memory": {"use": example, "warnings_sent": sent, "warnings_withheld": withheld}}


def test_the_arms_alternate_and_differ_only_in_the_warnings():
    assert [experiment.arm_order(s) for s in (42, 43, 44)] == [["C", "C-W"], ["C-W", "C"], ["C", "C-W"]]
    assert experiment.ARMS == {"C": ("guarded", None), "C-W": ("guarded", {"experiment_failure_warnings": False})}


def test_the_experiment_job_carries_the_arm_fields(job_store):
    db, _ = job_store
    job = db.get(main_experiment.new_job(db, "sql-01", "guarded", 42, fields={"experiment_failure_warnings": False}))
    plain = db.get(main_experiment.new_job(db, "sql-01", "guarded", 42))
    assert job["experiment_failure_warnings"] is False and "experiment_failure_warnings" not in plain
    assert job["memory_mode"] == plain["memory_mode"] == "guarded"


def test_the_subgroups_are_where_arm_c_sent_the_warnings():
    rows = [row("C", "a", False, sent=2), row("C-W", "a", True, withheld=2),        # warned only: C-W better
            row("C", "b", True, example="example", sent=1), row("C-W", "b", True, example="example", withheld=1),
            row("C", "c", True), row("C-W", "c", True),
            row("C", "d", False), row("C-W", "d", False, withheld=1)]            # C-W saw a failure C did not
    result = experiment.analyze(rows)
    assert (result["primary"]["pairs"], result["primary"]["only_C-W"], result["primary"]["only_C"]) == (4, 1, 0)
    assert result["secondary_c_sent_warnings_only"]["pairs"] == 1 and result["secondary_c_sent_warnings_only"]["only_C-W"] == 1
    assert result["secondary_c_sent_any_warning"]["pairs"] == 2 and result["c_w_withheld_jobs"] == 3
    summary = experiment.summarize([{**r, "seed": 42} for r in rows])
    assert summary["C"]["total"]["warnings_sent_jobs"] == 2 and summary["C-W"]["total"]["warnings_withheld_jobs"] == 3


def test_the_exploration_separates_the_cascade_from_the_direct_effect(tmp_path):
    rows = [{**r, "job": f"{r['arm']}-{r['case']}", "attempts": [{"passed": r["accepted"]}]} for r in (
        row("C", "a", False, sent=2), row("C-W", "a", True, withheld=2),                         # direct
        row("C", "b", False, sent=1), row("C-W", "b", True, example="example", withheld=1),      # cascade
        row("C", "c", True), row("C-W", "c", True))]
    result = experiment.explore(rows, tmp_path)
    splits = result["splits"]
    assert (splits["c_warnings_only_and_c_w_no_example"]["pairs"], splits["c_warnings_only_and_c_w_no_example"]["only_C-W"]) == (1, 1)
    assert (splits["c_warnings_only_and_c_w_example"]["pairs"], splits["c_no_warning"]["pairs"]) == (1, 1)
    assert [d["case"] for d in result["discordant_c_warnings_only"]] == ["a", "b"]
    assert result["attempt_outcomes_c_warnings_only"] == {"C": {"unknown": 2}, "C-W": {"passed": 2}}
    assert result["warning_kinds"] == {"databases_sha256": {}, "kinds": {}}
