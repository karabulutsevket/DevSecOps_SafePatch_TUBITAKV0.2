"""Hidden evaluation tests (ROADMAP.md week 6): measure false acceptance.

The verifier never sees these tests. They live in l3/hidden/<case> (not in the case's
repository) and are copied into a fresh checkout of a candidate only after the candidate was
accepted; a candidate that passed verification but fails them was a false acceptance.
Lab and evaluation profiles only; real projects run in the sandbox like any build.

    python scripts/l3_hidden.py --jobs <experiment jobs.db or folder of job JSON files>
writes EVIDENCE_DIR/hidden/<label>.json with one row per accepted job.
"""
import argparse
import json
from pathlib import Path
import shutil
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from safepatch import runner
from safepatch.common import evidence, known_findings_enabled, runtime, safe_path
from safepatch.repository import checkout, project
from safepatch.store import Store
from l3_catalog import case as catalog_case

ACCEPTED = ("awaiting_review", "approved", "deployed")


def hidden_result(case_id, commit, edits, deadline=None):
    """Hidden tests of the case on `commit` with `edits` ({path: content}) applied."""
    if not known_findings_enabled():
        raise SystemExit("hidden evaluation tests run in the lab and evaluation profiles only")
    hidden = catalog_case(case_id).hidden
    if hidden is None:
        raise SystemExit(f"{case_id} has no hidden tests")
    spec = project(case_id, commit)
    deadline = deadline or time.time() + spec.limits.build_seconds + spec.limits.test_seconds
    workspace = (runtime("runner-work") / f"hidden-{uuid.uuid4().hex[:12]}").resolve()
    try:
        checkout(case_id, commit, workspace)
        for path, content in edits.items():
            if not safe_path(path) or not (workspace / path).is_file():
                raise ValueError(f"edit outside the repository's files: {path}")
            (workspace / path).write_text(content, encoding="utf-8", newline="\n")
        source = ROOT / hidden.path
        for file in sorted(p for p in source.rglob("*") if p.is_file()):
            target = workspace / file.relative_to(source)
            if target.exists():
                raise ValueError(f"hidden test would replace a project file: {target.relative_to(workspace)}")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(file, target)
        result = runner.tests(workspace, hidden.selection(), deadline, spec.limits.test_seconds, runner.sandbox_mode(spec), spec.java, spec.build)
        return {k: result.get(k) for k in ("passed", "tests", "failures", "errors", "skipped", "details", "duration_seconds", "reason")}
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def accepted_edits(job):
    """{path: content} of the attempt that passed verification."""
    attempt = next(a for a in reversed(job["attempts"]) if (a.get("verification") or {}).get("passed"))
    return {e["path"]: e["content"] for e in attempt["proposal"]["patch"]["edits"]}, attempt["number"]


def jobs_from(source):
    source = Path(source)
    if source.suffix == ".db":
        return Store("sqlite:///" + source.resolve().as_posix()).all()
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(source.glob("*.json"))]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--jobs", required=True, help="experiment jobs.db or a folder of job JSON files")
    parser.add_argument("--label", required=True)
    args = parser.parse_args()
    out = evidence("hidden") / f"{args.label}.json"
    if out.exists():
        raise SystemExit("Use a fresh label; evidence is never overwritten")
    rows = []
    for job in jobs_from(args.jobs):
        if job["status"] not in ACCEPTED:
            continue
        try:
            catalog_case(job["case_id"])
        except KeyError:
            continue
        if catalog_case(job["case_id"]).hidden is None:
            rows.append({"job": job["id"], "case": job["case_id"], "hidden": None})
            continue
        edits, number = accepted_edits(job)
        result = hidden_result(job["case_id"], job["base_commit"], edits)
        rows.append({"job": job["id"], "case": job["case_id"], "seed": job.get("seed"), "attempt": number, "hidden": result,
                     "false_acceptance": not result["passed"]})
        print(json.dumps({k: rows[-1][k] for k in ("job", "case", "false_acceptance")}), flush=True)
    measured = [r for r in rows if r["hidden"] is not None]
    summary = {"label": args.label, "source": str(args.jobs), "accepted": len(rows), "with_hidden_tests": len(measured),
               "false_acceptances": sum(r["false_acceptance"] for r in measured), "rows": rows}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("accepted", len(rows), "with hidden tests", len(measured), "false acceptances", summary["false_acceptances"], "; written:", out)


if __name__ == "__main__":
    main()
