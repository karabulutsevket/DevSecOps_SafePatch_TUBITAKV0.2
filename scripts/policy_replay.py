"""Replay the forbidden-token rule over stored model answers (policy decisions only).

Compares the current safepatch.policy with its version at --base (a git ref) on every model
answer kept in .runtime/l3-measure/<run>/jobs.db: which refusals a policy change lifts or adds.
No model call, no build. The answers touch third-party code, so they stay in .runtime; the
record keeps cases, attempts and decisions. Writes policy-replay.json to EVIDENCE_DIR.
"""
import argparse
import difflib
import json
from pathlib import Path
import subprocess
import sys
import types

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from safepatch import policy
from safepatch.common import evidence
from safepatch.repository import run_git
from safepatch.store import Store

DESCRIPTORS = (".runtime/l3/projects", ".runtime/dev-all/projects")


def policy_at(ref):
    code = subprocess.run(["git", "show", f"{ref}:safepatch/policy.py"], cwd=ROOT, capture_output=True, check=True).stdout.decode("utf-8")
    module = types.ModuleType(f"policy_at_{ref}")
    exec(compile(code, f"safepatch/policy.py@{ref}", "exec"), module.__dict__)
    return module


def repositories():
    found = {}
    for folder in DESCRIPTORS:
        for path in sorted((ROOT / folder).glob("*.yml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            found[data["id"]] = (Path(data["repository"]["path"]), data["repository"]["commit"])
    return found


def original(repo, commits, target):
    """The target file at the job's base commit, else at the descriptor's (the target file is the
    same there: a re-derived evaluation commit only changed test files)."""
    for commit in commits:
        try:
            return run_git(repo, "show", f"{commit}:{target}").decode("utf-8"), commit
        except RuntimeError:
            continue
    raise RuntimeError(f"{target} not found")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", required=True, help="git ref of the policy to compare with")
    args = parser.parse_args()
    out = evidence("policy-replay.json")
    if out.exists():
        raise SystemExit("Use a fresh EVIDENCE_DIR; evidence is never overwritten")
    before, repos = policy_at(args.base), repositories()
    answers, changed, runs = 0, [], []
    for db in sorted((ROOT / ".runtime/l3-measure").glob("*/jobs.db")):
        runs.append(db.parent.name)
        for job in Store("sqlite:///" + db.as_posix()).all():
            repo, commit = repos[job["case_id"]]
            for attempt in job["attempts"]:
                for edit in (attempt["proposal"].get("patch") or {}).get("edits", []):
                    source, used = original(repo, (job["base_commit"], commit), edit["path"])
                    diff = list(difflib.unified_diff(source.splitlines(True), edit["content"].splitlines(True)))
                    old = before.introduces_forbidden(source, edit["content"], diff)
                    new = policy.introduces_forbidden(source, edit["content"], diff)
                    answers += 1
                    if old != new:
                        changed.append({"run": db.parent.name, "case": job["case_id"], "attempt": attempt["number"],
                                        "before": "refused" if old else "passed", "now": "refused" if new else "passed",
                                        "job_status": job["status"], "source_commit": used})
    out.write_text(json.dumps({"base": args.base, "runs": runs, "answers": answers, "changed": changed}, indent=2) + "\n", encoding="utf-8")
    print("answers", answers, "changed", len(changed))
    for row in changed:
        print(json.dumps(row))
    print("written:", out)


if __name__ == "__main__":
    main()
