"""Check an L3 evaluation case prepared by prepare_l3.py (ROADMAP.md week 6).

Variants, each verified like a candidate (policy, sandbox build, behaviour, witness) and
then given the hidden evaluation tests the verifier never runs:
- baseline: the vulnerable revision; the witness must fail;
- human fix: the upstream fix of the target file; must pass both;
- control: a comment only; must be refused;
- partial fix (if the case defines one): a plausible weak fix that passes verification;
  the hidden tests must catch it.
Writes <case>-check.json to EVIDENCE_DIR. Needs PROJECTS_DIR=.runtime/l3/projects
SAFEPATCH_PROFILE=evaluation RUNNER_SANDBOX=docker SANDBOX_MAVEN_CACHE=<wsl path>.
"""
import argparse
import json
from pathlib import Path
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from safepatch import runner
from safepatch.common import Patch, VerifyRequest, digest, evidence, setting
from safepatch.repository import baseline
from l3_hidden import hidden_result
from prepare_l3 import CASES
from prepare_vul4j import L3, git
from vul4j_check import summary


def naive_prefix_guard(source):
    """VUL4J-41: refuse only names that start with "../"; a nested climb still escapes."""
    sink = "        final File f = FileUtils.resolveFile( dir, entryName );\n"
    guard = ("        if ( entryName.startsWith( \"../\" ) )\n        {\n"
             "            throw new ArchiverException( \"Entry is outside of the target directory (\" + entryName + \")\" );\n        }\n")
    assert source.count(sink) == 1
    return source.replace(sink, sink + guard)


def file_branch_guard(source):
    """VUL4J-43: check only entries written as files; a directory entry is still created outside."""
    branch = "\t\telse {\n\t\t\toutFile.getParentFile().mkdirs();\n"
    guard = ("\t\telse {\n\t\t\tif (!outFile.getCanonicalFile().toPath().startsWith(destDir.getCanonicalFile().toPath())) {\n"
             "\t\t\t\tthrow new IOException(\"Zip entry outside destination directory: \" + entry.getName());\n\t\t\t}\n"
             "\t\t\toutFile.getParentFile().mkdirs();\n")
    assert source.count(branch) == 1
    return source.replace(branch, guard)


PARTIAL = {"vul4j-41": naive_prefix_guard, "vul4j-43": file_branch_guard}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("case", choices=sorted(CASES))
    args = parser.parse_args()
    for name, value in (("SAFEPATCH_PROFILE", "evaluation"), ("RUNNER_SANDBOX", "docker")):
        if setting(name) != value:
            raise SystemExit(f"set {name}={value}")
    spec = CASES[args.case]
    commit, target = spec["derived"], spec["target"]
    _, files = baseline(args.case, commit)
    fixed = git(L3 / "repos" / spec["upstream"], "show", f"{spec['fix']}:{target}").decode("utf-8")
    variants = {"baseline": None, "human_fix": fixed, "control": files[target] + "// control: no fix\n"}
    if args.case in PARTIAL:
        variants["partial_fix"] = PARTIAL[args.case](files[target])
    record = {"case": args.case.upper(), "cve": spec["cve"], "cwe": spec["cwe"], "derived_commit": commit, "human_fix_commit": spec["fix"], "started_at": time.time()}
    for name, content in variants.items():
        patch = None if content is None else Patch.model_validate({"edits": [{"path": target, "old_sha256": digest(files[target]), "content": content}], "rationale": name})
        result = runner.execute(VerifyRequest(job_id=uuid.uuid4().hex, case_id=args.case, base_commit=commit, attempt=1 if patch else 0,
                                              deadline=time.time() + 3600, scanner="known", patch=patch, target_file=target if patch else None))
        record[name] = summary(result)
        record[name]["hidden"] = hidden_result(args.case, commit, {} if content is None else {target: content})
        print(name, json.dumps({"passed": result["passed"], "baseline_valid": result.get("baseline_valid"), "feedback": result["feedback"]["code"],
                                "behavior": [record[name]["behavior"][k] for k in ("tests", "failures", "errors")],
                                "security": [record[name]["security"][k] for k in ("tests", "failures", "errors")],
                                "hidden": [record[name]["hidden"][k] for k in ("passed", "tests", "failures", "errors")]}), flush=True)
    out = evidence(f"{args.case}-check.json")
    out.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("written:", out)
    expected = (record["baseline"]["baseline_valid"] and record["human_fix"]["passed"] and record["human_fix"]["hidden"]["passed"]
                and not record["control"]["passed"] and not record["baseline"]["hidden"]["passed"]
                and ("partial_fix" not in record or (record["partial_fix"]["passed"] and not record["partial_fix"]["hidden"]["passed"])))
    if not expected:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
