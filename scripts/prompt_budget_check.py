"""How many tokens worker1's prompts really take against its estimate (ROADMAP.md week 6).

worker1 estimates two UTF-8 bytes per token in both modes and checks the model's own count
after generation. This composes prompts with worker1's own code and has the local model count
them (one output token, no repair):
- the development sources (synthetic lab, variants, region cases), with a retry context;
- OWASP Benchmark servlets with their read-only context as the engine picks it, where the
  old one-byte-per-token count sent 70-line files to region mode (the L3 run of 26 Oct);
- a file of Turkish comments, a hard case for the estimate (non-ASCII text).
Writes prompt-budget.json to EVIDENCE_DIR. Needs Ollama running and PROJECTS_DIR=.runtime/l3/projects.
"""
import json
from pathlib import Path
import secrets
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from safepatch import worker1
from safepatch.common import SOURCE, Patch, evidence, setting
from safepatch.engine import read_only_context
from safepatch.repository import baseline, project, registry

RETRY = {"feedback": {"category": "behavior_regression", "previous_patch_diff": "-        old line\n+        new line\n" * 40},
         "guidance": "Keep the behaviour for normal input and change only the vulnerable call. " * 8}
TURKISH = "".join(f"    // {i}. adım: kullanıcı girdisi çözümlenmeden önce doğrulanır; şüpheli öğeler, ığdır ve çağrı günlüğe yazılır.\n" for i in range(40))


def development():
    files = {p.name: p.read_text(encoding="utf-8") for folder in ("samples/sources", "samples/variants", "samples/region")
             for p in sorted((ROOT / folder).glob("*.java"))}
    for name, source in files.items():
        siblings, size = {}, 0
        for other, text in files.items():
            if other != name and size + len(text) <= 8000:
                siblings[f"src/main/java/demo/{other.replace('-', '_')}"] = text
                size += len(text)
        yield "development/" + name, source, siblings


def benchmark():
    for case, info in sorted(registry()[1].items()):
        if case.startswith("owasp-benchmark-"):
            target = project(case, info["commit"]).scan.known[0].file
            files = baseline(case, info["commit"])[1]
            yield "benchmark/" + case, files[target], read_only_context(files, target)


def count(system, prompt):
    endpoint = setting("OLLAMA_URL", "http://127.0.0.1:11434")
    body = {"model": setting("OLLAMA_MODEL", "qwen2.5-coder:7b-instruct-q4_K_M"), "system": system, "prompt": prompt, "format": Patch.model_json_schema(),
            "stream": False, "options": {"temperature": 0, "seed": 42, "num_ctx": int(setting("MODEL_CONTEXT", "8192")), "num_predict": 1}}
    return worker1.request(endpoint + "/api/generate", "POST", body=body, timeout=180)["prompt_eval_count"]


def main():
    out = evidence("prompt-budget.json")
    if out.exists():
        raise SystemExit("Use a fresh EVIDENCE_DIR; evidence is never overwritten")
    cases = [*development(), *benchmark(), ("hard/turkish-comments", "class Notes {\n" + TURKISH + "}\n", {})]
    rows = []
    for name, source, siblings in cases:
        for shape, extra in (("first", {}), ("retry", {**RETRY, "context_files": siblings})):
            req = worker1.Propose(job_id="a" * 32, attempt=1 if shape == "first" else 2, deadline=time.time() + 300,
                                  source={SOURCE: source}, finding={"rule_id": "x", "cwe": "CWE-89"}, **extra)
            try:
                system, prompt, dropped = worker1.compose_mode(req, secrets.token_hex(6), False)
            except ValueError:
                rows.append({"case": name, "shape": shape, "fits_whole_file": False})
                continue
            text = len((system + prompt).encode("utf-8"))
            schema = len(json.dumps(Patch.model_json_schema()).encode("utf-8"))
            measured = count(system, prompt)
            rows.append({"case": name, "shape": shape, "fits_whole_file": True, "dropped": len(dropped), "prompt_bytes": text,
                         "estimate_tokens": (text + schema + 1) // 2, "measured_tokens": measured, "bytes_per_token": round(text / measured, 2),
                         "within_estimate": measured <= (text + schema + 1) // 2})
        print(json.dumps(rows[-1]), flush=True)
    measured = [r for r in rows if r["fits_whole_file"]]
    summary = {"limit": worker1.input_limit(), "prompts": len(measured), "over_estimate": sum(not r["within_estimate"] for r in measured),
               "over_limit": sum(r["measured_tokens"] > worker1.input_limit() for r in measured),
               "min_bytes_per_token": min(r["bytes_per_token"] for r in measured), "max_measured_tokens": max(r["measured_tokens"] for r in measured),
               "not_fitting_whole": [f"{r['case']} ({r['shape']})" for r in rows if not r["fits_whole_file"]]}
    out.write_text(json.dumps({**summary, "rows": rows}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False), "\nwritten:", out)


if __name__ == "__main__":
    main()
