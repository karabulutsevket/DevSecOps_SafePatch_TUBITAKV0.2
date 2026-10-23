"""Time-budget-controlled comparison; never invent missing second-model outcomes."""
import argparse
import json
from pathlib import Path
import sys
import time
import uuid
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from safepatch.common import request

parser = argparse.ArgumentParser()
parser.add_argument("--token-file", required=True)
parser.add_argument("--case", default="sql-01")
parser.add_argument("--url", default="http://127.0.0.1:8100")
parser.add_argument("--review-model-available", action="store_true")
parser.add_argument("--out", default="evidence/experiment.json")
args = parser.parse_args()
token = Path(args.token_file).read_text().strip()
results = []
for name, attempts, review in (("one_attempt", 1, False), ("same_model_retries", 3, False), ("different_model_advisory", 3, True)):
    if review and not args.review_model_available:
        results.append({"arm": name, "status": "not_executed", "reason": "second_local_model_not_prepared"})
        continue
    j = request(args.url + "/v1/jobs", "POST", token=token, body={"case_id": args.case, "scanner": "semgrep", "max_attempts": attempts, "second_review": review, "idempotency_key": "experiment-" + uuid.uuid4().hex})
    while j["status"] in ("queued", "scanning", "patching", "verifying"):
        time.sleep(3)
        j = request(args.url + "/v1/jobs/" + j["id"], token=token)
    results.append({"arm": name, "job": j, "allocated_seconds": j["deadline"] - j["started_at"]})
output = Path(args.out)
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps({"mode": "real-local-model", "fairness": "Same configured wall-time cap per arm; sequential single-GPU execution; no cost or quality gain inferred", "results": results, "human_time_saved": None}, indent=2), encoding="utf-8")
print(output.resolve())
