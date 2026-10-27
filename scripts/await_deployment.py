import argparse
import os
from pathlib import Path
import sys
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from safepatch.common import request

parser = argparse.ArgumentParser()
parser.add_argument("job_id")
parser.add_argument("--timeout", type=int, default=900)
args = parser.parse_args()
deadline = time.monotonic() + args.timeout
while time.monotonic() < deadline:
    j = request(os.environ.get("SAFEPATCH_URL", "http://127.0.0.1:8100") + "/v1/jobs/" + args.job_id, token=os.environ["SAFEPATCH_TOKEN"])
    if j["status"] == "deployed":
        print("Same approved artifact deployed:", j["deployment"]["artifact_sha256"])
        raise SystemExit(0)
    if j["status"] in ("rejected", "cancelled", "expired", "infrastructure_error", "needs_human"):
        raise SystemExit("Human/staging gate stopped: " + j["status"])
    time.sleep(5)
raise SystemExit("Human approval/staging wait timed out; no implicit approval was granted.")
