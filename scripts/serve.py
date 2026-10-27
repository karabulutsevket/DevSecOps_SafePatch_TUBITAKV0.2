"""Launch exactly one service, loading only that service's required credentials."""
import argparse
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
ROLES = {
    "orchestrator": ["WORKER1_TOKEN", "WORKER2_TOKEN", "DEPLOYER_TOKEN", "APPROVAL_SIGNING_KEY"],
    "worker1": ["WORKER1_TOKEN"],
    "worker2": ["WORKER2_TOKEN", "RUNNER_TOKEN", "ARTIFACT_READ_TOKEN"],
    "runner": ["RUNNER_TOKEN"],
    "deployer": ["DEPLOYER_TOKEN", "APPROVAL_SIGNING_KEY", "ARTIFACT_READ_TOKEN"],
}
PORTS = {"orchestrator": 8100, "worker1": 8101, "worker2": 8102, "runner": 8103, "deployer": 8104}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("service", choices=ROLES)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int)
    args = parser.parse_args()
    for role in ROLES[args.service]:
        os.environ.setdefault(role + "_FILE", str(ROOT / ".secrets" / role.lower()))
    if args.service == "orchestrator" and os.environ.get("DATABASE_PASSWORD_FILE"):
        from urllib.parse import quote
        password = Path(os.environ["DATABASE_PASSWORD_FILE"]).read_text().strip()
        os.environ["DATABASE_URL"] = "postgresql+psycopg://safepatch:" + quote(password, safe="") + "@" + os.environ.get("DATABASE_HOST", "db") + ":5432/safepatch"
    import uvicorn
    uvicorn.run(f"safepatch.{args.service}:app", host=args.host, port=args.port or PORTS[args.service], access_log=False, log_level="warning")
