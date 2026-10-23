import argparse
import json
import os
from pathlib import Path
import sys
import time
import uuid

import httpx
from safepatch.common import local_url


def main():
    parser = argparse.ArgumentParser(description="Yerel SafePatch istemcisi; kimlik ortamdan veya dosyadan alınır")
    parser.add_argument("--url", default=os.environ.get("SAFEPATCH_URL", "http://127.0.0.1:8100"))
    parser.add_argument("--token-file", default=os.environ.get("SAFEPATCH_TOKEN_FILE"))
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("cases")
    create = sub.add_parser("start")
    create.add_argument("case_id")
    create.add_argument("--scanner", choices=["builtin", "semgrep", "sonarqube+semgrep"], default="semgrep")
    create.add_argument("--key", default=None)
    create.add_argument("--attempts", type=int, default=3, choices=[1, 2, 3])
    create.add_argument("--second-review", action="store_true")
    for action in ("show", "wait", "cancel", "approve", "reject", "deploy", "evidence"):
        child = sub.add_parser(action)
        child.add_argument("job_id")
        if action == "wait":
            child.add_argument("--timeout", type=int, default=1300)
        if action == "evidence":
            child.add_argument("--out", default="evidence")
    sub.add_parser("rollback")
    args = parser.parse_args()
    token = Path(args.token_file).read_text().strip() if args.token_file else os.environ.get("SAFEPATCH_TOKEN")
    if not token:
        parser.error("--token-file veya SAFEPATCH_TOKEN gerekli")
    url = local_url(args.url)
    with httpx.Client(base_url=url, headers={"Authorization": "Bearer " + token}, trust_env=False, follow_redirects=False, timeout=100) as client:
        def call(method, path, body=None):
            resp = client.request(method, path, json=body)
            if resp.status_code >= 400:
                print(resp.text, file=sys.stderr)
                raise SystemExit(1)
            return resp.json()
        action = args.action
        if action == "cases":
            result = call("GET", "/v1/cases")
        elif action == "start":
            result = call("POST", "/v1/jobs", {"case_id": args.case_id, "scanner": args.scanner, "idempotency_key": args.key or uuid.uuid4().hex, "max_attempts": args.attempts, "second_review": args.second_review})
        elif action == "rollback":
            result = call("POST", "/v1/staging/rollback")
        else:
            path = "/v1/jobs/" + args.job_id
            if action == "show":
                result = call("GET", path)
            elif action == "wait":
                end = time.monotonic() + args.timeout
                while True:
                    result = call("GET", path)
                    if result["status"] not in ("queued", "scanning", "patching", "verifying", "deploying"):
                        break
                    if time.monotonic() >= end:
                        raise SystemExit("İstemci bekleme süresi doldu; iş sunucuda devam edebilir")
                    time.sleep(2)
            elif action in ("approve", "reject"):
                job = call("GET", path)
                c = job.get("candidate")
                if not c:
                    raise SystemExit("İncelenebilir aday yok")
                result = call("POST", path + "/approval", {"candidate_commit": c["commit"], "artifact_sha256": c["artifact_sha256"], "policy_version": c["policy_version"], "decision": "approve" if action == "approve" else "reject", "comment": "Explicit human CLI decision"})
            elif action == "evidence":
                output = Path(args.out) / args.job_id
                output.mkdir(parents=True, exist_ok=True)
                result = call("GET", path + "/evidence.json")
                (output / "evidence.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
                resp = client.get(path + "/evidence.html")
                resp.raise_for_status()
                (output / "evidence.html").write_text(resp.text, encoding="utf-8")
                if result.get("candidate"):
                    (output / "candidate.diff").write_text(result["candidate"]["diff"], encoding="utf-8")
                result = {"saved": str(output.resolve())}
            else:
                result = call("POST", path + "/" + action)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
