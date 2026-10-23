"""Export local evidence without credentials or raw prompts. Preserves failed jobs."""
import json
from pathlib import Path
import shutil
import sys
import xml.etree.ElementTree as ET
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from safepatch.common import ROOT, request

token = (ROOT / ".secrets/developer.token").read_text().strip()
jobs = request("http://127.0.0.1:8100/v1/jobs", token=token)
summary = []
for job in jobs:
    target = ROOT / "evidence" / job["id"]
    target.mkdir(exist_ok=True)
    (target / "evidence.json").write_text(json.dumps(job, ensure_ascii=False, indent=2), encoding="utf-8")
    import httpx
    with httpx.Client(trust_env=False, timeout=10) as client:
        html = client.get(f'http://127.0.0.1:8100/v1/jobs/{job["id"]}/evidence.html', headers={"Authorization": "Bearer " + token})
        html.raise_for_status()
    (target / "evidence.html").write_text(html.text, encoding="utf-8")
    if job.get("candidate"):
        (target / "candidate.diff").write_text(job["candidate"]["diff"], encoding="utf-8")
    for workspace in (ROOT / ".runtime/runner-work").glob(job["id"] + "-*"):
        dest = target / "raw" / workspace.name
        dest.mkdir(parents=True, exist_ok=True)
        for file in list((workspace / "target/surefire-reports").glob("TEST-*.xml")) + list(workspace.glob("semgrep.json")):
            shutil.copyfile(file, dest / file.name)
    summary.append({"id": job["id"], "case_id": job["case_id"], "mode": job["mode"], "status": job["status"], "reason": job.get("reason"), "attempts": job["attempt_count"], "seconds": job.get("duration_seconds"), "approval": job["approval"], "artifact_sha256": job.get("candidate", {}).get("artifact_sha256")})
(ROOT / "evidence/real-model-runs.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(summary, ensure_ascii=False, indent=2))
