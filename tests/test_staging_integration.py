"""Real JAR processes on a separate port, simulated humans; never live approval."""
import os
from pathlib import Path
import time

import httpx
import pytest

from safepatch import deployer
from safepatch.common import POLICY, ROOT, digest, seal
from safepatch.process import terminate

pytestmark = [pytest.mark.integration, pytest.mark.skipif(os.environ.get("RUN_JAVA_INTEGRATION") != "1", reason="Requires reference artifacts from Java integration suite")]


def test_same_artifact_deploy_and_rollback(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_ROOT", str(tmp_path))
    monkeypatch.setenv("STAGING_PORT", "18081")
    monkeypatch.setenv("ALLOW_TEST_DEPLOYMENT", "1")
    monkeypatch.setenv("APPROVAL_SIGNING_KEY", "test-only-signature-key" * 4)
    monkeypatch.delenv("APPROVAL_SIGNING_KEY_FILE", raising=False)
    monkeypatch.setattr(deployer, "process", None)
    files = [ROOT / ".runtime/test-verified-artifacts" / name for name in ("sql-01-reference-fix.jar", "path-01-reference-fix.jar")]
    assert all(f.exists() for f in files), "Run Java integration suite first"
    checksums = [digest(f.read_bytes()) for f in files]
    def fetch(checksum):
        file = files[checksums.index(checksum)]
        saved = deployer.runtime("staging/artifacts") / (checksum + ".jar")
        saved.write_bytes(file.read_bytes())
        return saved
    monkeypatch.setattr(deployer, "download", fetch)
    results = []
    try:
        for i, checksum in enumerate(checksums):
            approval = {"job_id": str(i) * 32, "candidate_commit": str(i) * 40, "artifact_sha256": checksum, "decision": "approve", "reviewer": "SIMULATED-TEST-REVIEWER", "policy_version": POLICY, "expires_at": time.time() + 120, "mode": "mock-test"}
            result = deployer.deploy(deployer.Deployment(approval=approval, signature=seal(approval, os.environ["APPROVAL_SIGNING_KEY"])))
            assert result["artifact_sha256"] == checksum
            assert result["built_after_approval"] is False
            results.append(result)
        rolled = deployer.rollback(deployer.Rollback(actor="SIMULATED-TEST-DEPLOYER"))
        assert rolled["artifact_sha256"] == checksums[0]
        with httpx.Client(trust_env=False) as client:
            assert client.get("http://127.0.0.1:18081/lookup", params={"input": "alice"}).json()["result"] == "alice"
        import json
        (ROOT / "evidence/staging-test.json").write_text(json.dumps({"mode": "mock-test-with-real-java-process", "human_approval": "simulated-only", "port": 18081, "deployments": results, "rollback": rolled, "same_bytes_verified": True}, indent=2), encoding="utf-8")
    finally:
        if deployer.process:
            terminate(deployer.process)
