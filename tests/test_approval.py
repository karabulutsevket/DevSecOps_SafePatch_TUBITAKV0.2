import time

import pytest

from conftest import headers
from safepatch.common import POLICY, seal, digest, canonical
from safepatch.acceptance import manifest
from safepatch.deployer import check_approval


def ready(db, job):
    candidate = {"commit": "a" * 40, "artifact_sha256": "b" * 64, "patch_sha256": "c" * 64, "policy_version": POLICY, "diff": "mock-test"}
    evidence = manifest(job, {"passed": True, "candidate_commit": candidate["commit"], "artifact_sha256": candidate["artifact_sha256"]}, candidate["patch_sha256"])
    candidate["evidence_sha256"] = digest(canonical(evidence))
    db.mutate(job["id"], lambda j: j.update(status="awaiting_review", candidate=candidate, acceptance_manifest=evidence, review_expires_at=time.time() + 300))
    return {"candidate_commit": candidate["commit"], "artifact_sha256": candidate["artifact_sha256"], "policy_version": POLICY, "decision": "approve"}


def test_unauthenticated_rejected(api):
    client, db, j = api
    assert client.get("/v1/jobs/" + j["id"]).status_code == 401


def test_worker_or_submitter_cannot_approve(api):
    client, db, j = api
    decision = ready(db, j)
    assert client.post(f'/v1/jobs/{j["id"]}/approval', headers=headers("developer"), json=decision).status_code == 403
    assert client.post(f'/v1/jobs/{j["id"]}/approval', headers={"Authorization": "Bearer worker-token"}, json=decision).status_code == 401


def test_unapproved_deploy_blocked(api):
    client, db, j = api
    ready(db, j)
    assert client.post(f'/v1/jobs/{j["id"]}/deploy', headers=headers("deployer")).status_code == 409


@pytest.mark.parametrize("field,value", [("artifact_sha256", "c" * 64), ("candidate_commit", "c" * 40), ("policy_version", "v0")])
def test_approval_binding(api, field, value):
    client, db, j = api
    decision = ready(db, j)
    decision[field] = value
    assert client.post(f'/v1/jobs/{j["id"]}/approval', headers=headers("reviewer"), json=decision).status_code == 409


def test_expired_review(api):
    client, db, j = api
    decision = ready(db, j)
    db.mutate(j["id"], lambda x: x.update(review_expires_at=time.time() - 1))
    assert client.post(f'/v1/jobs/{j["id"]}/approval', headers=headers("reviewer"), json=decision).status_code == 409


def test_approval_actor_is_backend_identity(api):
    client, db, j = api
    decision = ready(db, j)
    response = client.post(f'/v1/jobs/{j["id"]}/approval', headers=headers("reviewer"), json=decision)
    assert response.status_code == 200
    assert response.json()["approval"]["reviewer"] == "reviewer"
    assert response.json()["mode"] == "mock-test"


def test_changed_candidate_revokes_effect_of_approval(api):
    client, db, j = api
    decision = ready(db, j)
    client.post(f'/v1/jobs/{j["id"]}/approval', headers=headers("reviewer"), json=decision)
    db.mutate(j["id"], lambda x: x["candidate"].update(artifact_sha256="c" * 64))
    assert client.post(f'/v1/jobs/{j["id"]}/deploy', headers=headers("deployer")).status_code == 409


def test_signed_approval_tampering():
    key = "only-for-test" * 8
    payload = {"decision": "approve", "policy_version": POLICY, "reviewer": "test", "expires_at": time.time() + 30, "mode": "real-local-model", "artifact_sha256": "a" * 64}
    signature = seal(payload, key)
    check_approval(payload, signature, key)
    payload["artifact_sha256"] = "b" * 64
    with pytest.raises(ValueError, match="signature"):
        check_approval(payload, signature, key)


def test_mock_deployment_refused_by_default(monkeypatch):
    monkeypatch.delenv("ALLOW_TEST_DEPLOYMENT", raising=False)
    payload = {"decision": "approve", "policy_version": POLICY, "reviewer": "test", "expires_at": time.time() + 30, "mode": "mock-test"}
    key = "test-key" * 8
    with pytest.raises(ValueError, match="mock_artifact"):
        check_approval(payload, seal(payload, key), key)


def test_evidence_html_escapes_untrusted_content(api):
    client, db, j = api
    db.mutate(j["id"], lambda x: x.update(reason="<script>alert(1)</script>"))
    result = client.get(f'/v1/jobs/{j["id"]}/evidence.html', headers=headers("developer"))
    assert "<script>" not in result.text
    assert "&lt;script&gt;" in result.text
