"""Evidence binding is separate from model generation and mutable review state."""
from safepatch.common import POLICY, canonical, digest
from safepatch.policy import PolicyError


def manifest(job, verified, patch_sha256):
    return {"schema": "safepatch-evidence-v1", "job_id": job["id"],
            "base_commit": job["base_commit"], "policy": POLICY,
            "patch_sha256": patch_sha256, "verification": verified,
            "memory_ids": job.get("memory_ids", []), "mode": job["mode"]}


def check_evidence(job):
    candidate = job.get("candidate", {})
    evidence = job.get("acceptance_manifest")
    if not evidence or digest(canonical(evidence)) != candidate.get("evidence_sha256"):
        raise PolicyError("acceptance_evidence_missing_or_changed")
    if evidence["patch_sha256"] != candidate["patch_sha256"] or evidence["base_commit"] != job["base_commit"] or evidence["policy"] != POLICY:
        raise PolicyError("acceptance_scope_changed")
    v = evidence["verification"]
    if v.get("candidate_commit") != candidate["commit"] or v.get("artifact_sha256") != candidate["artifact_sha256"] or not v.get("passed"):
        raise PolicyError("verified_artifact_changed")
    if evidence.get("memory_ids") != job.get("memory_ids", []):
        raise PolicyError("memory_provenance_changed")
