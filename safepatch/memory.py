"""Conservative institutional memory. No model training and no automatic promotion.

Single control-process profile: all lifecycle/approval operations share Store.lock.
Examples remain untrusted data; an exact replay still runs the full verifier.
"""
import copy
import time
import uuid

from sqlalchemy import Column, Float, JSON, MetaData, String, Table, select, update

from safepatch.common import SOURCE, canonical, digest
from safepatch.policy import PolicyError


def context_for(case, files, finding):
    """Only facts from the trusted registry and baseline enter applicability checks.

    V0.1 intentionally requires identical build/test contracts. This is narrower
    than AST/dataflow applicability and may miss reusable examples.
    """
    return {
        "project": case.get("project", "owned-java-demo"),
        "kind": case["kind"], "rule_id": finding["rule_id"],
        "jdk": "17", "source_path": SOURCE,
        "build_sha256": digest(files["pom.xml"]),
        "contract_sha256": digest(canonical({p: digest(v) for p, v in files.items() if p.startswith("src/test/")})),
        "source_sha256": digest(files[SOURCE]),
    }


REQUIRED = ("project", "kind", "rule_id", "jdk", "source_path", "build_sha256", "contract_sha256")


def applicability(saved, current):
    if any(not saved.get(k) or not current.get(k) for k in REQUIRED):
        return "unknown"
    if any(saved[k] != current[k] for k in REQUIRED):
        return "incompatible"
    return "compatible"


class Memory:
    def __init__(self, store):
        self.store = store
        meta = MetaData()
        self.table = Table("patch_memory", meta, Column("id", String(32), primary_key=True),
                           Column("created", Float), Column("data", JSON, nullable=False))
        meta.create_all(store.engine)

    def all(self, project=None):
        with self.store.engine.connect() as conn:
            records = [r[0] for r in conn.execute(select(self.table.c.data).order_by(self.table.c.created.desc()))]
        return [r for r in records if project is None or r["context"]["project"] == project]

    def get(self, memory_id):
        with self.store.engine.connect() as conn:
            row = conn.execute(select(self.table.c.data).where(self.table.c.id == memory_id)).first()
        if row is None:
            raise KeyError(memory_id)
        return row[0]

    def promote(self, job, context, before, actor, rationale):
        if job.get("evaluation"):
            raise PolicyError("evaluation_job_cannot_enter_operational_memory")
        if job["status"] not in ("approved", "deployed") or not job.get("approval") or job["approval"]["decision"] != "approve":
            raise PolicyError("human_approved_job_required")
        approved = job["approval"]
        candidate = job["candidate"]
        if any(approved[k] != candidate[v] for k, v in (("candidate_commit", "commit"), ("artifact_sha256", "artifact_sha256"), ("policy_version", "policy_version"))):
            raise PolicyError("approval_scope_changed")
        if time.time() > approved["expires_at"]:
            raise PolicyError("approval_expired")
        attempt = next((a for a in reversed(job["attempts"]) if a.get("verification", {}).get("passed")), None)
        if not attempt or attempt["patch_sha256"] != candidate["patch_sha256"]:
            raise PolicyError("verified_patch_required")
        record = {"id": uuid.uuid4().hex, "state": "approved", "version": 1,
                  "created_at": time.time(), "context": context, "before": before,
                  "patch": attempt["proposal"]["patch"], "diff": candidate["diff"], "source_job": job["id"],
                  "model": attempt["proposal"].get("model"), "provenance": "human-approved-local-repair",
                  "evidence_sha256": candidate["evidence_sha256"],
                  "approval": copy.deepcopy(approved), "uses": [],
                  "events": [{"state": "approved", "actor": actor, "reason": rationale, "at": time.time()}]}
        with self.store.lock, self.store.engine.begin() as conn:
            for old in self.all(context["project"]):
                if old["source_job"] == job["id"]:
                    raise PolicyError("job_already_promoted")
            conn.execute(self.table.insert().values(id=record["id"], created=time.time(), data=record))
        return record

    def change(self, memory_id, state, actor, reason):
        if state not in ("quarantined", "revoked"):
            raise PolicyError("invalid_memory_transition")
        with self.store.lock, self.store.engine.begin() as conn:
            record = self.get(memory_id)
            if record["state"] == "revoked":
                raise PolicyError("revoked_memory_is_terminal")
            record.update(state=state, version=record["version"] + 1)
            record["events"].append({"state": state, "actor": actor, "reason": reason, "at": time.time()})
            conn.execute(update(self.table).where(self.table.c.id == memory_id).values(data=record))
        # Existing approvals become visibly stale. Deployed artifacts need a human
        # remediation decision; never silently change a running application.
        affected = []
        with self.store.lock:
            for job in self.store.all():
                if memory_id in job.get("memory_ids", []):
                    affected.append(job["id"])
                    def invalidate(j):
                        j["memory_alert"] = {"id": memory_id, "state": state, "at": time.time()}
                        if j["status"] in ("awaiting_review", "approved"):
                            j.update(status="needs_human", approval=None, reason="memory_no_longer_approved")
                    self.store.mutate(job["id"], invalidate)
        return {**record, "affected_jobs": affected}

    def assert_active(self, ids):
        for memory_id in ids:
            if self.get(memory_id)["state"] != "approved":
                raise PolicyError("memory_no_longer_approved")

    def use(self, memory_id, job_id):
        with self.store.lock, self.store.engine.begin() as conn:
            record = self.get(memory_id)
            if record["state"] != "approved":
                raise PolicyError("memory_no_longer_approved")
            if job_id not in record["uses"]:
                record["uses"].append(job_id)
                conn.execute(update(self.table).where(self.table.c.id == memory_id).values(data=record))

    def search(self, context, mode="guarded"):
        start = time.perf_counter()
        if mode == "off":
            return {"decision": "disabled", "selected": None, "duration_seconds": 0, "rejected": []}
        rejected, candidates = [], []
        for record in self.all(context["project"]):
            if record["state"] != "approved" or record["context"].get("rule_id") != context["rule_id"]:
                continue
            decision = applicability(record["context"], context)
            if mode == "guarded" and decision != "compatible":
                rejected.append({"id": record["id"], "decision": decision})
                continue
            candidates.append(record)
        # Prefer exact source, then newest. No semantic correctness score is made up.
        candidates.sort(key=lambda r: (r["context"].get("source_sha256") == context["source_sha256"], r["created_at"]), reverse=True)
        selected = candidates[0] if candidates else None
        return {"decision": "match" if selected else "no_match", "selected": selected,
                "rejected": rejected, "duration_seconds": round(time.perf_counter() - start, 6)}
