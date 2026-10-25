"""Conservative institutional memory. No model training and no automatic promotion.

Single control-process profile: all lifecycle/approval operations share Store.lock.
Examples remain untrusted data; an exact replay still runs the full verifier.
"""
import copy
import time
import uuid

from sqlalchemy import Column, Float, JSON, MetaData, String, Table, select, update

from safepatch.common import canonical, digest
from safepatch.feedback import patch_caused
from safepatch.policy import PolicyError
from safepatch.signature import signature
from safepatch.weakness import family


def _bytes(files, path):
    # Git-backed baselines expose raw bytes (binary test resources included); plain dicts hold text.
    return files.raw(path) if hasattr(files, "raw") else files[path]


def context_for(case, files, finding):
    """Only facts from the trusted registry and baseline enter applicability checks.

    V0.1 intentionally requires identical build/test contracts. This is narrower
    than AST/dataflow applicability and may miss reusable examples. The weakness is
    its CWE family, not one scanner's rule id; `rule_id` is kept for traceability only.
    """
    source = finding["file"]
    spec = case.get("spec")
    tests = {p: digest(_bytes(files, p)) for p in files if p.startswith("src/test/") or "/src/test/" in p}
    pom = _bytes(files, "pom.xml") if "pom.xml" in files else None
    weakness = family(finding)
    return {
        "project": case.get("project", "owned-java-demo"),
        "cwe_family": weakness, "rule_id": finding["rule_id"],
        "jdk": spec.java if spec else "17", "source_path": source,
        "build_sha256": digest(pom) if pom is not None else None,
        "contract_sha256": digest(canonical(tests)),
        "source_sha256": digest(files[source]),
        # Read from the code, not the scanner; recorded now, used for adaptive matching next (week 4).
        "signature": signature(files[source], weakness, finding.get("line"), pom),
    }


REQUIRED = ("project", "cwe_family", "jdk", "source_path", "build_sha256", "contract_sha256")


def normalized(context):
    """Records written before week 4 carry a rule id and a lab kind; their family comes from the rule."""
    return context if "cwe_family" in context else {**context, "cwe_family": family({"rule_id": context.get("rule_id")})}


def applicability(saved, current):
    saved, current = normalized(saved), normalized(current)
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
        # Negative evidence lives apart from approved repairs and is never offered as an example.
        self.failure_table = Table("failure_memory", meta, Column("id", String(32), primary_key=True),
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
        # Nobody labels their own patch as institutional knowledge.
        if candidate.get("author") is not None and actor == candidate["author"]:
            raise PolicyError("author_cannot_promote_own_patch")
        human = attempt["proposal"].get("mode") == "human-authored"
        record = {"id": uuid.uuid4().hex, "state": "approved", "version": 1,
                  "created_at": time.time(), "context": context, "before": before,
                  "patch": attempt["proposal"]["patch"], "diff": candidate["diff"], "source_job": job["id"],
                  "model": attempt["proposal"].get("model"), "author": attempt["proposal"].get("author"),
                  "provenance": "human-authored" if human else "human-approved-local-repair",
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

    def failure_records(self, project=None):
        with self.store.engine.connect() as conn:
            records = [r[0] for r in conn.execute(select(self.failure_table.c.data).order_by(self.failure_table.c.created.desc()))]
        return [r for r in records if project is None or r["context"]["project"] == project]

    def record_failure(self, job, context, attempt, strategy):
        """A candidate that failed verification in this context: candidate, context, cause, evidence.

        One record per (source, patch); a repeat in another job adds an occurrence. Evaluation
        jobs never write operational memory.
        """
        if job.get("evaluation") or not patch_caused(attempt["verification"], attempt["failure"]):
            return None
        proposal = attempt["proposal"]
        occurrence = {"job_id": job["id"], "attempt": attempt["number"], "category": attempt["failure"]["category"],
                      "evidence_sha256": digest(canonical(attempt["verification"])), "at": time.time()}
        key = (context["source_path"], context["source_sha256"], attempt["patch_sha256"])
        with self.store.lock, self.store.engine.begin() as conn:
            for old in self.failure_records(context["project"]):
                if (old["context"]["source_path"], old["context"]["source_sha256"], old["patch_sha256"]) == key:
                    if not any((o["job_id"], o["attempt"]) == (job["id"], attempt["number"]) for o in old["occurrences"]):
                        old["occurrences"].append(occurrence)
                        conn.execute(update(self.failure_table).where(self.failure_table.c.id == old["id"]).values(data=old))
                    return old["id"]
            record = {"id": uuid.uuid4().hex, "schema": "safepatch-failure/1", "created_at": time.time(),
                      "context": context, "context_sha256": digest(canonical({k: context.get(k) for k in REQUIRED})),
                      "patch_sha256": attempt["patch_sha256"], "diff": attempt["diff"], "changed_lines": attempt["changed_lines"],
                      "origin": proposal.get("mode"), "author": proposal.get("author"), "model": proposal.get("model"),
                      "strategy": strategy, "retry": attempt.get("retry"), "failure": attempt["failure"],
                      "memory_ids": list(job.get("memory_ids", [])), "occurrences": [occurrence]}
            conn.execute(self.failure_table.insert().values(id=record["id"], created=time.time(), data=record))
        return record["id"]

    def failures(self, context, limit=20):
        """Failures for this exact source first, then for the same contract; summaries only.
        Only `compatible` contexts count, as for approved repairs."""
        found = []
        for record in self.failure_records(context["project"]):
            if applicability(record["context"], context) != "compatible":
                continue
            relation = "same_source" if record["context"].get("source_sha256") == context["source_sha256"] else "same_context"
            found.append({"id": record["id"], "relation": relation, "category": record["failure"]["category"],
                          "patch_sha256": record["patch_sha256"], "origin": record["origin"], "occurrences": len(record["occurrences"])})
        found.sort(key=lambda f: f["relation"] != "same_source")
        return found[:limit]

    def search(self, context, mode="guarded"):
        start = time.perf_counter()
        if mode == "off":
            return {"decision": "disabled", "selected": None, "duration_seconds": 0, "rejected": []}
        rejected, candidates = [], []
        for record in self.all(context["project"]):
            if record["state"] != "approved" or normalized(record["context"]).get("cwe_family") != normalized(context).get("cwe_family"):
                continue
            decision = applicability(record["context"], context)
            if mode == "guarded" and decision != "compatible":
                rejected.append({"id": record["id"], "decision": decision})
                continue
            candidates.append(record)
        # Prefer exact source, then newest. No semantic correctness score is made up.
        candidates.sort(key=lambda r: (r["context"].get("source_sha256") == context["source_sha256"], r["created_at"]), reverse=True)
        selected = candidates[0] if candidates else None
        # Recorded for review and evidence; the model does not see failures yet (roadmap week 5).
        failures = self.failures(context)
        return {"decision": "match" if selected else "no_match", "selected": selected,
                "rejected": rejected, "failures": failures, "duration_seconds": round(time.perf_counter() - start, 6)}
