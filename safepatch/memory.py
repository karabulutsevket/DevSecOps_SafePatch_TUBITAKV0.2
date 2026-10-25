"""Conservative institutional memory. No model training and no automatic promotion.

Single control-process profile: all lifecycle/approval operations share Store.lock.
Examples remain untrusted data; an exact replay still runs the full verifier.
"""
import copy
import time
import uuid

from sqlalchemy import Column, Float, JSON, MetaData, String, Table, select, update

from safepatch.acceptance import untolerated
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


# Exact reuse (replay without the model) needs the same file, build and test contract; the
# hashes serve only this. Adaptive reuse (an example for the model on other code) needs the
# same weakness shape instead: the structural signature, wherever the file is.
REQUIRED = ("project", "cwe_family", "jdk", "source_path", "build_sha256", "contract_sha256")
ADAPTIVE = ("project", "cwe_family", "jdk")
SHAPE = ("sink", "construction", "library", "library_version")


def normalized(context):
    """Records written before week 4 carry a rule id and a lab kind; their family comes from the rule."""
    return context if "cwe_family" in context else {**context, "cwe_family": family({"rule_id": context.get("rule_id")})}


def decide(saved, current, fields):
    if any(not saved.get(k) or not current.get(k) for k in fields):
        return "unknown"
    if any(saved[k] != current[k] for k in fields):
        return "incompatible"
    return "compatible"


def applicability(saved, current):
    """Exact-reuse decision: same file, build and test contract (the source may still differ)."""
    return decide(normalized(saved), normalized(current), REQUIRED)


def adaptability(saved, current):
    """Adaptive-reuse decision: same project, weakness and JDK, and the same signature shape."""
    decision = decide(normalized(saved), normalized(current), ADAPTIVE)
    if decision != "compatible":
        return decision
    shapes = [{k: c["signature"].get(k) for k in SHAPE} if c.get("signature") else None for c in (saved, current)]
    if None in shapes:
        return "unknown"
    return "compatible" if shapes[0] == shapes[1] else "incompatible"


def use_of(saved, current):
    """How a guarded job may use an approved record: replay, example, example_unknown, or None."""
    if applicability(saved, current) == "compatible" and saved.get("source_sha256") == current.get("source_sha256"):
        return "replay"
    return {"compatible": "example", "unknown": "example_unknown"}.get(adaptability(saved, current))


def evidence_vector(job, attempt):
    """What the record's own acceptance proved (roadmap week 4). None means not recorded, never 'failed'."""
    verified = attempt.get("verification") or {}
    suite = lambda result: {"passed": result.get("passed"), "tests": result.get("tests")} if result else None
    findings = [f for scan in verified.get("scans", []) for f in scan.get("findings", [])]
    approval = job.get("approval") or {}
    return {"build": (verified.get("build") or {}).get("passed"),
            "behavior": suite(verified.get("behavior")), "security": suite(verified.get("security")),
            "rescan": {"tools": sorted({s.get("tool") for s in verified.get("scans", []) if s.get("tool")}),
                       "remaining": len(untolerated(findings, verified.get("tolerated", []))),
                       "tolerated": len(verified.get("tolerated", []))} if "scans" in verified else None,
            "approval": {"reviewer": approval.get("reviewer"), "at": approval.get("approved_at")},
            "reuse": {"verified": 0, "failed": 0, "inconclusive": 0, "approved_by_reviewer": 0, "rejected_by_reviewer": 0}}


# How a job that used a record ended, as evidence about that record. Infrastructure trouble,
# deadlines, a missing witness or a cancellation say nothing about the record itself.
INCONCLUSIVE = ("job_deadline_exceeded", "token_budget_exhausted", "security_witness_missing", "memory_no_longer_approved")


def reuse_result(job):
    if job["status"] in ("awaiting_review", "approved", "deployed"):
        return "verified"
    reason = job.get("reason") or ""
    if job["status"] in ("infrastructure_error", "cancelled", "expired") or reason in INCONCLUSIVE or reason.startswith("verification_infrastructure"):
        return "inconclusive"
    return "failed"


def migrated_context(context, before):
    """A pre-week-4 context with the week-4 fields: the family from its rule, the signature from the stored source."""
    upgraded = normalized(context)
    if "signature" not in upgraded:
        upgraded = {**upgraded, "signature": signature(before, upgraded["cwe_family"]) if before else None}
    return upgraded


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
                  "evidence_sha256": candidate["evidence_sha256"], "evidence": evidence_vector(job, attempt),
                  "approval": copy.deepcopy(approved), "uses": [], "reuse": [],
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

    def use(self, memory_id, job_id, how=None):
        with self.store.lock, self.store.engine.begin() as conn:
            record = self.get(memory_id)
            if record["state"] != "approved":
                raise PolicyError("memory_no_longer_approved")
            if job_id not in record["uses"]:
                record["uses"].append(job_id)
                record.setdefault("reuse", []).append({"job_id": job_id, "use": how, "result": "pending", "review": None, "at": time.time()})
                conn.execute(update(self.table).where(self.table.c.id == memory_id).values(data=record))

    def settle(self, memory_id, job_id, result=None, review=None):
        """Record how a job that used this record ended (and the reviewer's later decision).
        Runs after the job finished, so a missing record or entry is skipped, never raised."""
        with self.store.lock, self.store.engine.begin() as conn:
            try:
                record = self.get(memory_id)
            except KeyError:
                return None
            entry = next((e for e in record.get("reuse", []) if e["job_id"] == job_id), None)
            if entry is None:
                return record
            if result:
                entry["result"] = result
            if review:
                entry["review"] = review
            entry["at"] = time.time()
            if record.get("evidence"):
                counts = {k: 0 for k in ("verified", "failed", "inconclusive")}
                for e in record["reuse"]:
                    if e["result"] in counts:
                        counts[e["result"]] += 1
                record["evidence"]["reuse"] = {**counts, "approved_by_reviewer": sum(e.get("review") == "approve" for e in record["reuse"]),
                                               "rejected_by_reviewer": sum(e.get("review") == "reject" for e in record["reuse"])}
            conn.execute(update(self.table).where(self.table.c.id == memory_id).values(data=record))
            return record

    def recovered_evidence(self, record):
        """The evidence vector of an older record, rebuilt from its source job if that job is still stored."""
        try:
            job = self.store.get(record["source_job"])
        except KeyError:
            return None
        passed = [a for a in job.get("attempts", []) if (a.get("verification") or {}).get("passed")]
        attempt = next((a for a in passed if a.get("proposal", {}).get("patch") == record.get("patch")), passed[-1] if passed else None)
        return evidence_vector({"approval": record.get("approval")}, attempt) if attempt else None

    def migrate(self, dry_run=False):
        """Bring records written before week 4 to the current schema (roadmap week 4).

        Approved records become a new version whose event keeps the previous context; what
        cannot be completed stays None (unknown). Running it twice changes nothing.
        """
        report = {"memory": {"total": 0, "migrated": [], "unknown_family": [], "no_signature": [], "no_evidence": []},
                  "failures": {"total": 0, "migrated": [], "unknown_family": []}}
        now = time.time()
        with self.store.lock:
            for record in self.all():
                report["memory"]["total"] += 1
                if all(k in record["context"] for k in ("cwe_family", "signature")) and "evidence" in record and "reuse" in record:
                    continue
                upgraded = copy.deepcopy(record)
                upgraded["context"] = migrated_context(record["context"], record.get("before"))
                upgraded.setdefault("evidence", self.recovered_evidence(record))
                upgraded.setdefault("reuse", [{"job_id": j, "use": None, "result": "unrecorded", "review": None, "at": None} for j in record.get("uses", [])])
                upgraded["version"] = record["version"] + 1
                upgraded["events"].append({"state": record["state"], "actor": "safepatch-migration", "reason": "Hafta 4 şeması: cwe_family, signature, evidence",
                                           "at": now, "migration": "week-4", "previous_context": record["context"]})
                for key, missing in (("migrated", False), ("unknown_family", not upgraded["context"].get("cwe_family")),
                                     ("no_signature", not upgraded["context"].get("signature")), ("no_evidence", not upgraded["evidence"])):
                    if key == "migrated" or missing:
                        report["memory"][key].append(record["id"])
                if not dry_run:
                    with self.store.engine.begin() as conn:
                        conn.execute(update(self.table).where(self.table.c.id == record["id"]).values(data=upgraded))
            for record in self.failure_records():
                report["failures"]["total"] += 1
                if all(k in record["context"] for k in ("cwe_family", "signature")):
                    continue
                # Failure records keep no source, so their signature stays unknown.
                upgraded = {**record, "context": migrated_context(record["context"], None),
                            "migration": {"name": "week-4", "at": now, "previous_context": record["context"]}}
                upgraded["context_sha256"] = digest(canonical({k: upgraded["context"].get(k) for k in REQUIRED}))
                report["failures"]["migrated"].append(record["id"])
                if not upgraded["context"].get("cwe_family"):
                    report["failures"]["unknown_family"].append(record["id"])
                if not dry_run:
                    with self.store.engine.begin() as conn:
                        conn.execute(update(self.failure_table).where(self.failure_table.c.id == record["id"]).values(data=upgraded))
        return report

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
        """Failures for this exact source, then the same contract, then the same signature shape
        elsewhere; summaries only. `unknown` contexts never count as a lesson."""
        found, order = [], ("same_source", "same_context", "same_shape")
        for record in self.failure_records(context["project"]):
            if applicability(record["context"], context) == "compatible":
                relation = "same_source" if record["context"].get("source_sha256") == context["source_sha256"] else "same_context"
            elif adaptability(record["context"], context) == "compatible":
                relation = "same_shape"
            else:
                continue
            found.append({"id": record["id"], "relation": relation, "category": record["failure"]["category"],
                          "patch_sha256": record["patch_sha256"], "origin": record["origin"], "occurrences": len(record["occurrences"])})
        found.sort(key=lambda f: order.index(f["relation"]))
        return found[:limit]

    def search(self, context, mode="guarded"):
        start = time.perf_counter()
        if mode == "off":
            return {"decision": "disabled", "selected": None, "duration_seconds": 0, "rejected": []}
        rejected, candidates, considered = [], [], []
        for record in self.all(context["project"]):
            if record["state"] != "approved" or normalized(record["context"]).get("cwe_family") != normalized(context).get("cwe_family"):
                continue
            decisions = {"id": record["id"], "exact": applicability(record["context"], context), "adaptive": adaptability(record["context"], context)}
            # naive (arm B): any record of the family is an example; guarded (arm C): the rules above.
            use = "example" if mode != "guarded" else use_of(record["context"], context)
            considered.append({**decisions, "use": use})
            if use is None:
                rejected.append(decisions)
                continue
            candidates.append((use, record))
        # Replay first, then a compatible example, then an unknown one; newest within each.
        # No semantic correctness score is made up.
        rank = ("replay", "example", "example_unknown")
        candidates.sort(key=lambda c: (rank.index(c[0]), -c[1]["created_at"]))
        use, selected = candidates[0] if candidates else (None, None)
        # Recorded for review and evidence; the model does not see failures yet (roadmap week 5).
        failures = self.failures(context)
        return {"decision": "match" if selected else "no_match", "use": use, "selected": selected, "considered": considered,
                "rejected": rejected, "failures": failures, "duration_seconds": round(time.perf_counter() - start, 6)}
