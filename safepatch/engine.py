import difflib
import time

from safepatch.common import POLICY, Patch, canonical, digest, remaining, request, secret, setting
from safepatch.memory import Memory, context_for
from safepatch.acceptance import manifest
from safepatch.feedback import classify, guidance_for, imitates_note
from safepatch.policy import PolicyError, validate_patch
from safepatch.project import is_protected
from safepatch.repository import allowed_files, baseline

TERMINAL = {"awaiting_review", "rejected", "needs_human", "infrastructure_error", "cancelled", "expired", "approved", "deployed"}
# v01: original loop. sampling: retries at higher temperature. guided: plus classified
# feedback and static guidance. guided+context: plus read-only sibling sources.
STRATEGIES = ("v01", "sampling", "guided", "guided+context")


def read_only_context(files, target, limit=8000):
    """Sibling sources in the finding's package; the model may read them, never edit."""
    folder = target.rpartition("/")[0]
    context, size = {}, 0
    for path in sorted(files):
        if path != target and path.endswith(".java") and path.rpartition("/")[0] == folder and not is_protected(path):
            try:
                content = files[path]
            except PolicyError:
                continue
            if size + len(content) <= limit:
                context[path] = content
                size += len(content)
    return context


EXPERT_ATTEMPTS = 3


def expert_scope(job):
    """What a human may patch: the finding's file under the descriptor rules, as for the model."""
    if job.get("evaluation"):
        raise PolicyError("evaluation_job_cannot_take_expert_patch")
    initial = job.get("baseline") or {}
    if not initial.get("baseline_valid"):
        raise PolicyError("baseline_not_valid")
    finding = initial["scans"][0]["findings"][0]
    case, files = baseline(job["case_id"], job["base_commit"])
    return case, files, finding, allowed_files(case["spec"], files, finding.get("file"))


def check_expert_patch(job, patch):
    """Submission checks; the engine repeats the policy check before verification."""
    if job["status"] != "needs_human":
        raise PolicyError("job_not_waiting_for_a_human")
    if sum(a.get("proposal", {}).get("mode") == "human-authored" for a in job["attempts"]) >= EXPERT_ATTEMPTS:
        raise PolicyError("expert_attempt_budget_exhausted")
    _, files, _, allowed = expert_scope(job)
    meta = validate_patch(files, patch, allowed=allowed)
    # Approved patches can reach later prompts through memory; keep forged notes out.
    if imitates_note(patch.rationale, *(e.content for e in patch.edits)):
        raise PolicyError("suspected_prompt_injection")
    return meta


def changed_lines(before, after, limit=1500):
    """Previous attempt as changed lines only (no context, no file headers)."""
    lines = list(difflib.unified_diff(before.splitlines(True), after.splitlines(True), n=0))[2:]
    return "".join(lines)[:limit]


def retry_options(strategy, kind, attempt, failure, context_files):
    """Extra worker1 fields per strategy; v01 sends none so its requests stay unchanged."""
    if strategy == "v01":
        return {}
    options = {"temperature": 0.0 if attempt == 1 else float(setting("RETRY_TEMPERATURE", "0.4"))}
    if strategy.startswith("guided") and failure:
        options["guidance"] = guidance_for(kind, failure, attempt - 2)
    if context_files:
        options["context_files"] = context_files
    return options


class Engine:
    def __init__(self, store, call=request):
        self.store, self.call = store, call
        self.memory = Memory(store)

    def active(self, job_id):
        job = self.store.get(job_id)
        if job["status"] in ("cancelled", "expired"):
            raise InterruptedError("cancelled")
        remaining(job["deadline"])
        return job

    def set(self, job_id, status, **fields):
        def change(job):
            if job["status"] == "cancelled":
                return
            job.update(fields, status=status)
            job["events"].append({"time": time.time(), "status": status})
        return self.store.mutate(job_id, change)

    def worker(self, name, path, body, deadline):
        port = {"worker1": 8101, "worker2": 8102}[name]
        return self.call(setting(name.upper() + "_URL", f"http://127.0.0.1:{port}") + path, "POST", token=secret(name.upper() + "_TOKEN"), body=body, timeout=remaining(deadline, 1200))

    def run(self, job_id):
        try:
            self._run(job_id)
        except InterruptedError:
            pass
        except PolicyError as exc:
            self.set(job_id, "rejected", reason=str(exc))
        except TimeoutError:
            self.set(job_id, "needs_human", reason="job_deadline_exceeded")
        except Exception as exc:
            # Never leak network URLs, tokens, raw model responses, or arbitrary code logs.
            self.set(job_id, "infrastructure_error", reason="dependency_failure:" + type(exc).__name__)

    def accept(self, job_id, verified, meta, origin, author=None):
        current = self.active(job_id)
        self.memory.assert_active(current.get("memory_ids", []))
        acceptance_manifest = manifest(current, verified, meta["patch_sha256"], origin, author)
        self.store.mutate(job_id, lambda j: j.update(acceptance_manifest=acceptance_manifest))
        review = None
        if current.get("second_review"):
            try:
                review = self.worker("worker1", "/advisory", {"diff": meta["diff"], "deadline": current["deadline"]}, current["deadline"])
            except Exception:
                review = {"status": "not_executed_or_failed", "authority": "advisory-only"}
        self.active(job_id)
        self.set(job_id, "awaiting_review", candidate={"evidence_sha256": digest(canonical(acceptance_manifest)), "commit": verified["candidate_commit"], "artifact_sha256": verified["artifact_sha256"], "patch_sha256": meta["patch_sha256"], "policy_version": POLICY, "diff": meta["diff"], "review_repository": verified["review_repository"], "review_branch": verified["review_branch"], "origin": origin, "author": author}, advisory=review, review_expires_at=time.time() + int(setting("REVIEW_TTL_SECONDS", "86400")), duration_seconds=round(time.time() - current["started_at"], 3))

    def _run_expert(self, job):
        """A human-authored patch: no model call, the same policy and verifier as a model patch."""
        job_id, pending = job["id"], job["pending_expert_patch"]
        case, files, finding, allowed = expert_scope(job)
        target = finding["file"]
        self.memory.assert_active(job.get("memory_ids", []))
        patch = Patch.model_validate(pending["patch"])
        meta = validate_patch(files, patch, allowed=allowed)
        number = max((a["number"] for a in job["attempts"]), default=0) + 1
        record = {"number": number, "proposal": {"mode": "human-authored", "patch": patch.model_dump(), "author": pending["author"], "submitted_at": pending["submitted_at"]}, **meta}
        self.set(job_id, "verifying", pending_expert_patch=None)
        verified = self.worker("worker2", "/verify", {"job_id": job_id, "case_id": job["case_id"], "base_commit": job["base_commit"], "deadline": job["deadline"], "scanner": job["scanner"], "attempt": number, "patch": patch.model_dump(), "target_file": target}, job["deadline"])
        current = self.active(job_id)
        record.update(verification=verified, failure=None if verified.get("passed") else classify(verified))
        lesson = self.memory.record_failure(current, context_for(case, files, finding), record, "expert") if record["failure"] else None
        if lesson:
            record["failure_memory_id"] = lesson
        self.store.mutate(job_id, lambda j: j["attempts"].append(record))
        if verified.get("feedback", {}).get("code") == "security_witness_missing":
            self.set(job_id, "needs_human", reason="security_witness_missing")
        elif verified.get("passed"):
            self.accept(job_id, verified, meta, "human-authored", pending["author"])
        else:
            self.set(job_id, "needs_human", reason="expert_patch_failed_verification")

    def _run(self, job_id):
        job = self.active(job_id)
        if job.get("pending_expert_patch"):
            return self._run_expert(job)
        case, files = baseline(job["case_id"], job["base_commit"])
        verify = {"job_id": job_id, "case_id": job["case_id"], "base_commit": job["base_commit"], "deadline": job["deadline"], "scanner": job["scanner"], "attempt": 0, "patch": None, "target_file": None}
        self.set(job_id, "scanning")
        initial = self.worker("worker2", "/verify", verify, job["deadline"])
        self.active(job_id)
        self.set(job_id, "scanning", baseline=initial)
        if not initial.get("baseline_valid"):
            self.set(job_id, "needs_human", reason="baseline_missing_expected_failing_security_assertion_or_finding")
            return
        finding = initial["scans"][0]["findings"][0]
        # Only the finding's file may change, and only if the descriptor makes it editable.
        target = finding.get("file")
        allowed = allowed_files(case["spec"], files, target)
        if not allowed:
            self.set(job_id, "needs_human", reason="finding_file_not_editable")
            return
        source = files[target]
        siblings = read_only_context(files, target)
        # Everything the model could read is checked before any model call.
        if imitates_note(source, *siblings.values(), canonical(finding)):
            self.set(job_id, "needs_human", reason="suspected_prompt_injection")
            return
        context = context_for(case, files, finding)
        lookup = self.memory.search(context, job.get("memory_mode", "guarded"))
        selected = lookup.pop("selected")
        lookup["selected_id"] = selected["id"] if selected else None
        self.set(job_id, "scanning", memory_lookup=lookup, memory_context=context, memory_ids=[])
        memory_data = None
        replay = None
        if selected:
            with self.store.lock:
                self.memory.use(selected["id"], job_id)
                self.store.mutate(job_id, lambda j: j.update(memory_ids=[selected["id"]]))
            memory_data = {"patch_diff": selected["diff"], "context": selected["context"]}
            if job.get("memory_mode", "guarded") == "guarded" and selected["context"].get("source_sha256") == digest(source):
                replay = {"mode": "approved-memory-replay", "patch": selected["patch"], "memory_id": selected["id"],
                          "metrics": {"duration_seconds": lookup["duration_seconds"], "prompt_tokens_measured": 0, "output_tokens_measured": 0}}
        strategy = job.get("strategy", "v01")
        if strategy not in STRATEGIES:
            raise PolicyError("unknown_retry_strategy")
        context_files = siblings if strategy == "guided+context" else {}
        seen, previous_feedback, feedback, failure = set(), None, None, None
        for attempt in range(1, job["max_attempts"] + 1):
            self.active(job_id)
            self.set(job_id, "patching", attempt_count=attempt)
            self.memory.assert_active(self.store.get(job_id).get("memory_ids", []))
            # Reserve the configured maximum before invoking inference. Actual
            # usage is recorded separately; missing telemetry never becomes zero.
            reservation = int(setting("MODEL_CONTEXT", "8192"))
            used = self.store.get(job_id).get("tokens_reserved", 0)
            if not (replay and attempt == 1) and used + reservation > int(setting("JOB_TOKEN_BUDGET", "32768")):
                self.set(job_id, "needs_human", reason="token_budget_exhausted")
                return
            options = {}
            if replay and attempt == 1:
                proposal = replay
            else:
                self.store.mutate(job_id, lambda j: j.update(tokens_reserved=used + reservation))
                options = retry_options(strategy, case.get("kind"), attempt, failure, context_files)
                proposal = self.worker("worker1", "/propose", {"job_id": job_id, "attempt": attempt, "deadline": job["deadline"], "source": {target: source}, "finding": finding, "feedback": feedback, "memory_data": memory_data, "seed": job.get("seed", 42) + attempt, **options}, job["deadline"])
            retry = {"strategy": strategy, "temperature": options.get("temperature", 0.0), "guidance_level": attempt - 2 if "guidance" in options else None, "context_paths": sorted(options.get("context_files", {}))}
            self.active(job_id)
            if proposal.get("mode") not in ("real-local-model", "mock-test", "approved-memory-replay"):
                raise PolicyError("unknown_model_mode")
            if proposal["mode"] == "approved-memory-replay" and proposal is not replay:
                raise PolicyError("worker_cannot_claim_memory_replay")
            if proposal["mode"] == "mock-test" and job["mode"] != "mock-test":
                raise PolicyError("mock_result_on_real_job")
            patch = Patch.model_validate(proposal["patch"])
            try:
                meta = validate_patch(files, patch, allowed=allowed)
            except PolicyError as exc:
                self.store.mutate(job_id, lambda j: j["attempts"].append({"number": attempt, "proposal": proposal, "policy_error": str(exc)}))
                raise
            record = {"number": attempt, "proposal": proposal, "retry": retry, **meta}
            if meta["patch_sha256"] in seen:
                self.store.mutate(job_id, lambda j: j["attempts"].append({**record, "stopped": "duplicate_patch"}))
                if strategy.startswith("guided"):
                    # Same patch, same verdict: skip verification and retry with deeper guidance.
                    continue
                self.set(job_id, "needs_human", reason="duplicate_patch")
                return
            seen.add(meta["patch_sha256"])
            self.set(job_id, "verifying")
            verified = self.worker("worker2", "/verify", {**verify, "attempt": attempt, "patch": patch.model_dump(), "target_file": target}, job["deadline"])
            current = self.active(job_id)
            record["verification"] = verified
            failure = None if verified.get("passed") else classify(verified)
            record["failure"] = failure
            lesson = self.memory.record_failure(current, context, record, strategy) if failure else None
            if lesson:
                record["failure_memory_id"] = lesson
            self.store.mutate(job_id, lambda j: j["attempts"].append(record))
            if verified.get("feedback", {}).get("code") == "security_witness_missing":
                # Builds, behaves and scans clean, but nothing proves the weakness is gone (decision 3).
                self.set(job_id, "needs_human", reason="security_witness_missing")
                return
            if verified.get("passed"):
                self.accept(job_id, verified, meta, proposal["mode"])
                return
            if strategy.startswith("guided"):
                # Each retry receives deeper guidance, so the attempt budget bounds the loop.
                edited = next(e.content for e in patch.edits if e.path == target)
                feedback = {**failure, "previous_patch_diff": changed_lines(source, edited)}
                continue
            feedback = verified.get("feedback", {"code": "unknown_verification_failure"})
            # Only deterministic failure categories enter no-progress comparison.
            signature = (feedback.get("code"), tuple(feedback.get("remaining_rules", [])), bool(feedback.get("behavior", {}).get("passed")), bool(feedback.get("security", {}).get("passed")))
            if signature == previous_feedback:
                self.set(job_id, "needs_human", reason="no_progress")
                return
            previous_feedback = signature
        self.set(job_id, "needs_human", reason="attempt_budget_exhausted")
