import difflib
import time

from safepatch.common import POLICY, SOURCE, Patch, canonical, digest, remaining, request, secret, setting
from safepatch.memory import Memory, context_for
from safepatch.acceptance import manifest
from safepatch.feedback import classify, guidance_for, imitates_note
from safepatch.policy import PolicyError, validate_patch
from safepatch.repository import baseline

TERMINAL = {"awaiting_review", "rejected", "needs_human", "infrastructure_error", "cancelled", "expired", "approved", "deployed"}
# v01: original loop. sampling: retries at higher temperature. guided: plus classified
# feedback and static guidance. guided+context: plus read-only sibling sources.
STRATEGIES = ("v01", "sampling", "guided", "guided+context")


def read_only_context(files, limit=8000):
    """Other main sources of the trusted baseline; the model may read them, never edit."""
    context, size = {}, 0
    for path, content in sorted(files.items()):
        if path.startswith("src/main/java/") and path.endswith(".java") and path != SOURCE and size + len(content) <= limit:
            context[path] = content
            size += len(content)
    return context


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

    def _run(self, job_id):
        job = self.active(job_id)
        case, files = baseline(job["case_id"], job["base_commit"])
        verify = {"job_id": job_id, "case_id": job["case_id"], "base_commit": job["base_commit"], "deadline": job["deadline"], "scanner": job["scanner"], "attempt": 0, "patch": None}
        self.set(job_id, "scanning")
        initial = self.worker("worker2", "/verify", verify, job["deadline"])
        self.active(job_id)
        self.set(job_id, "scanning", baseline=initial)
        if not initial.get("baseline_valid"):
            self.set(job_id, "needs_human", reason="baseline_missing_expected_failing_security_assertion_or_finding")
            return
        finding = initial["scans"][0]["findings"][0]
        # Everything the model could read is checked before any model call.
        if imitates_note(files[SOURCE], *read_only_context(files).values(), canonical(finding)):
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
            if job.get("memory_mode", "guarded") == "guarded" and selected["context"].get("source_sha256") == digest(files[SOURCE]):
                replay = {"mode": "approved-memory-replay", "patch": selected["patch"], "memory_id": selected["id"],
                          "metrics": {"duration_seconds": lookup["duration_seconds"], "prompt_tokens_measured": 0, "output_tokens_measured": 0}}
        strategy = job.get("strategy", "v01")
        if strategy not in STRATEGIES:
            raise PolicyError("unknown_retry_strategy")
        context_files = read_only_context(files) if strategy == "guided+context" else {}
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
                options = retry_options(strategy, case["kind"], attempt, failure, context_files)
                proposal = self.worker("worker1", "/propose", {"job_id": job_id, "attempt": attempt, "deadline": job["deadline"], "source": {SOURCE: files[SOURCE]}, "finding": finding, "feedback": feedback, "memory_data": memory_data, "seed": job.get("seed", 42) + attempt, **options}, job["deadline"])
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
                meta = validate_patch(files, patch)
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
            verified = self.worker("worker2", "/verify", {**verify, "attempt": attempt, "patch": patch.model_dump()}, job["deadline"])
            self.active(job_id)
            record["verification"] = verified
            failure = None if verified.get("passed") else classify(verified)
            record["failure"] = failure
            self.store.mutate(job_id, lambda j: j["attempts"].append(record))
            if verified.get("passed"):
                current = self.active(job_id)
                self.memory.assert_active(current.get("memory_ids", []))
                acceptance_manifest = manifest(current, verified, meta["patch_sha256"])
                self.store.mutate(job_id, lambda j: j.update(acceptance_manifest=acceptance_manifest))
                review = None
                if job.get("second_review"):
                    try:
                        review = self.worker("worker1", "/advisory", {"diff": meta["diff"], "deadline": job["deadline"]}, job["deadline"])
                    except Exception:
                        review = {"status": "not_executed_or_failed", "authority": "advisory-only"}
                self.active(job_id)
                self.set(job_id, "awaiting_review", candidate={"evidence_sha256": digest(canonical(acceptance_manifest)), "commit": verified["candidate_commit"], "artifact_sha256": verified["artifact_sha256"], "patch_sha256": meta["patch_sha256"], "policy_version": POLICY, "diff": meta["diff"], "review_repository": verified["review_repository"], "review_branch": verified["review_branch"]}, advisory=review, review_expires_at=time.time() + int(setting("REVIEW_TTL_SECONDS", "86400")), duration_seconds=round(time.time() - job["started_at"], 3))
                return
            if strategy.startswith("guided"):
                # Each retry receives deeper guidance, so the attempt budget bounds the loop.
                edited = next(e.content for e in patch.edits if e.path == SOURCE)
                feedback = {**failure, "previous_patch_diff": changed_lines(files[SOURCE], edited)}
                continue
            feedback = verified.get("feedback", {"code": "unknown_verification_failure"})
            # Only deterministic failure categories enter no-progress comparison.
            signature = (feedback.get("code"), tuple(feedback.get("remaining_rules", [])), bool(feedback.get("behavior", {}).get("passed")), bool(feedback.get("security", {}).get("passed")))
            if signature == previous_feedback:
                self.set(job_id, "needs_human", reason="no_progress")
                return
            previous_feedback = signature
        self.set(job_id, "needs_human", reason="attempt_budget_exhausted")
