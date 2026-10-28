import difflib
import time
import uuid

from safepatch.common import MODEL_REGION_CHARS, MODEL_SOURCE_CHARS, POLICY, Patch, canonical, digest, known_findings_enabled, remaining, request, secret, setting
from safepatch.memory import Memory, context_for, reuse_result
from safepatch.acceptance import manifest
from safepatch.feedback import GUIDANCE_KEY, classify, guidance_for, imitates_note
from safepatch.region import RegionPatch, complete_imports, region_view, splice
from safepatch.policy import PolicyError, validate_patch
from safepatch.project import is_protected
from safepatch.repository import allowed_files, baseline
from safepatch.weakness import family

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
            # A file holds at least a quarter as many characters as bytes: one that cannot fit is
            # not read (OWASP Benchmark's package has 2 740 siblings; reading them took 97 s a job).
            stored = files.size(path) if hasattr(files, "size") else None
            if stored is not None and size + -(-stored // 4) > limit:
                continue
            try:
                content = files[path]
            except PolicyError:
                continue
            if size + len(content) <= limit:
                context[path] = content
                size += len(content)
    return context


EXPERT_ATTEMPTS = 3


# Fields a per-file job keeps from the job whose scan it came from (week 4: one job per file).
INHERITED = ("project", "memory_mode", "strategy", "case_id", "base_commit", "split", "policy_version", "scanner", "mode",
             "max_attempts", "owner", "second_review", "evaluation", "seed", "experiment_failure_warnings")


def finding_groups(initial):
    """Baseline findings by file. One job per file, so two jobs never edit the same file."""
    groups = {}
    for report in initial.get("scans", []):
        for finding in report["findings"]:
            groups.setdefault(finding["file"], []).append(finding)
    return [(path, sorted(found, key=lambda f: f.get("line") or 0)) for path, found in sorted(groups.items())]


def primary_finding(job):
    """The finding a job repairs: the first one in its target file (the first file for older jobs)."""
    groups = finding_groups(job["baseline"])
    return dict(groups).get(job.get("target_file"), groups[0][1])[0]


def tolerated(initial, target):
    """Baseline findings in other files: the patch cannot touch them, so the rescan may keep them."""
    return sorted({f["fingerprint"] for report in initial.get("scans", []) for f in report["findings"] if f["file"] != target and f.get("fingerprint")})


def expert_scope(job):
    """What a human may patch: the finding's file under the descriptor rules, as for the model."""
    if job.get("evaluation"):
        raise PolicyError("evaluation_job_cannot_take_expert_patch")
    initial = job.get("baseline") or {}
    if not initial.get("baseline_valid"):
        raise PolicyError("baseline_not_valid")
    finding = primary_finding(job)
    case, files = baseline(job["case_id"], job["base_commit"])
    return case, files, finding, allowed_files(case["spec"], files, finding.get("file"))


def expert_attempts_left(job):
    return EXPERT_ATTEMPTS - sum(a.get("proposal", {}).get("mode") == "human-authored" for a in job["attempts"])


def check_expert_patch(job, patch):
    """Submission checks; the engine repeats the policy check before verification."""
    if job["status"] != "needs_human":
        raise PolicyError("job_not_waiting_for_a_human")
    if expert_attempts_left(job) <= 0:
        raise PolicyError("expert_attempt_budget_exhausted")
    _, files, _, allowed = expert_scope(job)
    meta = validate_patch(files, patch, allowed=allowed)
    # Approved patches can reach later prompts through memory; keep forged notes out.
    if imitates_note(patch.rationale, *(e.content for e in patch.edits)):
        raise PolicyError("suspected_prompt_injection")
    return meta


def model_view(target, source, findings):
    """The methods holding the job's findings, if they are few and small enough for the model."""
    view = region_view(target, source, [f.get("line") for f in findings])
    return view if view and sum(len(r["content"]) for r in view["regions"]) <= MODEL_REGION_CHARS else None


def region_answer(proposal, view, target, source):
    """A region answer as a whole-file patch: policy and verification judge the whole file."""
    if view is None:
        raise PolicyError("region_answer_without_regions")
    try:
        answer = RegionPatch.model_validate(proposal["region_patch"])
    except ValueError as exc:
        raise PolicyError("region_answer_invalid") from exc
    # JDK types the regions use but the file does not import are imported by SafePatch, and
    # recorded as such: the model leaves `imports` empty (region-mode development cases).
    content, completed = complete_imports(splice(source, view, answer), "".join(e.content for e in answer.regions))
    edit = {"path": target, "old_sha256": digest(source), "content": content}
    return {**proposal, "patch": {"edits": [edit], "rationale": answer.rationale}, "imports_completed": completed}


def no_change(proposal, view, source, initial):
    """Why an answer changed nothing, for the reviewer; the model's feedback stays as it was.

    `answer`: whether the model repeated the code it was shown (in the L3 run of 26 Oct 2026
    all 13 such answers did, while their rationale described a fix) or its edits made no
    difference once applied. `change_required_by`: the baseline's evidence. A failing security
    witness proves a change is needed; a finding without a witness may be a false positive."""
    shown = {r["id"]: r["content"] for r in (view or {}).get("regions", [])}
    regions = (proposal.get("region_patch") or {}).get("regions")
    if regions:
        repeated = all(r["content"].rstrip("\n") == shown.get(r["region"], "").rstrip("\n") for r in regions)
    else:
        repeated = all(e["content"] == source for e in proposal["patch"]["edits"])
    security = initial.get("security") or {}
    required = ("finding_without_security_witness" if security.get("missing") else
                "failing_security_witness" if security.get("failures") or security.get("errors") else None)
    return {"answer": "repeats_shown_code" if repeated else "edits_made_no_difference",
            "shown": "regions" if regions else "whole_file", "change_required_by": required}


def changed_lines(before, after, limit=1500):
    """Previous attempt as changed lines only (no context, no file headers)."""
    lines = list(difflib.unified_diff(before.splitlines(True), after.splitlines(True), n=0))[2:]
    return "".join(lines)[:limit]


def retry_options(strategy, guide, attempt, failure, context_files):
    """Extra worker1 fields per strategy; v01 sends none so its requests stay unchanged."""
    if strategy == "v01":
        return {}
    options = {"temperature": 0.0 if attempt == 1 else float(setting("RETRY_TEMPERATURE", "0.4"))}
    if strategy.startswith("guided") and failure:
        options["guidance"] = guidance_for(guide, failure, attempt - 2)
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

    def similar(self, job, context, target, source, finding):
        """Arm B of the main experiment (memory_mode "similar", never offered by the API): the
        record most similar to the finding's method, or to the lines around the finding."""
        line = finding.get("line") or 1
        view = region_view(target, source, [line])
        query = "".join(r["content"] for r in view["regions"]) if view else "\n".join(source.splitlines()[max(0, line - 26):line + 25])
        used = {}

        def embed(texts):
            vectors = []
            for start in range(0, len(texts), 64):
                answer = self.worker("worker1", "/embed", {"texts": texts[start:start + 64], "deadline": job["deadline"]}, job["deadline"])
                used.update(model=answer["model"], model_digest=answer["model_digest"])
                vectors += answer["embeddings"]
            return vectors
        lookup = self.memory.similar(context, query, embed)
        lookup["embedding"] = used or None
        return lookup

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
        # Each memory record learns how the job that used it ended (its evidence vector).
        job = self.store.get(job_id)
        for memory_id in job.get("memory_ids", []):
            self.memory.settle(memory_id, job_id, reuse_result(job))

    def split(self, job, initial, path, found):
        """A queued job for one more file of the same scan; it reuses the scan instead of rescanning."""
        now = time.time()
        child = {k: job[k] for k in INHERITED if k in job}
        child.update(id=uuid.uuid4().hex, parent_job=job["id"], status="queued", baseline=initial, target_file=path, findings=found,
                     started_at=now, deadline=now + int(setting("JOB_BUDGET_SECONDS", "1200")), attempt_count=0, attempts=[],
                     events=[{"time": now, "status": "queued", "parent_job": job["id"]}], approval=None)
        created, _ = self.store.create(child, job["id"] + ":" + digest(path)[:32])
        return created["id"]

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
        verified = self.worker("worker2", "/verify", {"job_id": job_id, "case_id": job["case_id"], "base_commit": job["base_commit"], "deadline": job["deadline"], "scanner": job["scanner"], "attempt": number, "patch": patch.model_dump(), "target_file": target, "tolerated": tolerated(job["baseline"], target)}, job["deadline"])
        current = self.active(job_id)
        record.update(verification=verified, failure=None if verified.get("passed") else classify(verified))
        lesson = self.memory.record_failure(current, context_for(case, files, finding), record, "expert") if record["failure"] else None
        if lesson:
            record["failure_memory_id"] = lesson
        self.store.mutate(job_id, lambda j: j["attempts"].append(record))
        if record["failure"] and record["failure"]["category"] == "infrastructure":
            # Back to the expert, who may resend once the environment is fixed (still one of the three attempts).
            self.set(job_id, "needs_human", reason="verification_infrastructure:" + record["failure"]["reason"])
        elif verified.get("feedback", {}).get("code") == "security_witness_missing":
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
        # A per-file job reuses the scan of the job it was split from; every other job scans.
        initial = job.get("baseline") if job.get("parent_job") else None
        if initial is None:
            self.set(job_id, "scanning")
            initial = self.worker("worker2", "/verify", verify, job["deadline"])
            self.active(job_id)
            self.set(job_id, "scanning", baseline=initial)
            if not initial.get("baseline_valid"):
                self.set(job_id, "needs_human", reason="baseline_missing_expected_failing_security_assertion_or_finding")
                return
            # One job per file: this job takes the first file, each further file gets its own job.
            groups = finding_groups(initial)
            children = [self.split(job, initial, path, found) for path, found in groups[1:]]
            job = self.set(job_id, "scanning", target_file=groups[0][0], findings=groups[0][1], children=children)
        finding = primary_finding(job)
        # Only the finding's file may change, and only if the descriptor makes it editable.
        target = finding.get("file")
        verify["tolerated"] = tolerated(initial, target)
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
        if job.get("memory_mode") == "similar":
            lookup = self.similar(job, context, target, source, finding)
        else:
            lookup = self.memory.search(context, job.get("memory_mode", "guarded"))
        selected = lookup.pop("selected")
        lookup["selected_id"] = selected["id"] if selected else None
        # The closest failed candidates ("did not work here") are found and recorded for the reviewer,
        # but not sent to the model: on the development set the 7B model did worse with them
        # (docs/DENEY_UYARI.md, decided 29 Oct). Week 5's sending stays as an experiment option,
        # lab and evaluation profiles only. Stored diffs are data; one that imitates the verifier
        # note is never sent.
        warnings = [w for w in self.memory.failure_warnings(lookup.get("failures", []), context["project"]) if not imitates_note(w["changed_lines"])]
        found = [{"id": w["id"], "relation": w["relation"], "failure": w["failure"]} for w in warnings]
        send = job.get("experiment_failure_warnings") is True and known_findings_enabled()
        lookup["warnings_sent"], lookup["warnings_withheld"] = (found, []) if send else ([], found)
        failure_data = [{k: w[k] for k in ("relation", "failure", "changed_lines")} for w in warnings] if send else []
        self.set(job_id, "scanning", memory_lookup=lookup, memory_context=context, memory_ids=[])
        memory_data = None
        replay = None
        if selected:
            with self.store.lock:
                self.memory.use(selected["id"], job_id, lookup["use"])
                self.store.mutate(job_id, lambda j: j.update(memory_ids=[selected["id"]]))
            memory_data = None if imitates_note(selected["diff"]) else {"patch_diff": selected["diff"], "context": selected["context"]}
            # Only an exact-compatible record on identical source is replayed; any other use is an example.
            if job.get("memory_mode", "guarded") == "guarded" and lookup["use"] == "replay" and selected["context"].get("source_sha256") == digest(source):
                # A replayed expert patch keeps its author, so the author cannot approve its reuse either.
                replay = {"mode": "approved-memory-replay", "patch": selected["patch"], "memory_id": selected["id"], "author": selected.get("author"),
                          "metrics": {"duration_seconds": lookup["duration_seconds"], "prompt_tokens_measured": 0, "output_tokens_measured": 0}}
        strategy = job.get("strategy", "v01")
        if strategy not in STRATEGIES:
            raise PolicyError("unknown_retry_strategy")
        context_files = siblings if strategy == "guided+context" else {}
        # Offered with every model call; worker1 uses it only when the whole file does not fit.
        view = model_view(target, source, job.get("findings") or [finding])
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
                if len(source) > MODEL_SOURCE_CHARS and view is None:
                    # Too large to show whole and no small set of methods holds the findings:
                    # the job goes to the expert without a model attempt.
                    self.set(job_id, "needs_human", reason="source_exceeds_model_context", attempt_count=attempt - 1)
                    return
                self.store.mutate(job_id, lambda j: j.update(tokens_reserved=used + reservation))
                options = retry_options(strategy, GUIDANCE_KEY.get(family(finding)), attempt, failure, context_files)
                proposal = self.worker("worker1", "/propose", {"job_id": job_id, "attempt": attempt, "deadline": job["deadline"], **({"source": {target: source}} if len(source) <= MODEL_SOURCE_CHARS else {}), **({"region_source": view} if view else {}), "finding": finding, "feedback": feedback, "memory_data": memory_data, "seed": job.get("seed", 42) + attempt, **({"failure_data": failure_data} if failure_data else {}), **options}, job["deadline"])
            retry = {"strategy": strategy, "temperature": options.get("temperature", 0.0), "guidance_level": attempt - 2 if "guidance" in options else None, "context_paths": sorted(options.get("context_files", {}))}
            self.active(job_id)
            if proposal.get("mode") not in ("real-local-model", "mock-test", "approved-memory-replay"):
                raise PolicyError("unknown_model_mode")
            if proposal["mode"] == "approved-memory-replay" and proposal is not replay:
                raise PolicyError("worker_cannot_claim_memory_replay")
            if proposal["mode"] == "mock-test" and job["mode"] != "mock-test":
                raise PolicyError("mock_result_on_real_job")
            try:
                if "region_patch" in proposal:
                    proposal = region_answer(proposal, view, target, source)
                patch = Patch.model_validate(proposal["patch"])
                meta = validate_patch(files, patch, allowed=allowed)
            except PolicyError as exc:
                empty = str(exc) == "empty_patch"
                failure = {"category": "empty_patch"} if empty else None
                report = {"failure": failure, "no_change": no_change(proposal, view, source, initial)} if empty else {}
                self.store.mutate(job_id, lambda j: j["attempts"].append({"number": attempt, "proposal": proposal, "policy_error": str(exc), **report}))
                if not empty:
                    raise
                # A model answer that changes nothing is a failed attempt, not a policy breach
                # (region-mode development cases, 25 Oct 2026): retry with feedback.
                feedback = dict(failure) if strategy.startswith("guided") else {"code": "empty_patch"}
                if not strategy.startswith("guided"):
                    if ("empty_patch",) == previous_feedback:
                        self.set(job_id, "needs_human", reason="no_progress")
                        return
                    previous_feedback = ("empty_patch",)
                continue
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
            if failure and failure["category"] == "infrastructure":
                # The environment failed, not the patch: no retry, no guidance, no lesson.
                self.set(job_id, "infrastructure_error", reason="verification_infrastructure:" + failure["reason"])
                return
            if verified.get("feedback", {}).get("code") == "security_witness_missing":
                # Builds, behaves and scans clean, but nothing proves the weakness is gone (decision 3).
                self.set(job_id, "needs_human", reason="security_witness_missing")
                return
            if verified.get("passed"):
                # Authorship only ever comes from our own memory record, never from a worker response.
                self.accept(job_id, verified, meta, proposal["mode"], replay["author"] if proposal is replay else None)
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
