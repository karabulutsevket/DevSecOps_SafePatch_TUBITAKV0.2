import json
import base64
import os
from pathlib import Path
import time
import uuid

import pytest

from safepatch.common import ROOT, SOURCE, Patch, VerifyRequest, digest
from safepatch.policy import PolicyError
from safepatch.repository import baseline, registry
from safepatch.runner import execute
from mock_patches import correct_patch

pytestmark = [pytest.mark.integration, pytest.mark.skipif(os.environ.get("RUN_JAVA_INTEGRATION") != "1", reason="Set RUN_JAVA_INTEGRATION=1 after Java/Maven preparation")]


def run_case(case_id, patch=None):
    spec = registry()[1][case_id]
    return execute(VerifyRequest(job_id=uuid.uuid4().hex, case_id=case_id, base_commit=spec["commit"], attempt=1 if patch else 0, deadline=time.time() + 180, scanner="builtin", patch=patch))


def record(name, result):
    artifact = result.pop("artifact_b64", None)
    if artifact:
        target = ROOT / ".runtime/test-verified-artifacts"
        target.mkdir(parents=True, exist_ok=True)
        (target / (name + ".jar")).write_bytes(base64.b64decode(artifact))
    directory = ROOT / "evidence/java-integration"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / (name + ".json")).write_text(json.dumps({"model_mode": "mock-test-reference-patch", "scanner_mode": "real-builtin-demo", "result": result}, indent=2), encoding="utf-8")


@pytest.mark.parametrize("kind", ["sql", "path", "command"])
def test_real_baseline_then_reference_fix(kind):
    case_id = kind + "-01"
    initial = run_case(case_id)
    record(case_id + "-baseline", initial)
    assert initial["baseline_valid"], initial
    _, files = baseline(case_id, registry()[1][case_id]["commit"])
    fixed = run_case(case_id, correct_patch(kind, files))
    record(case_id + "-reference-fix", fixed)
    assert fixed["passed"], fixed


@pytest.mark.parametrize("kind", ["sql", "path", "command"])
def test_function_disabling_patch_is_rejected(kind):
    case_id = kind + "-02"
    _, files = baseline(case_id, registry()[1][case_id]["commit"])
    patch = Patch.model_validate({"edits": [{"path": SOURCE, "old_sha256": digest(files[SOURCE]), "content": 'package demo;\npublic class DemoService {\n    public String lookup(String input) throws Exception { return ""; }\n}\n'}], "rationale": "MOCK TEST ONLY: deliberately broken behavior"})
    result = run_case(case_id, patch)
    record(case_id + "-broken-function", result)
    assert not result["passed"]
    assert not result["behavior"]["passed"]


@pytest.mark.parametrize("kind", ["sql", "path", "command"])
def test_protected_test_deletion_rejected_before_execution(kind):
    case_id = kind + "-03"
    _, files = baseline(case_id, registry()[1][case_id]["commit"])
    patch = correct_patch(kind, files)
    patch.edits[0].path = "src/test/java/demo/SecurityTest.java"
    with pytest.raises(PolicyError):
        run_case(case_id, patch)
    record(case_id + "-protected-test", {"passed": False, "reason": "policy_rejected_before_execution"})
