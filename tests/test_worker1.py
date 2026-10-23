import json
import time

import pytest

from safepatch import worker1
from safepatch.common import SOURCE


@pytest.fixture
def sent(monkeypatch):
    captured = {}
    monkeypatch.setattr(worker1, "model_info", lambda endpoint, model: {"model": model})
    def request(url, method="GET", body=None, **kwargs):
        captured.update(body or {})
        patch = {"edits": [{"path": SOURCE, "old_sha256": "a" * 64, "content": "class A {}\n"}], "rationale": "MOCK TEST ONLY"}
        return {"done": True, "done_reason": "stop", "response": json.dumps(patch), "prompt_eval_count": 1, "eval_count": 1}
    monkeypatch.setattr(worker1, "request", request)
    return captured


def propose(**extra):
    return worker1.Propose(job_id="a" * 32, attempt=2, deadline=time.time() + 60, source={SOURCE: "class DemoService {}\n"}, finding={"rule_id": "test.rule"}, **extra)


def test_default_request_keeps_v01_prompt(sent):
    worker1.propose(propose())
    assert sent["system"] == worker1.SYSTEM
    assert sent["options"]["temperature"] == 0.0
    assert "read_only_context_data" not in json.loads(sent["prompt"])


def test_guidance_and_context_are_added_only_when_given(sent):
    context = {"src/main/java/demo/EchoMain.java": "class EchoMain {}\n"}
    result = worker1.propose(propose(temperature=0.4, guidance="Use a fixed argv.", context_files=context))
    assert sent["system"].startswith(worker1.SYSTEM)
    assert worker1.GUIDANCE_NOTE + "Use a fixed argv." in sent["system"]
    assert worker1.CONTEXT_NOTE in sent["system"]
    assert json.loads(sent["prompt"])["read_only_context_data"] == [{"path": "src/main/java/demo/EchoMain.java", "content": "class EchoMain {}\n"}]
    assert sent["options"]["temperature"] == 0.4
    assert result["metrics"]["temperature"] == 0.4


@pytest.mark.parametrize("path", [SOURCE, "pom.xml", "src/test/java/demo/SecurityTest.java", "src/main/java/../../pom.java"])
def test_context_cannot_include_editable_source_tests_or_build(sent, path):
    with pytest.raises(ValueError):
        worker1.propose(propose(context_files={path: "x"}))


def test_context_size_is_bounded(sent):
    with pytest.raises(ValueError):
        worker1.propose(propose(context_files={"src/main/java/demo/Big.java": "x" * 8001}))
