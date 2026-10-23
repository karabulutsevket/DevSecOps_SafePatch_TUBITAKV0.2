import pytest

from safepatch.feedback import CATEGORIES, GUIDANCE, classify, guidance_for


def result(behavior=True, security=True, rules=(), details=()):
    def suite(name, passed):
        return {"passed": passed, "details": [{"name": test, "assertion": marker} for s, test, marker in details if s == name]}
    return {"passed": False, "feedback": {"code": "validation_failed", "remaining_rules": list(rules),
            "behavior": suite("behavior", behavior), "security": suite("security", security)}}


def test_compilation_failure_keeps_at_most_four_diagnostics():
    failure = classify({"passed": False, "feedback": {"code": "compilation_failed", "diagnostics": [str(i) for i in range(9)]}})
    assert failure == {"category": "compilation_failed", "diagnostics": ["0", "1", "2", "3"]}


def test_behavior_regression_takes_precedence_over_security():
    failure = classify(result(behavior=False, security=False, details=[("behavior", "echoesHello", "BEHAVIOR_REGRESSION"), ("security", "literal", "BEHAVIOR_REGRESSION")]))
    assert failure["category"] == "behavior_regression"
    assert {"suite": "security", "test": "literal", "marker": "BEHAVIOR_REGRESSION"} in failure["failed_tests"]


def test_security_witness_and_remaining_finding():
    assert classify(result(security=False, details=[("security", "cannotReadParentSecret", "PATH_TRAVERSAL_REGRESSION")]))["category"] == "security_witness_failed"
    assert classify(result(rules=["bigg.java.sql-concatenation"]))["category"] == "finding_remaining"
    assert classify({"passed": False})["category"] == "unknown"


def test_guidance_is_kind_specific_with_generic_fallback_and_clamped_level():
    path = {"category": "security_witness_failed"}
    assert guidance_for("path", path, 0) == GUIDANCE["path"]["security_witness_failed"][0]
    assert guidance_for("path", path, 7) == GUIDANCE["path"]["security_witness_failed"][-1]
    assert guidance_for("sql", {"category": "compilation_failed"}, 1) == GUIDANCE["*"]["compilation_failed"][1]
    assert guidance_for("unknown-kind", {"category": "finding_remaining"}, 0) == GUIDANCE["*"]["finding_remaining"][0]
    assert guidance_for("path", None, 0) is None


@pytest.mark.parametrize("kind", list(GUIDANCE))
def test_guidance_table_uses_known_categories(kind):
    for category, texts in GUIDANCE[kind].items():
        assert category in CATEGORIES
        assert texts and all(isinstance(t, str) and 0 < len(t) <= 1500 for t in texts)
