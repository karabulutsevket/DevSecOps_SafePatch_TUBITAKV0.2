"""Trusted retry feedback: deterministic failure classes and static repair guidance.

Verifier facts are reduced to a compact failure record. Test names and messages
from the repository stay data. Guidance text is fixed SafePatch content written
by the team; it never contains model output or repository text.
"""
from safepatch.common import canonical, digest

CATEGORIES = ("compilation_failed", "behavior_regression", "security_witness_failed", "finding_remaining", "unknown")

# Level 0 names the failure; level 1 adds a concrete repair strategy.
# Written from development cases (*-01) only; evaluation cases are reported separately.
GUIDANCE = {
    "sql": {
        "security_witness_failed": [
            "The input is still interpreted as SQL: a quote in the input changes the query result.",
            "Build the query with a '?' placeholder, call conn.prepareStatement(sql) and statement.setString(1, input). Never concatenate input into SQL. Keep try-with-resources, sorting and the comma-joined result.",
        ],
        "behavior_regression": [
            "Normal account lookups must return the same names as before.",
            "Keep the table setup, the 'WHERE name = ?' semantics, sorting and the comma-joined result; change only how input reaches the query.",
        ],
    },
    "path": {
        "security_witness_failed": [
            "A parent-directory input such as '../x' still reads outside the root. A startsWith check on a path that is not canonical does not stop '..' segments.",
            "Canonicalize before checking: make the root canonical with toRealPath(), resolve the input against it, make the target canonical with toRealPath() or normalize(), and throw unless target.startsWith(root). Nested relative paths such as 'sub/file.txt' must keep working.",
        ],
        "behavior_regression": [
            "Reading files inside the root, including nested relative paths, must keep working.",
            "Do not reject every input that contains a separator; canonicalize the target and compare it with the canonical root instead.",
        ],
    },
    "command": {
        "behavior_regression": [
            "Legitimate inputs must still produce exactly \"echo:\" followed by the input. The previous patch changed what the child process prints.",
            "Do not run a shell and do not build a command string. Start a fixed executable with the input as its own argv element. If read_only_context_data contains a helper main class, run it with the current classpath: new ProcessBuilder(java, \"-cp\", System.getProperty(\"java.class.path\"), \"<helper class>\", input). Keep the timeout and exit-code checks.",
        ],
        "security_witness_failed": [
            "Shell metacharacters in the input are still interpreted. The input must be one literal argv element, never part of a shell command.",
            "Do not run a shell and do not build a command string. Start a fixed executable with the input as its own argv element. If read_only_context_data contains a helper main class, run it with the current classpath: new ProcessBuilder(java, \"-cp\", System.getProperty(\"java.class.path\"), \"<helper class>\", input). Keep the timeout and exit-code checks.",
        ],
    },
    "*": {
        "compilation_failed": [
            "The previous patch does not compile. Fix the reported compiler errors.",
            "Keep the package, class name, public method signature and required imports; change only the vulnerable statements.",
        ],
        "behavior_regression": [
            "The previous patch changed legitimate behavior.",
            "Preserve the original output for normal inputs; change only how untrusted input reaches the sink.",
        ],
        "security_witness_failed": [
            "The security test can still exploit the code.",
            "Fix the root cause at the sink instead of adding a check that can be bypassed.",
        ],
        "finding_remaining": [
            "The scanner still reports the weakness at the same sink.",
            "Remove the vulnerable construction itself; do not suppress or wrap it.",
        ],
        "unknown": [
            "The previous patch failed verification.",
            "Re-read the source and produce a minimal root-cause fix.",
        ],
    },
}
GUIDANCE_SHA256 = digest(canonical(GUIDANCE))


def classify(verified):
    """Reduce a verifier result to a compact, deterministic failure record."""
    feedback = verified.get("feedback") or {}
    if feedback.get("code") == "compilation_failed":
        return {"category": "compilation_failed", "diagnostics": list(feedback.get("diagnostics", []))[:4]}
    behavior, security = feedback.get("behavior") or {}, feedback.get("security") or {}
    if behavior and not behavior.get("passed"):
        category = "behavior_regression"
    elif security and not security.get("passed"):
        category = "security_witness_failed"
    elif feedback.get("remaining_rules"):
        category = "finding_remaining"
    else:
        category = "unknown"
    failed = [{"suite": suite, "test": d.get("name"), "marker": d.get("assertion")}
              for suite, result in (("behavior", behavior), ("security", security)) for d in result.get("details", [])]
    return {"category": category, "failed_tests": failed[:8], "remaining_rules": list(feedback.get("remaining_rules", []))[:4]}


def guidance_for(kind, failure, level):
    """Static guidance for a failure; level is clamped to the deepest available text."""
    if not failure:
        return None
    category = failure["category"]
    texts = GUIDANCE.get(kind, {}).get(category) or GUIDANCE["*"].get(category) or GUIDANCE["*"]["unknown"]
    return texts[max(0, min(level, len(texts) - 1))]
