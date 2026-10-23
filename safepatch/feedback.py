"""Trusted retry feedback: deterministic failure classes and static repair guidance.

Verifier facts are reduced to a compact failure record. Test names and messages
from the repository stay data. Guidance text is fixed SafePatch content written
by the team; it never contains model output or repository text.
"""
from safepatch.common import canonical, digest

CATEGORIES = ("compilation_failed", "behavior_regression", "security_witness_failed", "finding_remaining", "unknown")

# Guidance has two levels. Level 0 is a diagnosis of the failure category. Level 1 adds
# the weakness recipe (the standard secure repair), whatever the category: a model that
# keeps a wrong approach needs the right approach, not another compiler hint.
# Written from development cases (*-01) only; evaluation cases are reported separately.
DIAGNOSIS = {
    "sql": {
        "security_witness_failed": "The input is still interpreted as SQL: a quote in the input changes the query result.",
        "behavior_regression": "Normal account lookups must return the same names as before.",
    },
    "path": {
        "security_witness_failed": "A parent-directory input such as '../x' still reads outside the root. A startsWith check on a path that is not canonical does not stop '..' segments.",
        "behavior_regression": "Reading files inside the root, including nested relative paths such as 'sub/file.txt', must keep working.",
    },
    "command": {
        "security_witness_failed": "Shell metacharacters in the input are still interpreted. The input must be one literal argv element, never part of a shell command.",
        "behavior_regression": "Legitimate inputs must still produce exactly \"echo:\" followed by the input. The previous patch changed what the child process prints.",
    },
    "*": {
        "compilation_failed": "The previous patch does not compile; see the compiler diagnostics in feedback_data. Keep the package, class name, public method signature and required imports.",
        "behavior_regression": "The previous patch changed legitimate behavior.",
        "security_witness_failed": "The security test can still exploit the code.",
        "finding_remaining": "The scanner still reports the weakness at the same sink; remove the vulnerable construction itself, do not suppress or wrap it.",
        "unknown": "The previous patch failed verification.",
    },
}
RECIPES = {
    "sql": "Build the query with a '?' placeholder, call conn.prepareStatement(sql) and statement.setString(1, input). Never concatenate input into SQL. Keep try-with-resources, sorting and the comma-joined result.",
    "path": "Canonicalize before checking: make the root canonical with toRealPath(), resolve the input against it, make the target canonical with toRealPath() or normalize(), and throw unless target.startsWith(root). Nested relative paths must keep working.",
    "command": "Do not run a shell and do not build a command string. Start a fixed executable with the input as its own argv element. If read_only_context_data contains a helper main class, run it with the current classpath: new ProcessBuilder(java, \"-cp\", System.getProperty(\"java.class.path\"), \"<helper class>\", input). Keep the timeout and exit-code checks.",
    "*": "Fix the root cause at the sink with the standard safe API for this weakness; keep the public API and legitimate behavior.",
}
GUIDANCE_SHA256 = digest(canonical({"diagnosis": DIAGNOSIS, "recipes": RECIPES}))


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
    """Static guidance: level 0 is the diagnosis, level 1 and deeper add the weakness recipe."""
    if not failure:
        return None
    category = failure["category"]
    diagnosis = DIAGNOSIS.get(kind, {}).get(category) or DIAGNOSIS["*"].get(category) or DIAGNOSIS["*"]["unknown"]
    return diagnosis if level <= 0 else diagnosis + " " + RECIPES.get(kind, RECIPES["*"])
