"""Trusted retry feedback: deterministic failure classes and static repair guidance.

Verifier facts are reduced to a compact failure record. Test names and messages
from the repository stay data. Guidance text is fixed SafePatch content written
by the team; it never contains model output or repository text.
"""
from safepatch.common import canonical, digest

CATEGORIES = ("compilation_failed", "behavior_regression", "security_witness_failed", "finding_remaining", "empty_patch", "unknown", "infrastructure")

# Guidance has two levels. Level 0 is a diagnosis of the failure category. Level 1 adds
# the weakness recipe (the standard secure repair), whatever the category: a model that
# keeps a wrong approach needs the right approach, not another compiler hint.
# Written from development cases (*-01) only; evaluation cases are reported separately.
# The path texts were revised on 25 Oct 2026 after the H2 review of accepted patches
# (docs/OLCUM_V02_YENIDEN_DENEME.md): the old recipe allowed normalize(); toRealPath() is now required.
# Revised again on 25 Oct 2026 (week 5) on the region-mode development cases: a file about to be
# created has no real path, so toRealPath() on it fails (docs/OLCUM_VUL4J.md).
DIAGNOSIS = {
    "sql": {
        "security_witness_failed": "The input is still interpreted as SQL: a quote in the input changes the query result.",
        "behavior_regression": "Normal account lookups must return the same names as before.",
    },
    "path": {
        "security_witness_failed": "A file outside the root can still be reached: through a parent-directory input such as '../x', an absolute path, or a link inside the root that points outside. A startsWith check on a path that was not resolved through the file system misses links.",
        "behavior_regression": "Files inside the root must keep working, read or written, including nested relative paths such as 'sub/file.txt' and a root configured through a link.",
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
        "empty_patch": "The previous answer returned the code unchanged. Change the vulnerable code itself.",
        "unknown": "The previous patch failed verification.",
    },
}
RECIPES = {
    "sql": "Build the query with a '?' placeholder, call conn.prepareStatement(sql) and statement.setString(1, input). Never concatenate input into SQL. Keep try-with-resources, sorting and the comma-joined result.",
    "path": "Resolve both paths through the file system before checking: make the root real with toRealPath(), resolve the input against it, make the target real with toRealPath(), and throw unless target.startsWith(root). Use toRealPath() for both; normalize() alone only rewrites the text and does not follow links. A file about to be created has no real path yet: resolve it under the real root, normalize() it and throw unless it startsWith(root); after creating its parent directories, make the parent real with toRealPath() and throw unless that startsWith(root) too. Nested relative paths and a root given through a link must keep working.",
    "command": "Do not run a shell and do not build a command string. Start a fixed executable with the input as its own argv element. If read_only_context_data contains a helper main class, run it with the current classpath: new ProcessBuilder(java, \"-cp\", System.getProperty(\"java.class.path\"), \"<helper class>\", input). Keep the timeout and exit-code checks.",
    "*": "Fix the root cause at the sink with the standard safe API for this weakness; keep the public API and legitimate behavior.",
}
GUIDANCE_SHA256 = digest(canonical({"diagnosis": DIAGNOSIS, "recipes": RECIPES}))
# CWE family (safepatch.weakness) -> guidance texts; any other family gets the generic ("*") texts.
GUIDANCE_KEY = {"CWE-89": "sql", "CWE-22": "path", "CWE-78": "command"}

# Title of the trusted note worker1 appends after the data. Repository text that
# imitates it is treated as a prompt-injection attempt, never as guidance.
NOTE_TITLE = "SafePatch verifier note"


def imitates_note(*texts):
    """True when untrusted text contains the trusted note title (case-insensitive)."""
    title = NOTE_TITLE.casefold()
    return any(title in (text or "").casefold() for text in texts)


def classify(verified):
    """Reduce a verifier result to a compact, deterministic failure record."""
    feedback = verified.get("feedback") or {}
    behavior, security = feedback.get("behavior") or {}, feedback.get("security") or {}
    # The environment failed, not the patch: a build with no compiler line to point at
    # (offline Maven cache, timeout) or a test run that left no JUnit report.
    if feedback.get("code") == "compilation_failed" and not feedback.get("diagnostics"):
        return {"category": "infrastructure", "reason": "build_without_compiler_diagnostic"}
    for suite, result in (("behavior", behavior), ("security", security)):
        if result.get("infrastructure_error"):
            return {"category": "infrastructure", "reason": suite + "_" + (result.get("reason") or "test_run_failed")}
    if feedback.get("code") == "compilation_failed":
        return {"category": "compilation_failed", "diagnostics": list(feedback["diagnostics"])[:4]}
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


def patch_caused(verified, failure):
    """True when the patch itself failed. Infrastructure failures and missing evidence (a
    project without a security witness) teach nothing about the repair."""
    feedback = verified.get("feedback") or {}
    if not failure or failure["category"] in ("unknown", "infrastructure") or feedback.get("code") == "security_witness_missing":
        return False
    security = feedback.get("security") or {}
    return not (failure["category"] == "security_witness_failed" and security.get("missing"))


def guidance_for(kind, failure, level):
    """Static guidance: level 0 is the diagnosis, level 1 and deeper add the weakness recipe."""
    if not failure:
        return None
    category = failure["category"]
    diagnosis = DIAGNOSIS.get(kind, {}).get(category) or DIAGNOSIS["*"].get(category) or DIAGNOSIS["*"]["unknown"]
    return diagnosis if level <= 0 else diagnosis + " " + RECIPES.get(kind, RECIPES["*"])
