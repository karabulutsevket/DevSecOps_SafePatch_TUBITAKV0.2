"""Policy is trusted code; repository/model prose has no authority here."""
from collections import Counter
import difflib
from pathlib import Path
import re

from safepatch.common import digest, safe_path


class PolicyError(ValueError):
    pass


# Tight scope. Deny external network, reflection, process exit, test/CI suppression and
# repository-supplied instructions to alter policy.
# Suppressions and test/build markers: none on an added line.
STRICT = re.compile(r"(?i)(NOSONAR|nosemgrep|SuppressWarnings|\.m2|surefire|org\.junit|\.github|sonar\.exclusions)")
# Capabilities, each reference with what follows it: java.net.URISyntaxException is not java.net.URL.
CAPABILITY = re.compile(r"(?i)(System\s*\.\s*exit|Runtime\s*\.\s*getRuntime(?:\s*\(\s*\)\s*\.\s*\w+)?|java\.net(?:\s*\.\s*[\w*]+)*"
                        r"|java\.lang\.reflect(?:\s*\.\s*[\w*]+)*|Class\.forName|ProcessHandle(?:\s*\.\s*\w+)*|System\.getenv|setSecurityManager|Unsafe)")


def references(pattern, text):
    return Counter(re.sub(r"\s+", "", m.group(0)).lower() for m in pattern.finditer(text))


def introduces_forbidden(original, content, diff):
    """A patch may not add a suppression or test/build marker on any line, nor make any
    capability reference more frequent than the file had it (counted over the whole file, so
    one split across lines is caught). An edited line may keep a reference the file already
    had (L3 run, owasp-benchmark-01643: a catch clause naming java.net.URISyntaxException);
    a new reference, also behind the same package token, is refused."""
    added = "".join(line[1:] for line in diff if line.startswith("+") and not line.startswith("+++"))
    if STRICT.search(added):
        return True
    return any(after[r] > before[r] for pattern in (STRICT, CAPABILITY)
               for before, after in [(references(pattern, original), references(pattern, content))] for r in after)


def validate_patch(base, patch, workspace: Path | None = None, allowed=()):
    """`allowed`: files this patch may change (the finding's file, already checked against
    the project descriptor by the caller). Nothing is editable by default."""
    seen = set()
    diffs = []
    changed = 0
    if not 1 <= len(patch.edits) <= 3:
        raise PolicyError("file_budget")
    for edit in patch.edits:
        if edit.path not in allowed or not safe_path(edit.path) or edit.path in seen:
            raise PolicyError("protected_or_unauthorized_path")
        if workspace:
            dest = workspace / edit.path
            if any(p.is_symlink() for p in (dest, *dest.parents)) or not dest.resolve().is_relative_to(workspace.resolve()):
                raise PolicyError("symlink_escape")
        seen.add(edit.path)
        original = base[edit.path]
        if digest(original) != edit.old_sha256:
            raise PolicyError("stale_base_hash")
        if "\x00" in edit.content or "\r" in edit.content:
            raise PolicyError("invalid_source_encoding")
        diff = list(difflib.unified_diff(original.splitlines(True), edit.content.splitlines(True), fromfile="a/" + edit.path, tofile="b/" + edit.path))
        if introduces_forbidden(original, edit.content, diff):
            raise PolicyError("forbidden_capability_or_suppression")
        if diff and not diff[-1].endswith("\n"):
            raise PolicyError("source_requires_final_newline")
        changed += sum(line.startswith(("+", "-")) and not line.startswith(("+++", "---")) for line in diff)
        diffs.extend(diff)
    if changed == 0:
        raise PolicyError("empty_patch")
    if changed > 200:
        raise PolicyError("line_budget")
    result = "".join(diffs)
    return {"diff": result, "patch_sha256": digest(result), "changed_lines": changed}
