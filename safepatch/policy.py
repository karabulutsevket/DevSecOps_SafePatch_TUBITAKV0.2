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
FORBIDDEN = re.compile(r"(?i)(NOSONAR|nosemgrep|SuppressWarnings|System\s*\.\s*exit|Runtime\s*\.\s*getRuntime|java\.net|java\.lang\.reflect|Class\.forName|ProcessHandle|System\.getenv|setSecurityManager|Unsafe|\.m2|surefire|org\.junit|\.github|sonar\.exclusions)")


def introduces_forbidden(original, content, diff):
    """A patch may not add a forbidden token: none on an added line, and no token more often in
    the file than before (catches one split across lines). Tokens the project file already had
    in untouched code stay; real files carry them (zt-zip's ZipUtil.java has three NOSONAR)."""
    added = "".join(line[1:] for line in diff if line.startswith("+") and not line.startswith("+++"))
    if FORBIDDEN.search(added):
        return True
    before, after = Counter(m.lower() for m in FORBIDDEN.findall(original)), Counter(m.lower() for m in FORBIDDEN.findall(content))
    return any(after[token] > before[token] for token in after)


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
