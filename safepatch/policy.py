"""Policy is trusted code; repository/model prose has no authority here."""
import difflib
from pathlib import Path
import re

from safepatch.common import digest, safe_path


class PolicyError(ValueError):
    pass


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
        # Tight synthetic scope. Deny external network, reflection, process exit,
        # test/CI suppression and repository-supplied instructions to alter policy.
        forbidden = r"(?i)(NOSONAR|nosemgrep|SuppressWarnings|System\s*\.\s*exit|Runtime\s*\.\s*getRuntime|java\.net|java\.lang\.reflect|Class\.forName|ProcessHandle|System\.getenv|setSecurityManager|Unsafe|\.m2|surefire|org\.junit|\.github|sonar\.exclusions)"
        if re.search(forbidden, edit.content):
            raise PolicyError("forbidden_capability_or_suppression")
        diff = list(difflib.unified_diff(original.splitlines(True), edit.content.splitlines(True), fromfile="a/" + edit.path, tofile="b/" + edit.path))
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
