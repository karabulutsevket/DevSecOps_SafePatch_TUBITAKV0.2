"""A patch written outside SafePatch: a developer's fix, GitHub Copilot Autofix, Sonar AI CodeFix.

It arrives as a unified diff (`git diff` output) and becomes the whole-file patch a model or an
expert would send: applied to the project's pinned base commit with exact context, then checked
by the same policy, verifier and human approval (docs/YAMA_DOGRULAMA.md). The diff is untrusted
data. Its lines are only matched and copied; what gets verified, and shown to the reviewer, is the
diff SafePatch computes between the pinned base and the result.
"""
import re

from safepatch.common import Patch, digest, safe_path
from safepatch.feedback import imitates_note
from safepatch.policy import PolicyError, validate_patch
from safepatch.repository import allowed_files

# The job mode and candidate origin of a submitted patch.
ORIGIN = "submitted-patch"
# What the submitter declares made the patch (developer, copilot-autofix, sonar-codefix): a label, never prose.
TOOL = r"^[a-z0-9][a-z0-9._+-]{0,39}$"
MAX_HUNKS = 100
HUNK = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
# git's a/ and b/ prefixes, or the mnemonic ones (i/, w/, c/, o/) some configurations use.
PREFIX = re.compile(r"[a-z]/")
# Git headers of changes other than edited lines of an existing text file.
UNSUPPORTED = ("new file mode", "deleted file mode", "old mode", "new mode", "rename from", "rename to", "copy from",
               "copy to", "similarity index", "dissimilarity index", "Binary files", "GIT binary patch")


def header_path(old, new):
    """The file a ---/+++ pair names. A one-letter prefix on both sides is dropped, as `git apply`
    drops the first component; `--no-prefix` paths stay whole. GNU diff appends a timestamp after
    a tab; git quotes unusual paths, which are refused rather than unquoted."""
    old, new = old.split("\t")[0], new.split("\t")[0]
    if "/dev/null" in (old, new):
        raise PolicyError("diff_unsupported_change")
    if old.startswith('"') or new.startswith('"'):
        raise PolicyError("diff_malformed")
    if PREFIX.match(old) and PREFIX.match(new):
        old, new = old[2:], new[2:]
    if old != new:
        raise PolicyError("diff_unsupported_change")
    return old


def read_hunk(lines, i):
    """(start, old lines, new lines) of the hunk whose header is lines[i], and the next index.
    An empty line is an empty context line (some editors strip the trailing space); a line
    starting with a backslash marks the line before it as having no final newline."""
    match = HUNK.match(lines[i])
    if not match:
        raise PolicyError("diff_malformed")
    old_left, new_left = int(match[2] or 1), int(match[4] or 1)
    entries = []
    i += 1
    while old_left or new_left:
        if i >= len(lines):
            raise PolicyError("diff_malformed")
        line = lines[i]
        op, text = (line[0], line[1:]) if line else (" ", "")
        if op == "\\" and entries:
            entries[-1][2] = False
        elif op in " -+":
            old_left -= op != "+"
            new_left -= op != "-"
            if old_left < 0 or new_left < 0:
                raise PolicyError("diff_malformed")
            entries.append([op, text, True])
        else:
            raise PolicyError("diff_malformed")
        i += 1
    if entries and i < len(lines) and lines[i].startswith("\\"):
        entries[-1][2] = False
        i += 1
    old = [text + "\n" * newline for op, text, newline in entries if op != "+"]
    new = [text + "\n" * newline for op, text, newline in entries if op != "-"]
    return (int(match[1]), old, new), i


def parse(text):
    """{path: hunks} of a unified diff. Lines before the first file header are ignored (a commit
    message, `git show` or `format-patch` headers), and so is a `format-patch` signature."""
    if "\r" in text or "\x00" in text:
        raise PolicyError("diff_invalid_encoding")
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    files, current, started, i = {}, None, False, 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("diff --git "):
            current, started = None, True
            i += 1
        elif started and line.startswith(UNSUPPORTED):
            raise PolicyError("diff_unsupported_change")
        elif line.startswith("--- ") and i + 1 < len(lines) and lines[i + 1].startswith("+++ "):
            path = header_path(line[4:], lines[i + 1][4:])
            if path in files:
                raise PolicyError("diff_malformed")
            current, started = files.setdefault(path, []), True
            i += 2
        elif line.startswith("@@"):
            if current is None:
                raise PolicyError("diff_malformed")
            hunk, i = read_hunk(lines, i)
            if current and hunk[0] <= current[-1][0]:
                raise PolicyError("diff_malformed")   # hunks out of order
            current.append(hunk)
        elif not started or line.startswith("index ") or not line.strip():
            i += 1
        elif line == "-- ":
            break
        else:
            raise PolicyError("diff_malformed")
    if not files or not all(files.values()):
        raise PolicyError("diff_malformed")
    if sum(len(h) for h in files.values()) > MAX_HUNKS:
        raise PolicyError("diff_too_large")
    return files


def lines_of(text):
    """Lines with their newline, split on "\\n" only, as a diff is (str.splitlines also splits on
    form feeds and other separators a Java file may hold)."""
    parts = text.split("\n")
    return [p + "\n" for p in parts[:-1]] + ([parts[-1]] if parts[-1] else [])


def apply(original, hunks):
    """The file after the hunks. Each hunk's old lines must match exactly: at its stated line,
    shifted as far as the hunk before it was, or else at the one other place they occur. A hunk
    with no old line at all could go anywhere and is refused, as `git apply` does by default."""
    lines = lines_of(original)
    out, pos, drift = [], 0, 0
    for start, old, new in hunks:
        if not old:
            raise PolicyError("diff_needs_context")
        at = start - 1 + drift
        if not (at >= pos and lines[at:at + len(old)] == old):
            found = [n for n in range(pos, len(lines) - len(old) + 1) if lines[n] == old[0] and lines[n:n + len(old)] == old]
            if len(found) != 1:
                raise PolicyError("diff_ambiguous" if found else "diff_does_not_apply")
            at = found[0]
        out += lines[pos:at] + new
        pos, drift = at + len(old), at - (start - 1)
    return "".join(out + lines[pos:])


def patch_from_diff(files, text, rationale):
    """The diff as a whole-file patch on the pinned base files: one file, changed in place."""
    parsed = parse(text)
    if len(parsed) != 1:
        raise PolicyError("patch_must_change_one_file")
    (path, hunks), = parsed.items()
    if not safe_path(path) or len(path) > 180 or path not in files:
        raise PolicyError("diff_unknown_file")
    original = files[path]
    content = apply(original, hunks)
    try:
        return Patch.model_validate({"edits": [{"path": path, "old_sha256": digest(original), "content": content}], "rationale": rationale})
    except ValueError:
        raise PolicyError("diff_too_large") from None


def submitted_patch(case, files, text, rationale):
    """(patch, policy result) for a submitted diff: the same checks as an expert's patch."""
    patch = patch_from_diff(files, text, rationale)
    path = patch.edits[0].path
    meta = validate_patch(files, patch, allowed=allowed_files(case["spec"], files, path))
    # Approved patches can reach later prompts through memory; keep forged notes out.
    if imitates_note(rationale, text, patch.edits[0].content):
        raise PolicyError("suspected_prompt_injection")
    return patch, meta
