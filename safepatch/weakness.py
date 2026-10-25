"""Scanner-independent weakness identity: each finding is reduced to a CWE family.

Memory and repair guidance match on the family, never on one scanner's rule id, so a
fix approved from a Semgrep finding also applies to a Sonar or FindSecBugs finding of
the same weakness. A finding whose CWE cannot be established has family None, and
memory treats it as `unknown` (roadmap week 4).
"""
from pathlib import Path
import re

import yaml

from safepatch.common import ROOT, setting

# Child CWE -> family, from the CWE "ChildOf" relations of the supported classes.
FAMILY = {"CWE-564": "CWE-89", "CWE-23": "CWE-22", "CWE-36": "CWE-22", "CWE-338": "CWE-330"}

# Rules whose findings carry no CWE of their own. The Sonar keys are those the runner
# already requires; the FindSecBugs names follow its bug pattern list. Each entry is
# confirmed when its adapter first runs against the live tool. A missing entry only
# means `unknown`, never a wrong match.
TOOL_RULES = {
    "javasecurity:S3649": "CWE-89", "javasecurity:S2083": "CWE-22", "javasecurity:S2076": "CWE-78",
    "SQL_INJECTION_JDBC": "CWE-89", "SQL_INJECTION_SPRING_JDBC": "CWE-89", "SQL_INJECTION_JPA": "CWE-89",
    "SQL_INJECTION_HIBERNATE": "CWE-564", "PATH_TRAVERSAL_IN": "CWE-22", "COMMAND_INJECTION": "CWE-78",
    "PREDICTABLE_RANDOM": "CWE-330",
}


def cwe_id(value):
    """'CWE-89', 'cwe-089' or ['CWE-89: Improper ...'] -> 'CWE-89'; anything else -> None."""
    for item in value if isinstance(value, (list, tuple)) else [value]:
        match = re.search(r"\bCWE-?0*(\d+)\b", str(item or ""), re.IGNORECASE)
        if match:
            return "CWE-" + match.group(1)
    return None


def own_rules(file=None):
    """CWE of each of our own Semgrep rules (trusted repository file)."""
    data = yaml.safe_load(Path(file or setting("RULES_FILE", str(ROOT / "rules/java.yml"))).read_text(encoding="utf-8"))
    return {rule["id"]: cwe_id((rule.get("metadata") or {}).get("cwe")) for rule in data.get("rules", [])}


RULE_CWE = {**own_rules(), **TOOL_RULES}


def family(finding):
    """CWE family of a finding: its own CWE, else its rule's; None when neither is known."""
    cwe = cwe_id(finding.get("cwe")) or RULE_CWE.get(finding.get("rule_id")) or RULE_CWE.get(finding.get("raw_rule_id"))
    return FAMILY.get(cwe, cwe) if cwe else None
