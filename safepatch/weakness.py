"""Scanner-independent weakness identity: each finding is reduced to a CWE family.

Memory and repair guidance match on the family, never on one scanner's rule id, so a
fix approved from a Semgrep finding also applies to a Sonar or FindSecBugs finding of
the same weakness. A finding whose CWE cannot be established has family None, and
memory treats it as `unknown` (roadmap week 4).
"""
from pathlib import Path
import re

import yaml

from safepatch.common import ROOT, canonical, digest, setting

# Child CWE -> family, from the CWE "ChildOf" relations of the supported classes.
FAMILY = {"CWE-564": "CWE-89", "CWE-23": "CWE-22", "CWE-36": "CWE-22", "CWE-338": "CWE-330"}
# Families whose class package (witness, tests, guidance, rules, development cases) is complete:
# only these become jobs. A scanner that reports more (FindSecBugs: log injection, trust
# boundary) keeps the rest as other findings, which would otherwise block every fix in the file.
SUPPORTED = frozenset({"CWE-89", "CWE-22", "CWE-78"})

# Rules whose findings carry no CWE of their own. The Sonar keys are those the runner
# already requires; the FindSecBugs names follow its bug pattern list. Each entry is
# confirmed when its adapter first runs against the live tool. A missing entry only
# means `unknown`, never a wrong match. FindSecBugs 1.14.0 (27 Oct 2026) names the CWE in its
# SARIF itself, which the adapter reads first; SQL_INJECTION_JDBC, SQL_INJECTION_SPRING_JDBC,
# PATH_TRAVERSAL_IN and COMMAND_INJECTION were seen there with the CWEs below.
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


def rule_definitions(file=None):
    data = yaml.safe_load(Path(file or setting("RULES_FILE", str(ROOT / "rules/java.yml"))).read_text(encoding="utf-8"))
    return {rule["id"]: rule for rule in data.get("rules", [])}


def own_rules(file=None):
    """CWE of each of our own Semgrep rules (trusted repository file)."""
    return {rule_id: cwe_id((rule.get("metadata") or {}).get("cwe")) for rule_id, rule in rule_definitions(file).items()}


RULE_CWE = {**own_rules(), **TOOL_RULES}
# One digest per own rule: a memory record must be revalidated when its rule changes,
# and only then (week 5); other rules may change freely.
RULE_DIGESTS = {rule_id: digest(canonical(rule)) for rule_id, rule in rule_definitions().items()}


def family(finding):
    """CWE family of a finding: its own CWE, else its rule's; None when neither is known."""
    cwe = cwe_id(finding.get("cwe")) or RULE_CWE.get(finding.get("rule_id")) or RULE_CWE.get(finding.get("raw_rule_id"))
    return FAMILY.get(cwe, cwe) if cwe else None
