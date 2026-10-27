"""Findings from any scanner reduce to one CWE family; unknown stays unknown."""
import pytest

from safepatch.feedback import DIAGNOSIS, GUIDANCE_KEY
from safepatch.weakness import family, cwe_id, own_rules


@pytest.mark.parametrize("value,expected", [
    ("CWE-89", "CWE-89"), ("cwe-089", "CWE-89"), (["CWE-22: Improper Limitation of a Pathname"], "CWE-22"),
    ("CWE89", "CWE-89"), (None, None), ("", None), (["owasp-a03"], None), ("XCWE-89", None),
])
def test_cwe_ids_are_normalized(value, expected):
    assert cwe_id(value) == expected


@pytest.mark.parametrize("finding,expected", [
    ({"tool": "semgrep", "rule_id": "bigg.java.sql-concatenation", "cwe": "CWE-89"}, "CWE-89"),
    ({"tool": "semgrep", "rule_id": "bigg.java.path-resolution"}, "CWE-22"),          # own rule, CWE from rules/java.yml
    ({"tool": "sonarqube", "rule_id": "javasecurity:S2076"}, "CWE-78"),
    ({"tool": "findsecbugs", "rule_id": "SQL_INJECTION_HIBERNATE"}, "CWE-89"),         # CWE-564 is a child of CWE-89
    ({"tool": "semgrep", "rule_id": "x", "raw_rule_id": "javasecurity:S3649"}, "CWE-89"),
    ({"tool": "semgrep", "rule_id": "javasecurity:S3649", "cwe": ["CWE-22"]}, "CWE-22"),  # the finding's own CWE wins
    ({"tool": "semgrep", "rule_id": "vendor.unmapped.rule"}, None),
    ({"tool": "semgrep", "rule_id": "vendor.rule", "cwe": "CWE-79"}, "CWE-79"),          # known CWE, no family table needed
])
def test_family_of_a_finding(finding, expected):
    assert family(finding) == expected


def test_every_own_rule_declares_a_cwe():
    # A class package adds its rule with CWE metadata; without it memory could never match the rule.
    assert own_rules() and all(own_rules().values())


def test_guidance_keys_name_existing_guidance():
    assert set(GUIDANCE_KEY.values()) <= set(DIAGNOSIS) - {"*"}
