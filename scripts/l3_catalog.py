"""Check and report the L3 evaluation set (l3/catalog.yml, ROADMAP.md week 6).

Exits non-zero when a rule is broken:
- an external case (Vul4J, OWASP Benchmark) is evaluation only;
- a project is on one side only (development or evaluation);
- a ready evaluation case has hidden tests: an existing folder and test selectors;
- case ids are unique and every hidden folder belongs to a case.
Prints the ready and planned counts per weakness family and side against the targets.
"""
from collections import Counter
from pathlib import Path
import sys
from typing import Literal

from pydantic import Field
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from safepatch.common import Strict
from safepatch.project import SuiteSelection
from safepatch.weakness import family

CATALOG = ROOT / "l3/catalog.yml"
EXTERNAL = ("vul4j", "owasp-benchmark")


class Hidden(Strict):
    path: str = Field(pattern=r"^l3/hidden/[A-Za-z0-9._-]+$")
    selectors: list[str] = Field(min_length=1, max_length=20)

    def selection(self):
        return SuiteSelection(selectors=self.selectors)


class Case(Strict):
    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$")
    source: Literal["safepatch-synthetic", "vul4j", "owasp-benchmark"]
    project: str = Field(min_length=1, max_length=200)
    cwe: str = Field(pattern=r"^CWE-[0-9]{1,5}$")
    split: Literal["development", "evaluation"]
    license: str = Field(min_length=1, max_length=60)
    upstream: dict[str, str] = Field(default_factory=dict)
    prepare: str | None = None
    hidden: Hidden | None = None
    status: Literal["ready", "planned"]


class Catalog(Strict):
    schema_version: Literal["safepatch-l3/1"] = Field(alias="schema")
    targets: dict[Literal["development", "evaluation"], int]
    cases: list[Case]


def load(path=CATALOG):
    return Catalog.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")))


def case(case_id, catalog=None):
    found = [c for c in (catalog or load()).cases if c.id == case_id]
    if not found:
        raise KeyError(case_id)
    return found[0]


def problems(catalog, root=ROOT):
    found = []
    ids = Counter(c.id for c in catalog.cases)
    found += [f"duplicate case id {i}" for i, n in ids.items() if n > 1]
    sides = {}
    for c in catalog.cases:
        sides.setdefault(c.project, set()).add(c.split)
        if c.source in EXTERNAL and c.split != "evaluation":
            found.append(f"{c.id}: an external case ({c.source}) is evaluation only")
        if c.split == "evaluation" and c.status == "ready":
            if not c.hidden:
                found.append(f"{c.id}: a ready evaluation case needs hidden tests")
            elif not (root / c.hidden.path).is_dir():
                found.append(f"{c.id}: hidden test folder {c.hidden.path} is missing")
        if c.prepare and not (root / c.prepare).is_file():
            found.append(f"{c.id}: prepare script {c.prepare} is missing")
    found += [f"project {p} is on both sides" for p, s in sides.items() if len(s) > 1]
    owned = {c.hidden.path for c in catalog.cases if c.hidden}
    found += [f"hidden folder l3/hidden/{d.name} belongs to no case" for d in sorted((root / "l3/hidden").glob("*"))
              if d.is_dir() and f"l3/hidden/{d.name}" not in owned]
    return found


def report(catalog):
    lines = []
    for split in ("development", "evaluation"):
        cases = [c for c in catalog.cases if c.split == split]
        ready = [c for c in cases if c.status == "ready"]
        by_family = Counter(family({"cwe": c.cwe}) for c in ready)
        planned = Counter(family({"cwe": c.cwe}) for c in cases if c.status == "planned")
        lines.append(f"{split}: {len(ready)} ready of target {catalog.targets[split]} ({len({c.project for c in ready})} projects); "
                     f"ready by family {dict(sorted(by_family.items()))}; planned {dict(sorted(planned.items()))}")
    return lines


def main():
    catalog = load()
    for line in report(catalog):
        print(line)
    found = problems(catalog)
    for problem in found:
        print("PROBLEM:", problem)
    raise SystemExit(1 if found else 0)


if __name__ == "__main__":
    main()
