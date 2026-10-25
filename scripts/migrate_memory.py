"""Bring memory records written before week 4 to the current schema (ROADMAP.md week 4).

Adds the CWE family (from the record's rule id), the structural signature (from the
stored source before the fix) and the evidence vector (from the source job, when it is
still in the database). Earlier uses are listed with result "unrecorded". What cannot be
completed stays None, so the record is `unknown` for matching. Each migrated approved
record gets a new version and an event that keeps its previous context.

Usage: python scripts/migrate_memory.py [--database URL] [--dry-run]
The default database is the orchestrator's (DATABASE_URL or .runtime/jobs.db).
"""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from safepatch.memory import Memory
from safepatch.store import Store


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", help="SQLAlchemy URL, e.g. sqlite:///C:/path/jobs.db")
    parser.add_argument("--dry-run", action="store_true", help="report what would change, write nothing")
    args = parser.parse_args()
    report = Memory(Store(args.database)).migrate(dry_run=args.dry_run)
    print(json.dumps({"dry_run": args.dry_run, **report}, indent=2))


if __name__ == "__main__":
    main()
