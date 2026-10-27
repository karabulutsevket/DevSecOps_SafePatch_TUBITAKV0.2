"""Build a signed L2 package from the approved L1 records of a SafePatch lab database (ROADMAP.md week 7).

Publisher side. A record's source job names its case, and the case must be an owned development
case of the L3 catalog (l3/catalog.yml) with an allowed license: no evaluation case and no
external code is shipped. A record approved by a simulated reviewer ships only in a package
built with --experiment. The private key stays on the publisher host; installations hold only
the public key, in their allowed-signers file.

  python scripts/l2_build.py --database sqlite:///LAB.db --version 1 --key PUBLISHER_KEY --out PACKAGE.zip [--experiment]
"""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from safepatch.l2 import PackageError, build, from_lab
from safepatch.memory import Memory
from safepatch.store import Store
from l3_catalog import load


def lab_records(store, catalog):
    """L2 records for every approved L1 record of the lab database; a record whose case is not
    in the catalog stops the build rather than being skipped."""
    cases = {c.id: c.model_dump() for c in catalog.cases}
    records = []
    for memory in Memory(store).all():
        if memory["state"] != "approved":
            continue
        case_id = store.get(memory["source_job"])["case_id"]
        if case_id not in cases:
            raise PackageError("case_not_in_l3_catalog:" + case_id)
        records.append(from_lab(memory, cases[case_id]))
    return records


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--database", required=True)
    parser.add_argument("--version", type=int, required=True)
    parser.add_argument("--publisher", default="safepatch-lab")
    parser.add_argument("--key", required=True, help="publisher's private key (OpenSSH, Ed25519)")
    parser.add_argument("--out", required=True)
    parser.add_argument("--experiment", action="store_true")
    parser.add_argument("--withdraw", nargs="*", default=[])
    args = parser.parse_args(argv)
    records = lab_records(Store(args.database), load())
    print(json.dumps(build(records, args.publisher, args.version, args.key, args.out, args.experiment, args.withdraw), indent=2))


if __name__ == "__main__":
    main()
