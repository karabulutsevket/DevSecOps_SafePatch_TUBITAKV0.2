import json
from pathlib import Path
import secrets
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from safepatch.common import ROOT, digest

NAMES = ("WORKER1_TOKEN", "WORKER2_TOKEN", "RUNNER_TOKEN", "ARTIFACT_READ_TOKEN", "DEPLOYER_TOKEN", "APPROVAL_SIGNING_KEY", "POSTGRES_PASSWORD")


def initialize():
    folder = ROOT / ".secrets"
    folder.mkdir(exist_ok=True)
    for name in NAMES:
        file = folder / name.lower()
        if not file.exists():
            file.write_text(secrets.token_hex(32), encoding="utf-8")
    users = []
    for name, roles in (("developer", ["submit"]), ("reviewer", ["review"]), ("deployer", ["deploy"])):
        file = folder / (name + ".token")
        if not file.exists():
            file.write_text(secrets.token_hex(32), encoding="utf-8")
        users.append({"subject": "local-" + name, "roles": roles, "token_sha256": digest(file.read_text().strip()), "enabled": True})
    if not (folder / "users.json").exists():
        (folder / "users.json").write_text(json.dumps(users, indent=2), encoding="utf-8")
    print("Unique credentials created in .secrets; no credential values printed.")


if __name__ == "__main__":
    initialize()
