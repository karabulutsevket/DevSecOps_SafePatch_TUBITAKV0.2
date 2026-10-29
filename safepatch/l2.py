"""Shared knowledge package (L2): signed, versioned and imported offline (ROADMAP.md week 7).

L2 records are made at SafePatch from lab-verified repairs, never from customer data, and reach
an installation only inside a signed package: a zip holding manifest.json (publisher, version,
one SHA-256 per record), its OpenSSH signature (Ed25519, namespace `safepatch-l2`, checked by
`ssh-keygen -Y verify` against the installation's own allowed-signers file) and the records.
A valid signature says who made the package, not that its content is safe: every record is
still checked field by field, and one bad record refuses the whole package.

Trust level: an L2 record is "external, not verified in this institution". It is never
replayed, only offered to the model as an example when no L1 record fits, and the candidate is
verified as usual. It reaches L1 only as the institution's own verified repair, through the
usual human promotion (Memory.promote), which records the L2 origin.

Usage (offline, on the orchestrator host; the database is DATABASE_URL):
  python -m safepatch.l2 verify  PACKAGE --trusted ALLOWED_SIGNERS
  python -m safepatch.l2 import  PACKAGE --trusted ALLOWED_SIGNERS
  python -m safepatch.l2 list
"""
import argparse
import getpass
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile

from sqlalchemy import Column, Float, JSON, MetaData, String, Table, select, update

from safepatch.common import digest, safe_path, setting
from safepatch.feedback import imitates_note
from safepatch.policy import PolicyError, introduces_forbidden
from safepatch.signature import SCHEMA as SIGNATURE_SCHEMA
from safepatch.weakness import SUPPORTED

SCHEMA = "safepatch-l2/1"
RECORD_SCHEMA = "safepatch-l2-record/1"
NAMESPACE = "safepatch-l2"
PREFIX = "l2:"
MANIFEST, SIGNATURE = "manifest.json", "manifest.json.sig"
MAX_PACKAGE_BYTES, MAX_RECORD_BYTES, MAX_RECORDS = 20 * 2**20, 256 * 2**10, 2000
# Licenses a record's source may carry. Today only SafePatch's own lab code (MIT); any other
# source is a license decision first (docs/LISANSLAR_VE_KAYNAKLAR.md).
LICENSES = frozenset({"MIT"})
ORIGINS = frozenset({"safepatch-lab-verified"})
# What an L2 example must share with the finding: no project, file or hash, only the weakness.
SHAPE = ("sink", "construction", "library", "library_version")
TRUST = "external_not_verified_here"
ID = re.compile(r"^l2:[a-z0-9][a-z0-9-]{0,63}$")
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,79}$")


class PackageError(ValueError):
    pass


def keygen():
    tool = setting("SSH_KEYGEN") or shutil.which("ssh-keygen")
    if not tool:
        raise PackageError("ssh_keygen_not_found")
    return tool


def sign(data, key, workdir):
    """OpenSSH signature of `data` with the publisher's private key (publisher side only)."""
    path = Path(workdir) / MANIFEST
    path.write_bytes(data)
    result = subprocess.run([keygen(), "-Y", "sign", "-f", str(key), "-n", NAMESPACE, str(path)], capture_output=True, timeout=60)
    if result.returncode:
        raise PackageError("signing_failed:" + result.stderr.decode(errors="replace")[:200])
    return (Path(workdir) / SIGNATURE).read_bytes()


def check_signature(data, signature, trusted, identity=NAMESPACE):
    """The signer's key fingerprint when `signature` is a good `safepatch-l2` signature of
    `data` by a key the allowed-signers file `trusted` lists for `identity`."""
    if not trusted or not Path(trusted).is_file():
        raise PackageError("l2_trust_not_configured")
    with tempfile.TemporaryDirectory() as work:
        sig = Path(work) / SIGNATURE
        sig.write_bytes(signature)
        result = subprocess.run([keygen(), "-Y", "verify", "-f", str(trusted), "-I", identity, "-n", NAMESPACE, "-s", str(sig)],
                                input=data, capture_output=True, timeout=60)
    said = (result.stdout + result.stderr).decode(errors="replace")
    found = re.search(r"SHA256:[A-Za-z0-9+/=]+", said)
    if result.returncode or not found:
        raise PackageError("signature_invalid")
    return found.group(0)


def diff_refused(diff):
    """Why a stored diff may not be shipped as an example, or None. The same rule as a patch:
    no suppression or test/build marker added, no capability reference added (here counted
    over the diff's own removed and added lines)."""
    lines = diff.splitlines(keepends=True)
    if not lines or not lines[0].startswith("--- ") or not any(l.startswith("@@") for l in lines):
        return "diff_not_unified"
    paths = {l[6:].strip() for l in lines if l.startswith(("--- a/", "+++ b/"))}
    if len(paths) != 1 or not all(safe_path(p) and p.endswith(".java") for p in paths):
        return "diff_not_one_java_file"
    if imitates_note(diff):
        return "diff_imitates_verifier_note"
    removed = "".join(l[1:] for l in lines if l.startswith("-") and not l.startswith("---"))
    added = "".join(l[1:] for l in lines if l.startswith("+") and not l.startswith("+++"))
    if introduces_forbidden(removed, added, lines):
        return "diff_forbidden_capability"
    return None


def record_problem(record):
    """Why `record` is not a valid L2 repair record, or None. Records are data: every field is
    checked for type and range, unknown fields are refused."""
    fields = {"schema", "id", "kind", "cwe_family", "jdk", "signature", "source_path", "diff", "origin", "evidence", "review"}
    if not isinstance(record, dict) or set(record) != fields:
        return "record_fields"
    if record["schema"] != RECORD_SCHEMA or record["kind"] != "repair":
        return "record_schema"
    if not isinstance(record["id"], str) or not ID.match(record["id"]):
        return "record_id"
    if record["cwe_family"] not in SUPPORTED or not isinstance(record["jdk"], str) or not re.fullmatch(r"\d{1,2}", record["jdk"]):
        return "record_weakness"
    sig = record["signature"]
    if (not isinstance(sig, dict) or sig.get("schema") != SIGNATURE_SCHEMA or not all(isinstance(sig.get(k), str) and sig[k] for k in SHAPE[:3])
            or not all(v is None or isinstance(v, str) and len(v) <= 200 for v in sig.values())):
        return "record_signature"
    if not isinstance(record["source_path"], str) or not safe_path(record["source_path"]) or not record["source_path"].endswith(".java"):
        return "record_source_path"
    if not isinstance(record["diff"], str) or len(record["diff"]) > 64000:
        return "record_diff"
    refused = diff_refused(record["diff"])
    if refused:
        return refused
    origin = record["origin"]
    if (not isinstance(origin, dict) or set(origin) != {"kind", "project", "case", "license", "lab_record"} or origin["kind"] not in ORIGINS
            or origin["license"] not in LICENSES or not all(isinstance(origin[k], str) and NAME.match(origin[k]) for k in ("project", "case", "lab_record"))):
        return "record_origin"
    evidence = record["evidence"]
    if (not isinstance(evidence, dict) or evidence.get("build") is not True
            or not all(isinstance(evidence.get(k), dict) and evidence[k].get("passed") is True for k in ("behavior", "security"))):
        return "record_not_verified"
    review = record["review"]
    if not isinstance(review, dict) or set(review) != {"author", "reviewer", "approved_at", "simulated"}:
        return "record_review"
    if review["author"] is not None and (not isinstance(review["author"], str) or not NAME.match(review["author"])):
        return "record_review"
    if not isinstance(review["reviewer"], str) or not NAME.match(review["reviewer"]) or review["reviewer"] == review["author"]:
        return "record_reviewer"
    if not isinstance(review["simulated"], bool) or not isinstance(review["approved_at"], (int, float)):
        return "record_review"
    return None


def manifest_problem(manifest):
    if not isinstance(manifest, dict) or set(manifest) != {"schema", "publisher", "version", "created_at", "experiment", "records", "withdrawn"}:
        return "manifest_fields"
    if manifest["schema"] != SCHEMA or not isinstance(manifest["publisher"], str) or not NAME.match(manifest["publisher"]):
        return "manifest_schema"
    if not isinstance(manifest["version"], int) or isinstance(manifest["version"], bool) or manifest["version"] < 1:
        return "manifest_version"
    if not isinstance(manifest["experiment"], bool) or not isinstance(manifest["created_at"], (int, float)):
        return "manifest_schema"
    entries, withdrawn = manifest["records"], manifest["withdrawn"]
    if not isinstance(entries, list) or len(entries) > MAX_RECORDS or not isinstance(withdrawn, list) or len(withdrawn) > MAX_RECORDS:
        return "manifest_records"
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"id", "sha256"} or not isinstance(entry["id"], str) or not ID.match(entry["id"]):
            return "manifest_records"
        if not isinstance(entry["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
            return "manifest_records"
    ids = [e["id"] for e in entries]
    if len(set(ids)) != len(ids) or len({e["sha256"] for e in entries}) != len(ids):
        return "manifest_duplicate_record"
    if not all(isinstance(w, str) and ID.match(w) for w in withdrawn) or set(withdrawn) & set(ids):
        return "manifest_withdrawn"
    return None


def read(path, trusted, identity=NAMESPACE):
    """(manifest, its SHA-256, signer fingerprint, records) of a package that passes every
    check; PackageError otherwise. Nothing is extracted to disk and nothing is written."""
    path = Path(path)
    if not path.is_file() or path.stat().st_size > MAX_PACKAGE_BYTES:
        raise PackageError("package_size")
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        raise PackageError("package_not_zip") from None
    with archive:
        infos = archive.infolist()
        names = [i.filename for i in infos]
        if len(names) != len(set(names)) or not {MANIFEST, SIGNATURE} <= set(names):
            raise PackageError("package_members")

        def member(name, limit):
            info = archive.getinfo(name)
            if info.file_size > limit:
                raise PackageError("member_size:" + name)
            with archive.open(info) as handle:
                data = handle.read(limit + 1)
            if len(data) > limit:
                raise PackageError("member_size:" + name)
            return data

        data = member(MANIFEST, MAX_RECORD_BYTES)
        signer = check_signature(data, member(SIGNATURE, 4096), trusted, identity)
        try:
            manifest = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise PackageError("manifest_not_json") from None
        problem = manifest_problem(manifest)
        if problem:
            raise PackageError(problem)
        expected = {MANIFEST, SIGNATURE} | {f"records/{e['sha256']}.json" for e in manifest["records"]}
        if set(names) != expected:
            raise PackageError("package_members")
        records = []
        for entry in manifest["records"]:
            raw = member(f"records/{entry['sha256']}.json", MAX_RECORD_BYTES)
            if digest(raw) != entry["sha256"]:
                raise PackageError("record_sha256_mismatch:" + entry["id"])
            try:
                record = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                raise PackageError("record_not_json:" + entry["id"]) from None
            problem = record_problem(record) or (None if record["id"] == entry["id"] else "record_id_mismatch")
            if problem:
                raise PackageError(problem + ":" + entry["id"])
            records.append(record)
    return manifest, digest(data), signer, records


def from_lab(memory, case):
    """An L2 record from an approved L1 record of SafePatch's own lab (publisher side). `case`
    is the L3 catalog entry of the record's case: only owned development cases are shipped,
    never an evaluation case (CLAUDE.md, rule 8)."""
    if case.get("split") != "development" or case.get("source") != "safepatch-synthetic":
        raise PackageError("not_an_owned_development_case:" + str(case.get("id")))
    if memory["state"] != "approved":
        raise PackageError("lab_record_not_approved:" + memory["id"])
    context, approval = memory["context"], memory.get("approval") or {}
    reviewer = approval.get("reviewer")
    return {"schema": RECORD_SCHEMA, "id": f"{PREFIX}{case['id']}-{memory['id'][:12]}", "kind": "repair",
            "cwe_family": context.get("cwe_family"), "jdk": context.get("jdk"), "signature": context.get("signature"),
            "source_path": context.get("source_path"), "diff": memory["diff"],
            "origin": {"kind": "safepatch-lab-verified", "project": case["project"], "case": case["id"], "license": case.get("license"), "lab_record": memory["id"]},
            "evidence": {k: (memory.get("evidence") or {}).get(k) for k in ("build", "behavior", "security", "rescan")},
            # Simulated approvals are named so (CLAUDE.md, rule 3); they ship only in an experiment package.
            "review": {"author": memory.get("author"), "reviewer": reviewer, "approved_at": approval.get("approved_at"),
                       "simulated": str(reviewer).startswith("SIMULATED")}}


def build(records, publisher, version, key, out, experiment=False, withdrawn=()):
    """Write a signed package (publisher side). Every record must already be valid, and a
    package holding a simulated review must say it is an experiment."""
    for record in records:
        problem = record_problem(record)
        if problem:
            raise PackageError(problem + ":" + str(record.get("id")))
        if record["review"]["simulated"] and not experiment:
            raise PackageError("simulated_review_requires_experiment_package:" + record["id"])
    blobs = {r["id"]: (json.dumps(r, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8") for r in records}
    manifest = {"schema": SCHEMA, "publisher": publisher, "version": version, "created_at": time.time(), "experiment": experiment,
                "records": [{"id": i, "sha256": digest(b)} for i, b in sorted(blobs.items())], "withdrawn": sorted(withdrawn)}
    problem = manifest_problem(manifest)
    if problem:
        raise PackageError(problem)
    data = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    with tempfile.TemporaryDirectory() as work:
        signature = sign(data, key, work)
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "x", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(MANIFEST, data)
        archive.writestr(SIGNATURE, signature)
        for i, blob in sorted(blobs.items()):
            archive.writestr(f"records/{digest(blob)}.json", blob)
    return {"path": str(out), "manifest_sha256": digest(data), "records": len(blobs)}


def differences(record, context):
    """Which matching facts differ between an L2 record and a job (suffix ':unknown' if missing)."""
    found = [k for k in ("cwe_family", "jdk") if record.get(k) != context.get(k)]
    signature = context.get("signature")
    if not signature:
        return found + ["signature:unknown"]
    return found + ["signature." + k for k in SHAPE if record["signature"].get(k) != signature.get(k)]


def example_view(record):
    """What the engine and the model see of an L2 record: its diff and the facts it matched on."""
    return {"id": record["id"], "tier": "L2", "diff": record["diff"], "patch": None, "author": None,
            "context": {"tier": "L2", "trust": TRUST, "project": record["origin"]["project"], "cwe_family": record["cwe_family"],
                        "jdk": record["jdk"], "source_path": record["source_path"], "signature": record["signature"]}}


class Shared:
    """L2 records and installed packages, apart from the institution's own L1 tables."""

    def __init__(self, store):
        self.store = store
        meta = MetaData()
        self.table = Table("shared_memory", meta, Column("id", String(80), primary_key=True), Column("created", Float), Column("data", JSON, nullable=False))
        self.packages = Table("l2_packages", meta, Column("id", String(120), primary_key=True), Column("created", Float), Column("data", JSON, nullable=False))
        meta.create_all(store.engine)

    def all(self):
        with self.store.engine.connect() as conn:
            return [r[0] for r in conn.execute(select(self.table.c.data).order_by(self.table.c.created.desc()))]

    def installed(self):
        with self.store.engine.connect() as conn:
            return [r[0] for r in conn.execute(select(self.packages.c.data).order_by(self.packages.c.created.desc()))]

    def get(self, record_id):
        with self.store.engine.connect() as conn:
            row = conn.execute(select(self.table.c.data).where(self.table.c.id == record_id)).first()
        if row is None:
            raise KeyError(record_id)
        return row[0]

    def install(self, path, trusted, identity=NAMESPACE):
        """Import a package: all of it or nothing. A version is installed once; an older or a
        different package under an installed version is refused (no downgrade, no replay)."""
        manifest, manifest_sha256, signer, records = read(path, trusted, identity)
        # A package with a simulated review is for the lab and evaluation profiles only.
        if manifest["experiment"] and setting("SAFEPATCH_PROFILE", "product") not in ("lab", "evaluation"):
            raise PackageError("experiment_package_outside_lab_profile")
        publisher, version, now = manifest["publisher"], manifest["version"], time.time()
        with self.store.lock, self.store.engine.begin() as conn:
            existing = {r["id"]: r for r in self.all()}
            latest = max((p for p in self.installed() if p["publisher"] == publisher), key=lambda p: p["version"], default=None)
            if latest and version == latest["version"]:
                if latest["manifest_sha256"] == manifest_sha256:
                    return {"status": "already_installed", **latest}
                raise PackageError("package_version_conflict")
            if latest and version < latest["version"]:
                raise PackageError("package_downgrade")
            if any(existing[r["id"]]["package"]["publisher"] != publisher for r in records if r["id"] in existing):
                raise PackageError("record_of_another_publisher")
            package = {"publisher": publisher, "version": version, "manifest_sha256": manifest_sha256, "signer": signer,
                       "experiment": manifest["experiment"], "created_at": manifest["created_at"], "imported_at": now,
                       "records": [r["id"] for r in records], "withdrawn": manifest["withdrawn"]}
            conn.execute(self.packages.insert().values(id=f"{publisher}:{version}", created=now, data=package))
            shipped = {r["id"] for r in records}
            for record in records:
                old = existing.get(record["id"])
                # Local evidence (uses, outcomes, validations here) outlives package versions.
                local = {k: old[k] for k in ("uses", "reuse", "validated_here", "imported_at")} if old else {"uses": [], "reuse": [], "validated_here": [], "imported_at": now}
                data = {**record, **local, "tier": "L2", "trust": TRUST, "state": "available", "updated_at": now,
                        "package": {"publisher": publisher, "version": version, "manifest_sha256": manifest_sha256, "signer": signer, "experiment": manifest["experiment"]},
                        "record_sha256": next(e["sha256"] for e in manifest["records"] if e["id"] == record["id"])}
                if old:
                    conn.execute(update(self.table).where(self.table.c.id == record["id"]).values(data=data))
                else:
                    conn.execute(self.table.insert().values(id=record["id"], created=now, data=data))
            # A record the publisher withdrew blocks what was built from it; one merely left out
            # of the new version is retired: no longer offered, nothing built from it is touched.
            for old in existing.values():
                if old["package"]["publisher"] != publisher or old["id"] in shipped:
                    continue
                state = "withdrawn" if old["id"] in manifest["withdrawn"] else "retired"
                if old["state"] != state:
                    conn.execute(update(self.table).where(self.table.c.id == old["id"]).values(data={**old, "state": state, "updated_at": now}))
        return {"status": "installed", **package}

    def candidates(self, context):
        """(considered entries, usable records): available records of the job's weakness with a
        known, equal signature shape. Locally verified reuse ranks first, then the newest."""
        considered, usable = [], []
        for record in self.all():
            if record["cwe_family"] != context.get("cwe_family"):
                continue
            if record["state"] != "available":
                considered.append({"id": record["id"], "tier": "L2", "use": None, "differences": ["state:" + record["state"]]})
                continue
            found = differences(record, context)
            considered.append({"id": record["id"], "tier": "L2", "use": None if found else "example", "differences": found})
            if not found:
                usable.append(record)
        score = lambda r: sum({"verified": 1, "failed": -2}.get(e["result"], 0) for e in r["reuse"])
        usable.sort(key=lambda r: (-score(r), -r["updated_at"]))
        return considered, usable

    def assert_active(self, record_id):
        if self.get(record_id)["state"] == "withdrawn":
            raise PolicyError("memory_no_longer_approved")

    def _change(self, record_id, fn):
        with self.store.lock, self.store.engine.begin() as conn:
            try:
                record = self.get(record_id)
            except KeyError:
                return None
            fn(record)
            conn.execute(update(self.table).where(self.table.c.id == record_id).values(data=record))
            return record

    def use(self, record_id, job_id, how):
        if self.get(record_id)["state"] != "available":
            raise PolicyError("memory_no_longer_approved")

        def add(record):
            if job_id not in record["uses"]:
                record["uses"].append(job_id)
                record["reuse"].append({"job_id": job_id, "use": how, "result": "pending", "review": None, "at": time.time()})
        self._change(record_id, add)

    def settle(self, record_id, job_id, result=None, review=None):
        def note(record):
            entry = next((e for e in record["reuse"] if e["job_id"] == job_id), None)
            if entry:
                entry.update({k: v for k, v in (("result", result), ("review", review)) if v}, at=time.time())
        return self._change(record_id, note)

    def validated(self, record_id, memory_id, job_id):
        """The institution verified and approved a repair built from this record; it is now L1 `memory_id`."""
        return self._change(record_id, lambda r: r["validated_here"].append({"memory_id": memory_id, "job_id": job_id, "at": time.time()}))


def main(argv=None):
    from safepatch.audit import AuditLog
    from safepatch.store import Store
    parser = argparse.ArgumentParser(description="L2 ortak bilgi paketi: doğrula, içeri al, listele (çevrimdışı)")
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("verify", "import"):
        child = sub.add_parser(action)
        child.add_argument("package")
        child.add_argument("--trusted", default=setting("L2_ALLOWED_SIGNERS"), help="allowed-signers dosyası (L2_ALLOWED_SIGNERS)")
        child.add_argument("--identity", default=NAMESPACE)
    sub.add_parser("list")
    args = parser.parse_args(argv)
    try:
        if args.action == "verify":
            manifest, manifest_sha256, signer, records = read(args.package, args.trusted, args.identity)
            result = {"valid": True, "publisher": manifest["publisher"], "version": manifest["version"], "experiment": manifest["experiment"],
                      "manifest_sha256": manifest_sha256, "signer": signer, "records": [r["id"] for r in records]}
        elif args.action == "import":
            store = Store()
            result = Shared(store).install(args.package, args.trusted, args.identity)
            if result["status"] == "installed":
                # Offline, so the actor is the operator's account on this machine.
                AuditLog(store).append("operator:" + getpass.getuser(), "l2.imported", result["manifest_sha256"], publisher=result["publisher"],
                                       version=result["version"], signer=result["signer"], experiment=result["experiment"], records=len(result["records"]))
        else:
            shared = Shared(Store())
            result = {"packages": shared.installed(), "records": [{k: r[k] for k in ("id", "cwe_family", "state", "trust", "validated_here")} for r in shared.all()]}
    except PackageError as exc:
        print(json.dumps({"valid": False, "error": str(exc)}), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
