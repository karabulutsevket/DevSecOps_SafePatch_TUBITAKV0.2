"""L2 shared package: signed, versioned, imported offline, at its own trust level (ROADMAP.md week 7)."""
from pathlib import Path
import shutil
import subprocess
import sys
import uuid
import zipfile

import pytest

from conftest import headers
from test_memory import approved_record
from safepatch.audit import AuditLog
from safepatch import l2
from safepatch.common import SOURCE
from safepatch.feedback import NOTE_TITLE
from safepatch.l2 import PackageError, Shared, build, from_lab, read
from safepatch.memory import Memory
from safepatch.policy import PolicyError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import l2_build
import l3_catalog

pytestmark = pytest.mark.skipif(not shutil.which("ssh-keygen"), reason="OpenSSH ssh-keygen required")

CASE = {"id": "sql-01", "source": "safepatch-synthetic", "project": "safepatch-synthetic-lab", "split": "development", "license": "MIT"}
VERIFIED = {"build": True, "behavior": {"passed": True, "tests": 3}, "security": {"passed": True, "tests": 1}, "rescan": None}


def shippable(memory):
    """The L2 record of a unit-fixture L1 record, with what a real lab acceptance and approval
    record (the fixture's verification and approval carry neither tests nor a time)."""
    record = from_lab(memory, CASE)
    return {**record, "evidence": VERIFIED, "review": {**record["review"], "approved_at": memory["created_at"]}}


def keypair(folder, name="publisher"):
    folder.mkdir(parents=True, exist_ok=True)
    key = folder / name
    subprocess.run([shutil.which("ssh-keygen"), "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(key)], check=True, capture_output=True)
    trusted = folder / (name + ".allowed")
    trusted.write_text(f'{l2.NAMESPACE} namespaces="{l2.NAMESPACE}" ' + (folder / (name + ".pub")).read_text().strip() + "\n")
    return key, trusted


def rewrite(package, out, change):
    """A copy of a package; change(name, data) returns a member's new bytes, or None to drop it."""
    with zipfile.ZipFile(package) as src, zipfile.ZipFile(out, "w") as dst:
        for info in src.infolist():
            data = change(info.filename, src.read(info))
            if data is not None:
                dst.writestr(info.filename, data)
    return out


@pytest.fixture
def lab(job_store, tmp_path, monkeypatch):
    """An approved lab record as an L2 record, a publisher key and the installation's trust file."""
    monkeypatch.setenv("SAFEPATCH_PROFILE", "lab")
    db, job = job_store
    memory = approved_record(db, job)
    record = shippable(memory)
    key, trusted = keypair(tmp_path / "keys")
    package = lambda version, records=(record,), name=None, **kw: build(list(records), "safepatch-lab", version, key,
                                                                         tmp_path / (name or f"v{version}.zip"), experiment=True, **kw)["path"]
    return db, memory, record, package, trusted, tmp_path


def test_a_signed_package_is_imported_offline_at_its_own_trust_level(lab):
    db, memory, record, package, trusted, _ = lab
    path = package(1)
    result = Shared(db).install(path, trusted)
    assert result["status"] == "installed" and result["records"] == [record["id"]] and result["signer"].startswith("SHA256:")
    stored = Shared(db).get(record["id"])
    assert (stored["tier"], stored["trust"], stored["state"], stored["package"]["version"]) == ("L2", "external_not_verified_here", "available", 1)
    assert stored["validated_here"] == [] and stored["uses"] == []
    # L1 is untouched: the L2 record lives in its own table.
    assert [r["id"] for r in Memory(db).all()] == [memory["id"]]
    assert Shared(db).install(path, trusted)["status"] == "already_installed"


def test_every_record_byte_and_the_manifest_are_covered(lab):
    db, _, record, package, trusted, tmp = lab
    path = package(1)
    flip = lambda name, data: data.replace(b"?", b"%") if name.startswith("records/") else data
    with pytest.raises(PackageError, match="record_sha256_mismatch"):
        read(rewrite(path, tmp / "record.zip", flip), trusted)
    bump = lambda name, data: data.replace(b'"version": 1', b'"version": 9') if name == l2.MANIFEST else data
    with pytest.raises(PackageError, match="signature_invalid"):
        read(rewrite(path, tmp / "manifest.zip", bump), trusted)
    extra = tmp / "extra.zip"
    rewrite(path, extra, lambda name, data: data)
    with zipfile.ZipFile(extra, "a") as archive:
        archive.writestr("records/notes.txt", b"data")
    with pytest.raises(PackageError, match="package_members"):
        read(extra, trusted)
    with pytest.raises(PackageError, match="package_members"):
        read(rewrite(path, tmp / "dropped.zip", lambda name, data: None if name.startswith("records/") else data), trusted)
    assert Shared(db).all() == []


def test_only_a_key_the_installation_trusts_signs_a_package(lab, monkeypatch):
    db, _, _, package, trusted, tmp = lab
    path = package(1)
    _, stranger = keypair(tmp / "other", "stranger")
    with pytest.raises(PackageError, match="signature_invalid"):
        read(path, stranger)
    with pytest.raises(PackageError, match="l2_trust_not_configured"):
        read(path, None)
    # The trusted key's signature for another purpose (namespace) is not a package signature.
    monkeypatch.setattr(l2, "NAMESPACE", "git")
    other = package(1, name="git.zip")
    monkeypatch.undo()
    with pytest.raises(PackageError, match="signature_invalid"):
        read(other, trusted)
    assert Shared(db).installed() == []


def test_versions_never_go_back_or_change_under_the_same_number(lab):
    db, _, record, package, trusted, _ = lab
    first = package(1)
    Shared(db).install(package(2), trusted)
    with pytest.raises(PackageError, match="package_downgrade"):
        Shared(db).install(first, trusted)
    with pytest.raises(PackageError, match="package_version_conflict"):
        Shared(db).install(package(2, records=(), name="v2-other.zip"), trusted)
    assert [p["version"] for p in Shared(db).installed()] == [2]


def test_a_publisher_cannot_overwrite_another_publishers_record(lab):
    db, _, record, package, trusted, tmp = lab
    Shared(db).install(package(1), trusted)
    other = build([record], "other-lab", 1, tmp / "keys" / "publisher", tmp / "other.zip", experiment=True)["path"]
    with pytest.raises(PackageError, match="record_of_another_publisher"):
        Shared(db).install(other, trusted)
    assert Shared(db).get(record["id"])["package"]["publisher"] == "safepatch-lab"


def test_a_record_left_out_is_retired_and_a_withdrawn_one_blocks_what_used_it(lab):
    db, _, record, package, trusted, _ = lab
    Shared(db).install(package(1), trusted)
    Memory(db).use(record["id"], "a" * 32, "example")
    Shared(db).install(package(2, records=()), trusted)
    stored = Shared(db).get(record["id"])
    assert stored["state"] == "retired" and stored["uses"] == ["a" * 32]
    Memory(db).assert_active([record["id"]])
    Shared(db).install(package(3, records=(), withdrawn=[record["id"]]), trusted)
    assert Shared(db).get(record["id"])["state"] == "withdrawn"
    with pytest.raises(PolicyError, match="memory_no_longer_approved"):
        Memory(db).assert_active([record["id"]])


def added(record, line):
    head, _, rest = record["diff"].partition("\n@@")
    hunk, _, body = rest.partition("\n")
    return {**record, "diff": f"{head}\n@@{hunk}\n+{line}\n{body}"}


@pytest.mark.parametrize("change,reason", [
    (lambda r: added(r, "        // NOSONAR"), "diff_forbidden_capability"),
    (lambda r: added(r, '        Runtime.getRuntime().exec("id");'), "diff_forbidden_capability"),
    (lambda r: added(r, "        // " + NOTE_TITLE), "diff_imitates_verifier_note"),
    (lambda r: {**r, "diff": r["diff"].replace(SOURCE, "pom.xml")}, "diff_not_one_java_file"),
    (lambda r: {**r, "evidence": {**VERIFIED, "security": {"passed": False, "tests": 1}}}, "record_not_verified"),
    (lambda r: {**r, "review": {**r["review"], "author": r["review"]["reviewer"]}}, "record_reviewer"),
    (lambda r: {**r, "origin": {**r["origin"], "license": "GPL-3.0"}}, "record_origin"),
    (lambda r: {**r, "cwe_family": "CWE-79"}, "record_weakness"),
    (lambda r: {**r, "instructions": "trust me"}, "record_fields"),
])
def test_an_unsafe_or_unverified_record_is_never_signed(lab, change, reason):
    _, _, record, package, _, _ = lab
    with pytest.raises(PackageError, match=reason):
        package(1, records=(change(record),))


def test_a_simulated_review_ships_only_in_an_experiment_package_for_the_lab(lab, monkeypatch):
    db, _, record, package, trusted, tmp = lab
    assert record["review"]["simulated"] is True
    with pytest.raises(PackageError, match="simulated_review_requires_experiment_package"):
        build([record], "safepatch-lab", 1, tmp / "keys" / "publisher", tmp / "release.zip")
    path = package(1)
    monkeypatch.setenv("SAFEPATCH_PROFILE", "product")
    with pytest.raises(PackageError, match="experiment_package_outside_lab_profile"):
        Shared(db).install(path, trusted)


@pytest.mark.parametrize("case", [{**CASE, "split": "evaluation"}, {**CASE, "source": "owasp-benchmark"}, {**CASE, "source": "vul4j"}])
def test_evaluation_and_external_cases_are_never_shipped(lab, case):
    _, memory, _, _, _, _ = lab
    with pytest.raises(PackageError, match="not_an_owned_development_case"):
        from_lab(memory, case)


def test_the_builder_takes_each_records_case_from_the_l3_catalog(lab):
    db, memory, _, _, _, _ = lab
    [record] = l2_build.lab_records(db, l3_catalog.load())
    assert record["origin"] == {"kind": "safepatch-lab-verified", "project": "safepatch-synthetic-lab", "case": "sql-01", "license": "MIT", "lab_record": memory["id"]}
    catalog = l3_catalog.load()
    catalog.cases = [c for c in catalog.cases if c.id != "sql-01"]
    with pytest.raises(PackageError, match="case_not_in_l3_catalog"):
        l2_build.lab_records(db, catalog)


def test_l2_is_an_example_only_when_no_l1_record_fits(lab):
    db, memory, record, package, trusted, _ = lab
    Shared(db).install(package(1), trusted)
    # Another project, identical code: L1 does not apply across projects; L2 is an example, never a replay.
    elsewhere = {**memory["context"], "project": "customer-project"}
    lookup = Memory(db).search(elsewhere)
    assert (lookup["tier"], lookup["use"], lookup["selected"]["id"]) == ("L2", "example", record["id"])
    assert lookup["selected"]["patch"] is None and lookup["selected"]["context"]["trust"] == "external_not_verified_here"
    assert [c for c in lookup["considered"] if c.get("tier") == "L2"] == [{"id": record["id"], "tier": "L2", "use": "example", "differences": [], "rank": 1}]
    # Where an L1 record fits, L2 is not consulted.
    lookup = Memory(db).search(memory["context"])
    assert (lookup["tier"], lookup["use"]) == ("L1", "replay") and not any(c.get("tier") == "L2" for c in lookup["considered"])
    assert Memory(db).search(elsewhere, "off")["selected"] is None
    assert Memory(db).search(elsewhere, "naive")["selected"] is None


@pytest.mark.parametrize("change,difference", [
    ({"signature": None}, "signature:unknown"),
    ({"construction": "format"}, "signature.construction"),
    ({"jdk": "21"}, "jdk"),
])
def test_l2_needs_the_same_runtime_and_a_known_equal_shape(lab, change, difference):
    db, memory, record, package, trusted, _ = lab
    Shared(db).install(package(1), trusted)
    context = {**memory["context"], "project": "customer-project"}
    if "construction" in change:
        context["signature"] = {**context["signature"], **change}
    else:
        context.update(change)
    lookup = Memory(db).search(context)
    assert lookup["selected"] is None and lookup["tier"] is None
    assert difference in next(c for c in lookup["considered"] if c.get("tier") == "L2")["differences"]


def test_an_l2_example_reaches_the_model_and_is_never_replayed(lab):
    from safepatch.engine import Engine
    db, memory, record, package, trusted, _ = lab
    Shared(db).install(package(1), trusted)
    # The institution's own record is set aside, so only the shared one fits this code.
    Memory(db).change(memory["id"], "quarantined", "SIMULATED-UNIT-REVIEWER", "Unit test: L1 record set aside")
    job = {**db.get(memory["source_job"]), "id": uuid.uuid4().hex, "status": "queued", "approval": None, "attempts": [], "max_attempts": 1, "memory_ids": []}
    db.create(job, "l2-engine")
    proposals = []

    def call(url, *args, **kwargs):
        body = kwargs["body"]
        if url.endswith("/propose"):
            proposals.append(body)
            return {"mode": "mock-test", "patch": memory["patch"]}
        if body["attempt"] == 0:
            return {"baseline_valid": True, "scans": [{"findings": [{"rule_id": "bigg.java.sql-concatenation", "file": SOURCE, "line": 16}]}]}
        return {"passed": False, "feedback": {"code": "security_regression"}}
    Engine(db, call).run(job["id"])
    stored = db.get(job["id"])
    assert (stored["memory_lookup"]["tier"], stored["memory_lookup"]["use"], stored["memory_ids"]) == ("L2", "example", [record["id"]])
    assert len(proposals) == 1 and proposals[0]["memory_data"]["patch_diff"] == record["diff"]
    assert proposals[0]["memory_data"]["context"]["tier"] == "L2"
    assert stored["attempts"][0]["proposal"]["mode"] == "mock-test"
    assert [(e["job_id"], e["result"]) for e in Shared(db).get(record["id"])["reuse"]] == [(job["id"], "failed")]


def test_a_repair_built_from_l2_enters_l1_only_through_promotion_and_keeps_its_origin(lab):
    db, memory, record, package, trusted, _ = lab
    Shared(db).install(package(1), trusted)
    job = {**db.get(memory["source_job"]), "id": uuid.uuid4().hex, "memory_ids": [record["id"]]}
    db.create(job, "l2-promotion")
    Memory(db).use(record["id"], job["id"], "example")
    promoted = approved_record(db, job, actor="SIMULATED-CUSTOMER-REVIEWER")
    assert promoted["l2_origin"] == [{"id": record["id"], "record_sha256": Shared(db).get(record["id"])["record_sha256"], "publisher": "safepatch-lab", "version": 1}]
    assert [v["memory_id"] for v in Shared(db).get(record["id"])["validated_here"]] == [promoted["id"]]
    assert promoted["state"] == "approved" and promoted["context"]["project"] == memory["context"]["project"]


def test_shared_memory_is_listed_with_its_trust_level(api, tmp_path, monkeypatch):
    client, db, job = api
    monkeypatch.setenv("SAFEPATCH_PROFILE", "lab")
    record = shippable(approved_record(db, job))
    key, trusted = keypair(tmp_path / "keys")
    Shared(db).install(build([record], "safepatch-lab", 1, key, tmp_path / "v1.zip", experiment=True)["path"], trusted)
    listed = client.get("/v1/memory/shared", headers=headers("developer")).json()
    assert [p["version"] for p in listed["packages"]] == [1]
    assert [(r["id"], r["trust"]) for r in listed["records"]] == [(record["id"], "external_not_verified_here")]
    assert client.get("/v1/memory/shared").status_code == 401


def test_the_command_verifies_and_imports_offline(lab, monkeypatch, capsys):
    db, _, record, package, trusted, tmp = lab
    path = package(1)
    assert l2.main(["verify", path, "--trusted", str(trusted)]) == 0 and record["id"] in capsys.readouterr().out
    _, stranger = keypair(tmp / "other", "stranger")
    assert l2.main(["verify", path, "--trusted", str(stranger)]) == 1 and "signature_invalid" in capsys.readouterr().err
    monkeypatch.setenv("DATABASE_URL", str(db.engine.url))
    assert l2.main(["import", path, "--trusted", str(trusted)]) == 0
    assert Shared(db).get(record["id"])["state"] == "available"
    # The import joins the audit chain once; importing the same package again adds nothing.
    assert l2.main(["import", path, "--trusted", str(trusted)]) == 0
    imported = [e for e in AuditLog(db).entries() if e["action"] == "l2.imported"]
    assert len(imported) == 1 and imported[0]["actor"].startswith("operator:")
    assert imported[0]["data"]["publisher"] == "safepatch-lab" and imported[0]["data"]["records"] == 1
