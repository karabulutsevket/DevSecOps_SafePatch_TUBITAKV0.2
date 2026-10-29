import json
import threading
import time

import pytest
from sqlalchemy import delete, update

from conftest import headers
from safepatch import audit
from safepatch.audit import GENESIS, AuditLog
from safepatch.common import POLICY, canonical, digest
from safepatch.engine import Engine
from safepatch.store import Store
from test_approval import ready


def chain(db, n=4):
    log = AuditLog(db)
    for i in range(n):
        log.append("reviewer", "job.approved", f"job-{i}", comment=f"ok {i}")
    return log


def rewrite(log, seq, change, rehash=False):
    """Edit one stored entry the way someone with database access would."""
    entry = next(e for e in log.entries() if e["seq"] == seq)
    entry.pop("hash")
    change(entry)
    text = canonical(entry)
    values = {"entry": text, **({"hash": digest(text)} if rehash else {})}
    with log.store.engine.begin() as conn:
        conn.execute(update(log.table).where(log.table.c.seq == seq).values(**values))


def sql(log, statement):
    with log.store.engine.begin() as conn:
        conn.execute(statement)


def test_each_entry_carries_the_hash_of_the_one_before(job_store):
    log = chain(job_store[0])
    entries = log.entries()
    assert [e["seq"] for e in entries] == [1, 2, 3, 4] and entries[0]["prev"] == GENESIS
    assert all(b["prev"] == a["hash"] for a, b in zip(entries, entries[1:]))
    assert log.verify() == {"ok": True, "entries": 4, "head": {"seq": 4, "hash": entries[-1]["hash"]}}
    assert [e["subject"] for e in log.entries("job-2")] == ["job-2"]


@pytest.mark.parametrize("tamper,broken_at,reason", [
    (lambda log: rewrite(log, 2, lambda e: e.update(actor="someone-else")), 2, "hash_mismatch"),
    (lambda log: rewrite(log, 2, lambda e: e["data"].update(comment="changed later"), rehash=True), 3, "chain_broken"),
    (lambda log: sql(log, delete(log.table).where(log.table.c.seq == 2)), 3, "sequence_gap"),
    (lambda log: sql(log, update(log.table).where(log.table.c.seq == 3).values(subject="job-0")), 3, "subject_mismatch"),
    (lambda log: sql(log, update(log.table).where(log.table.c.seq == 1).values(entry="not json")), 1, "entry_unreadable"),
])
def test_a_changed_removed_or_reindexed_entry_breaks_the_chain(job_store, tamper, broken_at, reason):
    log = chain(job_store[0])
    tamper(log)
    result = log.verify()
    assert (result["ok"], result["broken_at"], result["reason"]) == (False, broken_at, reason)


def test_a_rewritten_or_cut_chain_is_caught_by_a_checkpoint_kept_elsewhere(job_store):
    log = chain(job_store[0])
    head = log.verify()["head"]
    # Rewriting every entry from the second on keeps the chain consistent ...
    for seq in (2, 3, 4):
        previous = next(e["hash"] for e in log.entries() if e["seq"] == seq - 1)
        rewrite(log, seq, lambda e: e.update(prev=previous, actor="someone-else"), rehash=True)
    assert log.verify()["ok"]
    # ... but not with the head the operator copied out before.
    assert log.verify((head["seq"], head["hash"]))["reason"] == "checkpoint_mismatch"
    sql(log, delete(log.table).where(log.table.c.seq == 4))
    assert log.verify((head["seq"], head["hash"]))["reason"] == "checkpoint_missing"


def test_writers_in_two_processes_never_fork_the_chain(job_store):
    db = job_store[0]
    other = Store(str(db.engine.url))   # its own engine and lock, as the offline L2 import has
    errors = []

    def write(store, who):
        try:
            for i in range(15):
                AuditLog(store).append(who, "test.append", f"{who}-{i}")
        except Exception as exc:   # surfaced below
            errors.append(exc)
    threads = [threading.Thread(target=write, args=(store, who)) for store, who in ((db, "orchestrator"), (other, "l2-import"))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors and AuditLog(db).verify()["entries"] == 30 and AuditLog(db).verify()["ok"]


def test_the_command_verifies_and_shows_the_head(job_store, monkeypatch, capsys):
    db = job_store[0]
    monkeypatch.setenv("DATABASE_URL", str(db.engine.url))
    log = chain(db, 2)
    head = log.verify()["head"]
    assert audit.main(["head"]) == 0 and json.loads(capsys.readouterr().out) == head
    assert audit.main(["verify", "--checkpoint", f'{head["seq"]}:{head["hash"]}']) == 0
    capsys.readouterr()
    rewrite(log, 1, lambda e: e.update(action="job.rejected"))
    assert audit.main(["verify"]) == 1 and json.loads(capsys.readouterr().out)["reason"] == "hash_mismatch"


def test_human_decisions_are_recorded_by_the_backend_identity(api):
    client, db, j = api
    decision = ready(db, j)
    assert client.post(f'/v1/jobs/{j["id"]}/approval', headers=headers("reviewer"), json={**decision, "comment": "tanık ve testler yeterli"}).status_code == 200
    assert client.post(f'/v1/jobs/{j["id"]}/cancel', headers=headers("developer")).status_code == 200
    entries = AuditLog(db).entries(j["id"])
    assert [(e["actor"], e["action"]) for e in entries] == [("reviewer", "job.approved"), ("developer", "job.cancelled")]
    approved = entries[0]["data"]
    candidate = db.get(j["id"])["candidate"]
    assert approved == {"candidate_commit": candidate["commit"], "artifact_sha256": candidate["artifact_sha256"],
                        "evidence_sha256": candidate["evidence_sha256"], "policy_version": POLICY, "comment": "tanık ve testler yeterli"}
    assert AuditLog(db).verify()["ok"]


def test_a_refused_request_leaves_no_decision_in_the_log(api):
    client, db, j = api
    decision = ready(db, j)
    assert client.post(f'/v1/jobs/{j["id"]}/approval', headers=headers("reviewer"), json={**decision, "artifact_sha256": "f" * 64}).status_code == 409
    assert AuditLog(db).entries(j["id"]) == []


def test_the_engine_records_its_verdict_with_digests_not_code(job_store):
    db, j = job_store
    engine = Engine(db)
    engine.set(j["id"], "scanning")
    engine.set(j["id"], "awaiting_review", candidate={"evidence_sha256": "e" * 64, "commit": "a" * 40, "artifact_sha256": "b" * 64,
                                                       "patch_sha256": "c" * 64, "diff": "+secret line", "origin": "model", "author": None})
    entries = AuditLog(db).entries(j["id"])
    assert [(e["actor"], e["action"]) for e in entries] == [("safepatch", "job.awaiting_review")]
    assert "diff" not in entries[0]["data"] and entries[0]["data"]["evidence_sha256"] == "e" * 64
    db.mutate(j["id"], lambda x: x.update(status="cancelled"))
    engine.set(j["id"], "needs_human", reason="attempt_budget_exhausted")
    assert len(AuditLog(db).entries(j["id"])) == 1   # a cancelled job's late verdict changes nothing and is not recorded
