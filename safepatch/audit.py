"""Append-only audit log with a hash chain (ROADMAP week 10; docs/DENETIM_KAYDI.md).

One entry per decision that matters for trust: who did what to which job, memory record or package,
with digests rather than code. Each entry carries the hash of the one before it, so changing,
removing or reordering an entry breaks the chain from that point on, and `verify` names the first
break. Someone who controls the database can still rewrite the whole chain: the head
(`python -m safepatch.audit head`) is meant to be copied to storage the operator keeps apart, and
`verify --checkpoint SEQ:HASH` checks that the chain still holds that entry unchanged.
"""
import argparse
import json
import sys
import time

from sqlalchemy import Column, Integer, MetaData, String, Table, Text, select
from sqlalchemy.exc import IntegrityError, OperationalError

from safepatch.common import canonical, digest

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, store):
        self.store = store
        meta = MetaData()
        # The entry is stored as the exact canonical text that was hashed; subject is only an index.
        self.table = Table("audit", meta, Column("seq", Integer, primary_key=True, autoincrement=False),
                           Column("subject", String(64), index=True), Column("entry", Text, nullable=False),
                           Column("hash", String(64), nullable=False))
        try:
            meta.create_all(store.engine)
        except OperationalError:
            meta.create_all(store.engine)   # another process created it between the check and the create

    def append(self, actor, action, subject, **data):
        with self.store.lock:
            for attempt in range(10):
                try:
                    with self.store.engine.begin() as conn:
                        last = conn.execute(select(self.table.c.seq, self.table.c.hash).order_by(self.table.c.seq.desc()).limit(1)).first()
                        seq, prev = (last[0] + 1, last[1]) if last else (1, GENESIS)
                        entry = canonical({"seq": seq, "at": time.time(), "actor": actor, "action": action,
                                           "subject": subject, "data": data, "prev": prev})
                        conn.execute(self.table.insert().values(seq=seq, subject=subject, entry=entry, hash=digest(entry)))
                    return {**json.loads(entry), "hash": digest(entry)}
                except (IntegrityError, OperationalError):
                    # Another process (the offline L2 import) took this number or the write lock
                    # first: chain on its entry instead. The number is the primary key, so the
                    # chain can never fork.
                    if attempt == 9:
                        raise
                    time.sleep(0.05 * (attempt + 1))

    def entries(self, subject=None):
        query = select(self.table.c.entry, self.table.c.hash).order_by(self.table.c.seq)
        if subject is not None:
            query = query.where(self.table.c.subject == subject)
        with self.store.engine.connect() as conn:
            return [{**json.loads(entry), "hash": stored} for entry, stored in conn.execute(query)]

    def verify(self, checkpoint=None):
        """Walk the chain from its first entry; the first entry that does not fit is reported.
        A checkpoint (seq, hash) taken earlier must still be in the chain, unchanged."""
        prev, count, matched = GENESIS, 0, None
        with self.store.engine.connect() as conn:
            rows = conn.execute(select(self.table.c.seq, self.table.c.subject, self.table.c.entry, self.table.c.hash).order_by(self.table.c.seq))
            for seq, subject, text, stored in rows:
                try:
                    entry = json.loads(text)
                except ValueError:
                    entry = {}
                problem = ("entry_unreadable" if not isinstance(entry, dict) or not entry else
                           "sequence_gap" if seq != count + 1 or entry.get("seq") != seq else
                           "hash_mismatch" if digest(text) != stored else
                           "chain_broken" if entry.get("prev") != prev else
                           "subject_mismatch" if entry.get("subject") != subject else None)
                if problem:
                    return {"ok": False, "entries": count, "broken_at": seq, "reason": problem}
                if checkpoint and seq == checkpoint[0]:
                    matched = stored == checkpoint[1]
                prev, count = stored, seq
        result = {"ok": True, "entries": count, "head": {"seq": count, "hash": prev}}
        if checkpoint and not matched:
            reason = "checkpoint_missing" if matched is None else "checkpoint_mismatch"
            return {**result, "ok": False, "broken_at": checkpoint[0], "reason": reason}
        return result


def checkpoint(text):
    seq, _, value = text.partition(":")
    if not seq.isdigit() or len(value) != 64:
        raise argparse.ArgumentTypeError("SEQ:HASH bekleniyor")
    return int(seq), value


def main(argv=None):
    from safepatch.store import Store
    parser = argparse.ArgumentParser(description="Denetim kaydı: hash zincirini doğrula, zincirin başını göster")
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("verify").add_argument("--checkpoint", type=checkpoint, help="daha önce saklanan baş: SEQ:HASH")
    sub.add_parser("head")
    args = parser.parse_args(argv)
    result = AuditLog(Store()).verify(args.checkpoint if args.action == "verify" else None)
    print(json.dumps(result if args.action == "verify" else result.get("head", result), indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
