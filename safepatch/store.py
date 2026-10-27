import copy
import threading
import time

from sqlalchemy import Column, Float, JSON, MetaData, String, Table, create_engine, select, update

from safepatch.common import canonical, runtime, setting


class Store:
    """Single orchestrator, durable DB queue. SQLite native / PostgreSQL Compose."""
    def __init__(self, url=None):
        self.engine = create_engine(url or setting("DATABASE_URL", "sqlite:///" + str(runtime() / "jobs.db")), connect_args={"check_same_thread": False} if (url or setting("DATABASE_URL", "sqlite:")).startswith("sqlite:") else {})
        meta = MetaData()
        self.jobs = Table("jobs", meta, Column("id", String(32), primary_key=True), Column("idempotency", String(160), unique=True), Column("created", Float), Column("data", JSON, nullable=False))
        meta.create_all(self.engine)
        self.lock = threading.RLock()

    def create(self, data, idempotency):
        with self.lock, self.engine.begin() as conn:
            row = conn.execute(select(self.jobs.c.data).where(self.jobs.c.idempotency == idempotency)).first()
            if row:
                if any(row[0].get(key) != data.get(key) for key in ("case_id", "scanner", "max_attempts", "second_review", "memory_mode", "project")):
                    raise ValueError("idempotency_payload_conflict")
                return row[0], False
            conn.execute(self.jobs.insert().values(id=data["id"], idempotency=idempotency, created=time.time(), data=data))
            return data, True

    def get(self, job_id):
        with self.engine.connect() as conn:
            row = conn.execute(select(self.jobs.c.data).where(self.jobs.c.id == job_id)).first()
            if row is None:
                raise KeyError(job_id)
            return row[0]

    def all(self):
        with self.engine.connect() as conn:
            return [row[0] for row in conn.execute(select(self.jobs.c.data).order_by(self.jobs.c.created.desc()))]

    def mutate(self, job_id, fn):
        with self.lock, self.engine.begin() as conn:
            row = conn.execute(select(self.jobs.c.data).where(self.jobs.c.id == job_id)).first()
            if row is None:
                raise KeyError(job_id)
            data = copy.deepcopy(row[0])
            fn(data)
            conn.execute(update(self.jobs).where(self.jobs.c.id == job_id).values(data=data))
            return data
