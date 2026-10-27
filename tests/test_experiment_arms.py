"""Arm B of the main experiment (docs/DENEY_PROTOKOLU.md): memory chosen by embedding similarity alone."""
import uuid

from fastapi import HTTPException
import pytest

from test_memory import approved_record
from safepatch import worker1
from safepatch.common import SOURCE
from safepatch.memory import Memory, cosine, original_code
from safepatch.worker1 import EMBED_MODEL, Embed


def fake_embed(table):
    """Vectors chosen by the text's first matching key: what each record is 'about'."""
    def embed(texts):
        return [next((v for k, v in table.items() if k in text), [0.0, 0.0, 1.0]) for text in texts]
    return embed


def shift(db, record, **context):
    from sqlalchemy import update
    table = Memory(db).table
    changed = {**record, "context": {**record["context"], **context}}
    with db.engine.begin() as conn:
        conn.execute(update(table).where(table.c.id == record["id"]).values(data=changed))
    return changed


def test_the_most_similar_record_of_the_family_is_an_example_in_any_project(job_store):
    db, job = job_store
    record = shift(db, approved_record(db, job), project="another-project")
    lookup = Memory(db).similar({**record["context"], "project": "this-project"}, "query", fake_embed({"query": [1.0, 0.0, 0.0]}))
    assert (lookup["use"], lookup["tier"], lookup["selected"]["id"]) == ("example", "L1", record["id"])
    [entry] = lookup["considered"]
    assert entry["rank"] == 1 and entry["same_shape"] is True and "project" in entry["differences"]


def test_similarity_orders_and_other_families_are_never_considered(job_store):
    db, job = job_store
    first = approved_record(db, job)
    second_job = {**job, "id": uuid.uuid4().hex}
    db.create(second_job, "second")
    second = approved_record(db, second_job)
    other = shift(db, second, cwe_family="CWE-22")
    query = first["context"]
    embed = lambda texts: [[1.0, 0.0]] + [[0.0, 1.0] for _ in texts[1:]]
    lookup = Memory(db).similar(query, "q", embed)
    assert [c["id"] for c in lookup["considered"]] == [first["id"]] and other["id"] != first["id"]
    # Among records of the family, the higher cosine wins whatever the rules would say.
    third_job = {**job, "id": uuid.uuid4().hex}
    db.create(third_job, "third")
    third = shift(db, approved_record(db, third_job), signature={**first["context"]["signature"], "construction": "format"})
    vectors = {first["id"]: [0.2, 1.0], third["id"]: [1.0, 0.1]}
    records = {r["id"]: r for r in Memory(db).all()}
    order = [r for r in Memory(db).all() if r["context"]["cwe_family"] == "CWE-89"]
    embed = lambda texts: [[1.0, 0.0]] + [vectors[r["id"]] for r in order]
    lookup = Memory(db).similar(query, "q", embed)
    assert lookup["selected"]["id"] == third["id"] and lookup["considered"][0]["same_shape"] is False
    assert records[third["id"]]["context"]["signature"]["construction"] == "format"


def test_an_empty_pool_is_no_match_without_an_embedding_call(job_store):
    db, _ = job_store
    lookup = Memory(db).similar({"project": "p", "cwe_family": "CWE-89"}, "q", lambda texts: pytest.fail("no call"))
    assert lookup["decision"] == "no_match" and lookup["selected"] is None


def test_documents_are_the_repairs_original_code_and_cosine_is_scale_free():
    diff = "--- a/A.java\n+++ b/A.java\n@@ -1,3 +1,3 @@\n keep\n-old\n+new\n"
    assert original_code(diff) == "keep\nold\n"
    assert cosine([1.0, 2.0], [2.0, 4.0]) == pytest.approx(1.0) and cosine([0.0, 0.0], [1.0, 0.0]) == 0.0


def test_arm_b_sends_the_example_and_never_replays_even_identical_code(job_store):
    from safepatch.engine import Engine
    db, job = job_store
    record = approved_record(db, job)
    fresh = {**db.get(job["id"]), "id": uuid.uuid4().hex, "status": "queued", "approval": None, "attempts": [], "max_attempts": 1,
             "memory_mode": "similar", "memory_ids": []}
    db.create(fresh, "arm-b")
    seen = {"embed": [], "propose": []}

    def call(url, *args, **kwargs):
        body = kwargs["body"]
        if url.endswith("/embed"):
            seen["embed"].append(body["texts"])
            return {"model": EMBED_MODEL[0], "model_digest": EMBED_MODEL[1], "embeddings": [[1.0, 0.0] for _ in body["texts"]]}
        if url.endswith("/propose"):
            seen["propose"].append(body)
            return {"mode": "mock-test", "patch": record["patch"]}
        if body["attempt"] == 0:
            return {"baseline_valid": True, "scans": [{"findings": [{"rule_id": "bigg.java.sql-concatenation", "file": SOURCE, "line": 16}]}]}
        return {"passed": False, "feedback": {"code": "security_regression"}}
    Engine(db, call).run(fresh["id"])
    stored = db.get(fresh["id"])
    lookup = stored["memory_lookup"]
    assert (lookup["use"], lookup["selected_id"], lookup["embedding"]["model_digest"]) == ("example", record["id"], EMBED_MODEL[1])
    assert seen["embed"][0][0].startswith("search_query: ") and seen["embed"][0][1].startswith("search_document: ")
    # The same source would be a replay under the rules of arm C; arm B only ever gives an example.
    assert len(seen["propose"]) == 1 and seen["propose"][0]["memory_data"]["patch_diff"] == record["diff"]
    assert stored["memory_ids"] == [record["id"]] and stored["attempts"][0]["proposal"]["mode"] == "mock-test"


@pytest.fixture
def ollama(monkeypatch):
    calls = []

    def request(url, method="GET", **kwargs):
        calls.append((url, kwargs.get("body")))
        if url.endswith("/api/tags"):
            return {"models": [{"name": EMBED_MODEL[0], "digest": calls_digest[0]}]}
        return {"embeddings": [[0.5] * 3 for _ in kwargs["body"]["input"]]}
    calls_digest = [EMBED_MODEL[1]]
    monkeypatch.setattr(worker1, "request", request)
    return calls, calls_digest


def test_the_embedding_model_is_pinned_and_texts_are_bounded(ollama):
    calls, pinned = ollama
    answer = worker1.embed(Embed(texts=["a", "b"], deadline=9e9))
    assert answer["model_digest"] == EMBED_MODEL[1] and len(answer["embeddings"]) == 2
    assert calls[-1][1]["model"] == EMBED_MODEL[0]
    with pytest.raises(HTTPException) as refused:
        worker1.embed(Embed(texts=["x" * 8001], deadline=9e9))
    assert refused.value.status_code == 422
    pinned[0] = "f" * 64
    with pytest.raises(HTTPException) as refused:
        worker1.embed(Embed(texts=["a"], deadline=9e9))
    assert refused.value.detail == "embedding_model_digest_mismatch"


def test_the_experiment_order_is_fixed_by_the_seed_and_shared_by_the_arms():
    import sys
    from pathlib import Path
    from types import SimpleNamespace
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    import main_experiment
    assert [main_experiment.arm_order(s) for s in (42, 43, 44)] == [["A", "B", "C", "C+L2"], ["B", "C", "C+L2", "A"], ["C", "C+L2", "A", "B"]]
    cases = [SimpleNamespace(id=f"case-{i:02}") for i in range(12)]
    first = [c.id for c in main_experiment.case_order(42, cases)]
    assert first == [c.id for c in main_experiment.case_order(42, list(reversed(cases)))] != [c.id for c in main_experiment.case_order(43, cases)]
    assert sorted(first) == [c.id for c in cases]
