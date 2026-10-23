import json
import time
import uuid

from conftest import headers
from safepatch.common import digest
from safepatch.store import Store


def test_other_project_is_not_listed_or_accessible(api, tmp_path, monkeypatch):
    client, db, job=api
    file=tmp_path/'foreign-users.json'
    file.write_text(json.dumps([{'subject':'reviewer','roles':['review'],'projects':['different-customer'],'token_sha256':digest('reviewer-secret')}]))
    monkeypatch.setenv('USERS_FILE',str(file))
    assert client.get('/v1/jobs',headers=headers('reviewer')).json()==[]
    assert client.get('/v1/cases',headers=headers('reviewer')).json()=={}
    assert client.get('/v1/jobs/'+job['id'],headers=headers('reviewer')).status_code==404
    assert client.get('/v1/memory',headers=headers('reviewer')).json()==[]


def test_idempotency_payload_conflict_is_detected(job_store):
    import pytest
    db, job=job_store
    with pytest.raises(ValueError,match='idempotency'):
        db.create({**job,'memory_mode':'off'},'test-key')


def test_job_is_durable_after_store_reopen(job_store):
    db,job=job_store
    db.mutate(job['id'],lambda j:j.update(status='needs_human',reason='test-persisted'))
    other=Store(str(db.engine.url))
    assert other.get(job['id'])['reason']=='test-persisted'


def test_naive_retrieval_is_not_public_job_option(api):
    client,db,job=api
    response=client.post('/v1/jobs',headers=headers('developer'),json={'case_id':'sql-01','idempotency_key':uuid.uuid4().hex,'memory_mode':'naive'})
    assert response.status_code==422
