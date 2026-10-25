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


def test_new_jobs_default_to_measured_retry_strategy(api):
    client,db,job=api
    create=lambda **extra: client.post('/v1/jobs',headers=headers('developer'),json={'case_id':'sql-01','idempotency_key':uuid.uuid4().hex,**extra})
    default=create()
    assert default.status_code==201 and default.json()['strategy']=='guided+context'
    assert create(strategy='v01').json()['strategy']=='v01'
    assert create(strategy='bogus').status_code==422


def test_naive_retrieval_is_not_public_job_option(api):
    client,db,job=api
    response=client.post('/v1/jobs',headers=headers('developer'),json={'case_id':'sql-01','idempotency_key':uuid.uuid4().hex,'memory_mode':'naive'})
    assert response.status_code==422


def test_jobs_need_a_registered_project_id(api):
    client,db,job=api
    create=lambda case: client.post('/v1/jobs',headers=headers('developer'),json={'case_id':case,'idempotency_key':uuid.uuid4().hex})
    assert create('not-registered').status_code==404
    assert create('Has Space').status_code==422


def test_known_finding_jobs_only_in_lab_and_evaluation_profiles(api, tmp_path, monkeypatch):
    import yaml
    from safepatch.repository import projects_dir
    client,db,job=api
    create=lambda case: client.post('/v1/jobs',headers=headers('developer'),json={'case_id':case,'scanner':'known','idempotency_key':uuid.uuid4().hex})
    monkeypatch.delenv('SAFEPATCH_PROFILE',raising=False)
    assert create('sql-01').json()['detail']=='known_findings_only_in_lab_profile'
    monkeypatch.setenv('SAFEPATCH_PROFILE','evaluation')
    assert create('sql-01').json()['detail']=='known_findings_need_answer_key_and_witness'
    assert 'known_findings' not in client.get('/v1/cases',headers=headers('developer')).json()['sql-01']
    # A case with an answer key (as prepare_vul4j.py writes for VUL4J-79) is listed and accepted.
    folder=tmp_path/'projects'; folder.mkdir()
    data=yaml.safe_load((projects_dir()/'sql-01.yml').read_text(encoding='utf-8'))
    data['scan']['known']=[{'id':'K-1','file':data['editable'][0],'line':1,'cwe':'CWE-89','source':'test answer key'}]
    (folder/'sql-01.yml').write_text(yaml.safe_dump(data),encoding='utf-8')
    monkeypatch.setenv('PROJECTS_DIR',str(folder))
    assert client.get('/v1/cases',headers=headers('developer')).json()['sql-01']['known_findings']==1
    created=create('sql-01')
    assert created.status_code==201 and created.json()['scanner']=='known'
    monkeypatch.setenv('SAFEPATCH_PROFILE','product')
    assert create('sql-01').status_code==409
