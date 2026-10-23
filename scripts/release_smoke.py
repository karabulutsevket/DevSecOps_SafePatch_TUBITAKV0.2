"""New-runtime E2E: real inference and workers, in-process HTTP control API.

All humans are explicitly SIMULATED and the database/users are test-only.
No real deployment or operational-memory promotion occurs.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import sys
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from fastapi.testclient import TestClient
from safepatch import orchestrator
from safepatch.common import digest
from safepatch.engine import Engine
from safepatch.store import Store

parser=argparse.ArgumentParser();parser.add_argument('--port-base',type=int,default=8100);args=parser.parse_args()
for service,offset in [('WORKER1',1),('WORKER2',2)]:
    os.environ[service+'_URL']=f'http://127.0.0.1:{args.port_base+offset}'
    os.environ[service+'_TOKEN_FILE']=str(ROOT/'.secrets'/(service.lower()+'_token'))
folder=ROOT/'.runtime'/('release-'+uuid.uuid4().hex);folder.mkdir(parents=True)
tokens={role:secrets.token_hex(32) for role in ('developer','reviewer','deployer')}
users=[{'subject':'SIMULATED-'+role,'roles':[permission],'token_sha256':digest(tokens[role]),'projects':['owned-java-demo']} for role,permission in [('developer','submit'),('reviewer','review'),('deployer','deploy')]]
(folder/'users.json').write_text(json.dumps(users),encoding='utf-8')
os.environ['USERS_FILE']=str(folder/'users.json')
orchestrator.store=Store('sqlite:///'+str(folder/'jobs.db'))
client=TestClient(orchestrator.app)
def api(method,path,role='developer',body=None):
    result=client.request(method,path,headers={'Authorization':'Bearer '+tokens[role]},json=body)
    if result.status_code>=400:raise RuntimeError(f'{method} {path} failed {result.status_code}: {result.text[:180]}')
    return result.json()
def job(mode):
    j=api('POST','/v1/jobs',body={'case_id':'sql-01','scanner':'semgrep','memory_mode':mode,'max_attempts':2,'idempotency_key':uuid.uuid4().hex})
    start=time.perf_counter();Engine(orchestrator.store).run(j['id'])
    j=api('GET','/v1/jobs/'+j['id']);j['wall_seconds']=round(time.perf_counter()-start,3)
    assert j['status']=='awaiting_review',j.get('reason')
    return j
first=job('off');c=first['candidate']
assert client.post('/v1/jobs/'+first['id']+'/approval',headers={'Authorization':'Bearer '+tokens['developer']},json={'candidate_commit':c['commit'],'artifact_sha256':c['artifact_sha256'],'policy_version':c['policy_version'],'decision':'approve'}).status_code==403
api('POST','/v1/jobs/'+first['id']+'/approval','reviewer',{'candidate_commit':c['commit'],'artifact_sha256':c['artifact_sha256'],'policy_version':c['policy_version'],'decision':'approve','comment':'SIMULATED release smoke approval only'})
memory=api('POST','/v1/memory/promote','reviewer',{'job_id':first['id'],'reason':'SIMULATED release-only memory promotion'})
second=job('guarded')
assert second['attempts'][0]['proposal']['mode']=='approved-memory-replay'
assert second['attempts'][0]['verification']['passed']
api('POST','/v1/memory/'+memory['id']+'/state','reviewer',{'state':'revoked','reason':'SIMULATED revocation during release acceptance test'})
revoked=api('GET','/v1/jobs/'+second['id'])
assert revoked['status']=='needs_human' and revoked['approval'] is None
result={'passed':True,'scope':'real local LLM + HTTP workers + real Java/Semgrep + in-process control API; isolated test DB/users',
        'human_approval':'SIMULATED ONLY','deployment':'not attempted','first':first,'replay':second,'after_revocation':revoked['status'],
        'first_seconds':first['wall_seconds'],'replay_seconds':second['wall_seconds']}
(ROOT/'evidence/release-smoke.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps({k:v for k,v in result.items() if k not in ('first','replay')}),flush=True)
