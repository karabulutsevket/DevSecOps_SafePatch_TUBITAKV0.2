"""Compare acceptance gates on exactly the same real Java candidate pool."""
import json
import os
from pathlib import Path
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT/'tests')]
from safepatch.common import SOURCE, Patch, VerifyRequest, digest
from safepatch.repository import baseline, registry
from safepatch.runner import execute
from mock_patches import correct_patch


def main():
    directory = ROOT/'evidence/acceptance'
    directory.mkdir(parents=True, exist_ok=True)
    rows = []
    for kind in ('sql','path','command'):
        case_id = kind+'-01'
        case, files = baseline(case_id, registry()[1][case_id]['commit'])
        references = {'reference_fix': correct_patch(kind, files)}
        # These remove the vulnerable sink but also destroy the useful function.
        for name, expression in [('disabled_function', '""'), ('constant_response', '"alice"')]:
            content = 'package demo;\npublic class DemoService {\n public String lookup(String input) throws Exception { return '+expression+'; }\n}\n'
            references[name] = Patch(edits=[{'path':SOURCE,'old_sha256':digest(files[SOURCE]),'content':content}],rationale='Deliberate negative-control candidate; not model generated')
        for name, patch in references.items():
            result = execute(VerifyRequest(job_id=uuid.uuid4().hex, case_id=case_id, base_commit=case['commit'], attempt=1, deadline=time.time()+300, scanner='semgrep', patch=patch))
            result.pop('artifact_b64', None)
            scanner_clean = bool(result.get('scans')) and all(s['status']=='ok' and not s['findings'] for s in result['scans'])
            row = {'case':case_id,'candidate':name,'expected_acceptable':name=='reference_fix',
                   'V0_scanner_only':scanner_clean,'V1_build_and_scanner':bool(result['build']['passed'] and scanner_clean),
                   'V2_full_acceptance':result['passed'],'seconds':result.get('duration_seconds'),
                   'result':result, 'origin':'hand-authored deterministic control; not LLM'}
            rows.append(row)
            (directory/(case_id+'-'+name+'.json')).write_text(json.dumps(row,indent=2),encoding='utf-8')
            print(json.dumps({k:v for k,v in row.items() if k!='result'}),flush=True)
    summary={'n':len(rows),'scope':'Three owned synthetic families; same candidate pool across gates; no population-level correctness claim', 'gates':{}}
    for gate in ('V0_scanner_only','V1_build_and_scanner','V2_full_acceptance'):
        summary['gates'][gate]={'false_accepts':sum(r[gate] and not r['expected_acceptable'] for r in rows),
          'bad_candidates':sum(not r['expected_acceptable'] for r in rows),
          'true_accepts':sum(r[gate] and r['expected_acceptable'] for r in rows),
          'good_candidates':sum(r['expected_acceptable'] for r in rows)}
    (directory/'summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    print(json.dumps(summary),flush=True)

if __name__=='__main__': main()
