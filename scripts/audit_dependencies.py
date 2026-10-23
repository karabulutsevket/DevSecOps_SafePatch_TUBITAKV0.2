"""Optional connected preparation audit of PUBLIC Python package names/versions.

Never called by the repair services. No source, prompts, secrets or customer
dependencies are uploaded. For offline use consume an approved local advisory DB.
"""
import argparse
import concurrent.futures
import json
from pathlib import Path
import re
import time
import urllib.request

root=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser()
parser.add_argument('--online',action='store_true')
args=parser.parse_args()
if not args.online:
    raise SystemExit('Explicit --online is required for the optional OSV preparation audit')
packages=[{'name':m[1],'version':m[2]} for line in (root/'requirements.lock').read_text().splitlines() if (m:=re.fullmatch(r'([A-Za-z0-9_.-]+)==([A-Za-z0-9.+-]+)',line.strip()))]
queries=[{'package':{'name':p['name'],'ecosystem':'PyPI'},'version':p['version']} for p in packages]
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
def read(url,body=None):
    req=urllib.request.Request(url,data=json.dumps(body).encode() if body else None,headers={'Content-Type':'application/json'})
    with opener.open(req,timeout=40) as response:return json.load(response)
result=read('https://api.osv.dev/v1/querybatch',{'queries':queries})
if len(result.get('results',[]))!=len(packages):raise RuntimeError('Incomplete OSV response')
rows=[{**p,'vulnerabilities':r.get('vulns',[])} for p,r in zip(packages,result['results'])]
ids=sorted({v['id'] for r in rows for v in r['vulnerabilities']})
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    details=list(pool.map(lambda i:read('https://api.osv.dev/v1/vulns/'+i),ids))
data={'at':time.time(),'source':'https://api.osv.dev/v1/querybatch','scope':'Declared Python lock only, not Java/images/models or proof of no vulnerabilities',
      'packages':rows,'advisories':details,'affected_packages':sum(bool(r['vulnerabilities']) for r in rows),
      'queried_packages':len(rows),'online_preparation_only':True}
(root/'evidence/dependency-audit.json').write_text(json.dumps(data,indent=2),encoding='utf-8')
print(json.dumps({'queried_packages':len(rows),'affected_packages':data['affected_packages'],'advisory_ids':ids}))
