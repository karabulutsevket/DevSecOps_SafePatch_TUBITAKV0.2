"""Fail before publication if secrets/runtime files or broken local doc links slip in."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

root=Path(__file__).resolve().parents[1]
names=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard'],cwd=root,text=True).splitlines()
names=sorted(set(names))
problems=[]
secret_values=[p.read_bytes().strip() for p in (root/'.secrets').glob('*') if p.is_file() and p.suffix!='.json']
for name in names:
    file=root/name
    if not file.is_file():continue
    if any(p in ('.runtime','.secrets','.venv','node_modules','.presentation-build') for p in file.relative_to(root).parts):
        problems.append(name+': private directory')
    if file.suffix in ('.db','.jar') or name=='.env':problems.append(name+': private/binary runtime artifact')
    data=file.read_bytes()
    if any(len(v)>=32 and v in data for v in secret_values):problems.append(name+': actual local secret found')
    if re.search(rb'(?:ghp_|github_pat_|sk-proj-)[A-Za-z0-9_]{25,}',data):problems.append(name+': credential-shaped text')
    if name.endswith('.md'):
        content=data.decode('utf-8')
        for link in re.findall(r'\[[^\]]*\]\(([^)]+)\)',content):
            if link.startswith(('http:','https:','#','mailto:')):continue
            target=(file.parent/link.split('#')[0]).resolve()
            if not target.exists():problems.append(name+': broken link '+link)
raw=json.loads((root/'evidence/raw-manifest.json').read_text(encoding='utf-8'))
for item in raw:
    if hashlib.sha256((root/item['path']).read_bytes()).hexdigest()!=item['sha256']:
        problems.append(item['path']+': raw evidence hash mismatch')
    if '--staged' in sys.argv:
        staged=subprocess.check_output(['git','show',':'+item['path']],cwd=root)
        if hashlib.sha256(staged).hexdigest()!=item['sha256']:
            problems.append(item['path']+': staged evidence hash mismatch')
result={'passed':not problems,'checked_files':len(names),'checked_raw_files':len(raw),'staged_hashes_checked':'--staged' in sys.argv,'problems':problems,'checks':['excluded directories','actual generated secret bytes','credential patterns','Markdown local links','raw evidence SHA-256'],
        'scope':'Publication hygiene, not a complete secret scanner or application security audit'}
(root/'evidence/publication-check.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps(result))
if problems:raise SystemExit(1)
