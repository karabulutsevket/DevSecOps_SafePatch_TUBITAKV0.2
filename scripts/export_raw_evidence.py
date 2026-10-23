"""Collect only owned fixture test/scan evidence; never collect command logs."""
import hashlib
import json
from pathlib import Path
import shutil

root=Path(__file__).resolve().parents[1]
identifiers={p.stem for p in (root/'evidence/benchmark/jobs').glob('*.json')}
release=root/'evidence/release-smoke.json'
if release.exists():
    r=json.loads(release.read_text(encoding='utf-8'))
    identifiers.update(r[key]['id'] for key in ('first','replay'))
copied=[]
for workspace in (root/'.runtime/runner-work').iterdir():
    if workspace.name.split('-')[0] not in identifiers:continue
    for relative in ('semgrep.json','target/surefire-reports/TEST-demo.BehaviorTest.xml','target/surefire-reports/TEST-demo.SecurityTest.xml'):
        file=workspace/relative
        if not file.is_file():continue
        target=root/'evidence/raw'/workspace.name/file.name
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(file,target)
        copied.append({'path':target.relative_to(root).as_posix(),'sha256':hashlib.sha256(target.read_bytes()).hexdigest()})
(root/'evidence/raw-manifest.json').write_text(json.dumps(copied,indent=2),encoding='utf-8')
print(f'Collected {len(copied)} JUnit/scan files; no command logs or credentials.')
