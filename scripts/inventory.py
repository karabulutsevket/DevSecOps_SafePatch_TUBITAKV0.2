"""Export measured tools and installed Python packages without credentials."""
import importlib.metadata
import json
import platform
from pathlib import Path
import subprocess
import time

root=Path(__file__).resolve().parents[1]
def command(argv):
    try:
        r=subprocess.run(argv,capture_output=True,text=True,timeout=15)
        return {'exit_code':r.returncode,'text':(r.stdout+r.stderr).strip()[:2500]}
    except (OSError,subprocess.TimeoutExpired) as e:
        return {'unavailable':type(e).__name__}
data={'at':time.time(),'os':platform.platform(),'python':platform.python_version(),
      'java':command(['java','-version']), 'maven':command(['mvn.cmd' if platform.system()=='Windows' else 'mvn','-version']),
      'gpu':command(['nvidia-smi','--query-gpu=name,memory.total,driver_version','--format=csv,noheader']),
      'python_packages':sorted([{'name':d.metadata['Name'],'version':d.version,'license':d.metadata.get('License-Expression') or d.metadata.get('License','unspecified')[:100]} for d in importlib.metadata.distributions()],key=lambda d:d['name'].lower()),
      'note':'Measured environment inventory; not a vulnerability scan, complete SBOM or redistribution clearance.'}
(root/'evidence').mkdir(exist_ok=True)
(root/'evidence/environment.json').write_text(json.dumps(data,indent=2),encoding='utf-8')
print('Environment inventory written; no credentials collected.')
