"""A real isolated-network probe, not an airgap certification or runner test."""
import json
import argparse
from pathlib import Path
import subprocess
import time

root=Path(__file__).resolve().parents[1]
# A new unprivileged network namespace has no default route. No remote data is
# sent: only an empty TCP connect is attempted to reserved TEST-NET address.
probe="""import json,socket,os
s=socket.socket(); s.settimeout(2)
try:
 s.connect(('192.0.2.1',443)); result={'connected':True}
except OSError as e:
 result={'connected':False,'errno':e.errno}
print(json.dumps({'probe':result,'routes':open('/proc/net/route').read(),'namespace':os.readlink('/proc/self/ns/net')}))
"""
parser=argparse.ArgumentParser()
parser.add_argument('--python',default='python3',help='Existing Linux Python executable; no installation occurs')
args=parser.parse_args()
result=subprocess.run(['wsl','-d','Debian','--','unshare','-Urn',args.python,'-c',probe],capture_output=True,text=True,timeout=15)
data={'test':'linux-network-namespace-probe','time':time.time(),'exit_code':result.returncode,
      'scope':'Probe process only. Maven, LLM and all-host airgap were NOT verified by this probe.',
      'result':json.loads(result.stdout) if result.returncode==0 else None,
      'passed':result.returncode==0 and not json.loads(result.stdout)['probe']['connected']}
out=root/'evidence/network-namespace.json';out.parent.mkdir(parents=True,exist_ok=True)
out.write_text(json.dumps(data,indent=2),encoding='utf-8')
print(json.dumps(data))
