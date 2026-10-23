#!/bin/sh
# Rebuild launcher paths from existing packages/cache after moving this workspace.
set -eu
cd "$(dirname "$0")/.."
export UV_CACHE_DIR="$PWD/.runtime/uv-cache"
export UV_PYTHON_INSTALL_DIR="$PWD/.runtime/python-linux"
export UV_PYTHON_DOWNLOADS=never
export SEMGREP_SEND_METRICS=off
export SEMGREP_ENABLE_VERSION_CHECK=0
export SEMGREP_SETTINGS_FILE="$PWD/.runtime/semgrep-settings.yml"
python="$PWD/.runtime/python-linux/cpython-3.12.11-linux-x86_64-gnu/bin/python3.12"
uv="$PWD/.runtime/uv/uv"
test -x "$python" && test -x "$uv"
# Preserve installed versions before uv refreshes the environment metadata.
"$python" - <<'PY'
from pathlib import Path
from importlib.metadata import distributions
import json, shutil, time
root=Path.cwd()
venv=root/'.runtime/semgrep-venv'
backup=root/'.runtime'/('semgrep-launchers-before-repair-'+str(time.time_ns()))
backup.mkdir()
for name in ('bin','pyvenv.cfg'):
    source=venv/name
    if source.is_dir():
        shutil.copytree(source,backup/name,symlinks=True)
    elif source.is_file():
        shutil.copy2(source,backup/name)
packages=sorted({d.metadata['Name']+'=='+d.version for d in distributions(path=[str(venv/'lib/python3.12/site-packages')])})
if not any(p.lower()=='semgrep==1.136.0' for p in packages):
    raise SystemExit('Expected installed Semgrep 1.136.0; use prepare-semgrep.sh for first installation.')
(root/'.runtime/semgrep-installed.txt').write_text('\n'.join(packages)+'\n')
print('Saved launcher backup:',backup)
PY
"$uv" venv --offline --allow-existing --relocatable --python "$python" .runtime/semgrep-venv
# Keep the installed package files and regenerate their console launchers.
# This avoids downloading wheels when a copied uv cache lacks registry metadata.
.runtime/semgrep-venv/bin/python - <<'PY'
from pathlib import Path
from importlib.metadata import distributions
import re
venv=Path('.runtime/semgrep-venv')
count=0
for dist in distributions(path=[str(venv/'lib/python3.12/site-packages')]):
    for entry in dist.entry_points:
        if entry.group!='console_scripts':
            continue
        if not re.fullmatch(r'[A-Za-z0-9_.-]+',entry.name) or entry.name in ('.','..'):
            raise SystemExit('Invalid console script name')
        module,separator,function=entry.value.partition(':')
        if not separator:
            raise SystemExit('Unsupported console script entry point')
        function=function.split('[')[0].strip()
        lines=['#!/bin/sh', '""":"', 'exec "$(dirname "$0")/python" "$0" "$@"', '":"""',
               'import sys', 'from importlib import import_module',
               'target = import_module('+repr(module.strip())+')',
               'for part in '+repr(function.split('.'))+':',
               '    target = getattr(target, part)',
               'if __name__ == "__main__":', '    sys.exit(target())', '']
        file=venv/'bin'/entry.name
        file.write_text('\n'.join(lines),encoding='utf-8')
        file.chmod(0o755)
        count+=1
print('Rebuilt portable console launchers:',count)
PY
"$uv" pip check --python .runtime/semgrep-venv/bin/python
.runtime/semgrep-venv/bin/semgrep --version
