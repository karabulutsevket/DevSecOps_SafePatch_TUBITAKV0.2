"""Prepare the Docker sandbox (ROADMAP.md weeks 5–6) and prove its isolation.

1. Pulls the pinned Maven images (JDK 17 and JDK 8) if missing (internet, once; ~233 and
   ~150 MB compressed).
2. Copies the offline Maven cache (MAVEN_CACHE) into the WSL file system, where a build
   is ~8x faster than over /mnt/c, and mounts it read-only in every container. The copy adds
   to what is there: dependencies prefetched for evaluation cases (prepare_vul4j.py) stay.
3. Starts a sandboxed container and requires: no network, read-only cache, read-only root.
Prints the runner settings. Docker must run in WSL (`service docker start`).
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from safepatch.common import setting
from safepatch.runner import SANDBOX_IMAGES, sandbox_image, sandboxed, wsl, wsl_path

PROBE = ("exec 3<>/dev/tcp/1.1.1.1/53 2>/dev/null && echo NETWORK_OPEN || echo NETWORK_BLOCKED; "
         "touch /m2/probe 2>/dev/null && echo CACHE_WRITABLE || echo CACHE_READONLY; "
         "touch /etc/probe 2>/dev/null && echo ROOT_WRITABLE || echo ROOT_READONLY; "
         "touch /workspace/probe && echo WORKSPACE_WRITABLE || echo WORKSPACE_READONLY")


def check(*argv):
    return subprocess.run(wsl(*argv), capture_output=True, text=True, timeout=900)


def main():
    cache = setting("MAVEN_CACHE")
    if not cache or not Path(cache).is_dir():
        raise SystemExit("Set MAVEN_CACHE to the prepared offline Maven cache (docs/KURULUM_V02.md, section 3)")
    for image in map(sandbox_image, SANDBOX_IMAGES):
        if check("docker", "image", "inspect", image).returncode:
            print("pulling", image, flush=True)
            if check("docker", "pull", "-q", image).returncode:
                raise SystemExit("docker pull failed; is Docker running in WSL (service docker start)?")
    home = check("sh", "-c", 'printf %s "$HOME"').stdout.strip()
    target = setting("SANDBOX_MAVEN_CACHE") or home + "/.safepatch/m2"
    copied = check("sh", "-c", f'mkdir -p "{target}" && cp -r "{wsl_path(cache)}/." "{target}/" && du -sh "{target}"')
    if copied.returncode:
        raise SystemExit("copying the Maven cache into WSL failed: " + copied.stderr[-300:])
    os.environ["SANDBOX_MAVEN_CACHE"] = target
    with tempfile.TemporaryDirectory(dir=ROOT / ".runtime") as workspace:
        result = subprocess.run(sandboxed(["bash", "-c", PROBE], Path(workspace), "safepatch-probe-" + uuid.uuid4().hex[:8]),
                                capture_output=True, text=True, timeout=300)
    seen = set(result.stdout.split()) & {f"{k}_{v}" for k in ("NETWORK", "CACHE", "ROOT", "WORKSPACE") for v in ("OPEN", "BLOCKED", "READONLY", "WRITABLE")}
    expected = {"NETWORK_BLOCKED", "CACHE_READONLY", "ROOT_READONLY", "WORKSPACE_WRITABLE"}
    if not expected <= seen:
        raise SystemExit(f"isolation probe failed: {sorted(seen)} (expected {sorted(expected)})")
    print("cache:", copied.stdout.strip())
    print("isolation:", ", ".join(sorted(seen)))
    print("runner settings:")
    print("  $env:RUNNER_SANDBOX = 'docker'")
    print(f"  $env:SANDBOX_MAVEN_CACHE = '{target}'")


if __name__ == "__main__":
    main()
