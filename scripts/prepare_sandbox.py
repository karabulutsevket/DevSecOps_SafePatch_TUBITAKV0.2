"""Prepare the Docker sandbox (ROADMAP.md weeks 5–6) and prove its isolation.

1. Pulls the pinned Maven images (JDK 17 and JDK 8) if missing (internet, once; ~233 and
   ~150 MB compressed).
2. Copies the offline Maven cache (MAVEN_CACHE) into the WSL file system, where a build
   is ~8x faster than over /mnt/c, and mounts it read-only in every container. The copy adds
   to what is there: dependencies prefetched for evaluation cases (prepare_vul4j.py) stay.
3. Starts a sandboxed container and requires: no network, read-only cache, read-only root.
Prints the runner settings. Docker must run in WSL (`service docker start`).

`--bound-work-gb N` (week 8) puts the sandbox workspaces on their own N GB filesystem: an ext4
image under /var/lib/safepatch, loop-mounted over <home>/.safepatch/work and listed in
/etc/fstab (previous file kept as /etc/fstab.before-safepatch). It runs as root in WSL, once;
the runner refuses to stage a workspace anywhere else (`sandbox_work_not_bounded`). Without
it, a build could fill the Windows drive that holds the WSL disk.
"""
import argparse
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


BOUND_WORK = r"""
set -e
work="$1"; size="$2"; owner="$3"; image=/var/lib/safepatch/work.img
if mountpoint -q "$work"; then findmnt -n -o TARGET,SIZE "$work"; exit 0; fi
mkdir -p "$work" /var/lib/safepatch
if [ -n "$(ls -A "$work")" ]; then echo "$work is not empty" >&2; exit 3; fi
if [ ! -e "$image" ]; then
  truncate -s "${size}G" "$image"; chmod 600 "$image"
  mkfs.ext4 -q -F -m 0 -L safepatch-work -E root_owner="$owner" "$image"
fi
if ! grep -qF " $work " /etc/fstab; then
  cp /etc/fstab /etc/fstab.before-safepatch
  echo "$image $work ext4 loop,nosuid,nodev,nofail 0 0" >> /etc/fstab
  systemctl daemon-reload 2>/dev/null || true
fi
mount "$work"
findmnt -n -o TARGET,SIZE "$work"
"""


def bound_work(size_gb):
    """Mount the bounded work filesystem (root in WSL, idempotent); returns its mount line."""
    home = check("sh", "-c", 'printf %s "$HOME"').stdout.strip()
    cache = setting("SANDBOX_MAVEN_CACHE") or home + "/.safepatch/m2"
    work = setting("SANDBOX_WORK", cache.rstrip("/").rsplit("/", 1)[0] + "/work")
    owner = setting("SANDBOX_USER", "1000:1000")
    result = subprocess.run(["wsl", "-d", setting("WSL_DISTRO", "Debian"), "-u", "root", "--exec", "sh", "-c", BOUND_WORK, "sh", work, str(size_gb), owner],
                            capture_output=True, text=True, timeout=600)
    if result.returncode:
        raise SystemExit("bounded work filesystem failed: " + (result.stderr or result.stdout)[-300:])
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bound-work-gb", type=int, help="only set up the bounded work filesystem of this size (GB)")
    args = parser.parse_args()
    if args.bound_work_gb:
        print("work filesystem:", bound_work(args.bound_work_gb))
        return
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
