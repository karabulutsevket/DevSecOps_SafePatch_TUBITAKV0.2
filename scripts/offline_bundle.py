"""Week 10: the offline installation bundle for a clean machine (docs/KURULUM_CEVRIMDISI.md).

Built once on a prepared machine with internet; scripts/offline_install.ps1 installs from it on
a clean Windows 11 machine with the network off and times every step. Downloads are pinned (URL
and, where the publisher gives one, SHA-256; approved by the lead on 30 Oct 2026); the rest is
copied from this machine. manifest.json lists every file with its size and SHA-256, build.json
how long each part took. The bundle holds no secret, token or customer code; it stays out of Git.

    python scripts/offline_bundle.py build [--out .runtime/offline-bundle]
    python scripts/offline_bundle.py verify [--out ...]
    python scripts/offline_bundle.py refresh [--out ...]   # new install script, new manifest
    EVIDENCE_DIR=evidence/v02-kurulum python scripts/offline_bundle.py record   # build.json and manifest.json as evidence
"""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PREPARED = Path(os.environ.get("SAFEPATCH_PREPARED", r"C:\DevSecOps_Tubitak\.runtime"))   # where this machine keeps the tools
DISTRO = os.environ.get("WSL_DISTRO", "Debian")
DOWNLOADS = {   # path in the bundle: (URL, SHA-256 published by the source or None)
    "windows/python-3.12.10-amd64.exe": ("https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe", None),
    "windows/Git-2.55.0.5-64-bit.exe": ("https://github.com/git-for-windows/git/releases/download/v2.55.0.windows.5/Git-2.55.0.5-64-bit.exe", None),
    "windows/amazon-corretto-17.0.20.10.1-windows-x64.msi": ("https://corretto.aws/downloads/resources/17.0.20.10.1/amazon-corretto-17.0.20.10.1-windows-x64.msi", None),
    "windows/apache-maven-3.9.16-bin.zip": ("https://archive.apache.org/dist/maven/maven-3/3.9.16/binaries/apache-maven-3.9.16-bin.zip", None),
    "windows/wsl.2.7.12.0.x64.msi": ("https://github.com/microsoft/WSL/releases/download/2.7.12/wsl.2.7.12.0.x64.msi", None),
    "linux/Debian_WSL_AMD64_v1.26.0.0.wsl": ("https://salsa.debian.org/debian/WSL/-/jobs/9606244/artifacts/raw/Debian_WSL_AMD64_v1.26.0.0.wsl",
                                             "5ec7dc68216e75d1d4d4761474e99d8461a98d316537110314b137122a879e0f"),   # Microsoft's DistributionInfo.json
}
OLLAMA_ZIP = ("ollama-0.34.0.zip", "a7dd1b174f39d3d1b8a25d4cbc86045d0e190b17187bfdcbe2f2ee3b5a11470e")   # as scripts/prepare-ollama.ps1
MODEL = ("qwen2.5-coder", "7b-instruct-q4_K_M")
SEMGREP = ("semgrep==1.136.0", "setuptools==80.9.0")
LINUX_PLATFORMS = ("manylinux_2_28_x86_64", "manylinux_2_17_x86_64", "manylinux2014_x86_64", "manylinux1_x86_64", "musllinux_1_0_x86_64")


def digest(path):
    h = sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def wsl_path(path):
    path = Path(path).resolve()
    return "/mnt/" + path.drive[0].lower() + path.as_posix()[2:]


def wsl(*argv, user=None, timeout=3600):
    command = ["wsl", "-d", DISTRO, *(["-u", user] if user else []), "--exec", *argv]
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise SystemExit(f"{argv[0]} in WSL failed: {(result.stderr or result.stdout)[-400:]}")
    return result.stdout


def download(url, target, expected=None):
    import httpx
    if target.exists() and (expected is None or digest(target) == expected):
        return "kept"
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_suffix(target.suffix + ".part")
    with httpx.stream("GET", url, follow_redirects=True, timeout=120) as answer:
        answer.raise_for_status()
        with open(partial, "wb") as f:
            for block in answer.iter_bytes(1 << 20):
                f.write(block)
    if expected and digest(partial) != expected:
        partial.unlink()
        raise SystemExit(f"checksum mismatch for {url}")
    partial.replace(target)
    return "downloaded"


def zip_tree(source, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(source).as_posix())
    return f"{target.stat().st_size / 1e6:.1f} MB"


def semgrep_pins():
    """The exact distributions of the Semgrep environment this machine scans with."""
    site = PREPARED / "semgrep-venv" / "lib" / "python3.12" / "site-packages"
    pins = sorted(p.name[:-len(".dist-info")].rpartition("-")[0] + "==" + p.name[:-len(".dist-info")].rpartition("-")[2]
                  for p in site.glob("*.dist-info"))
    if not pins:
        raise SystemExit(f"no Semgrep environment under {site}")
    return pins


def docker_closure():
    names = wsl("sh", "-c", "apt-cache depends --recurse --no-recommends --no-suggests --no-conflicts --no-breaks --no-replaces --no-enhances docker.io"
                            " | grep '^[a-z]' | sort -u")
    return names.split()


def build(out):
    out.mkdir(parents=True, exist_ok=True)
    timings, started = {}, time.time()

    def step(name, action):
        begun = time.time()
        result = action()
        timings[name] = {"seconds": round(time.time() - begun, 1), "result": result}
        print(f"{name}: {timings[name]}", flush=True)

    for path, (url, expected) in DOWNLOADS.items():
        step("download " + Path(path).name, lambda path=path, url=url, expected=expected: download(url, out / path, expected))
    for name, action in (("wheels windows", windows_wheels), ("wheels linux", linux_wheels), ("docker debs", docker_debs),
                         ("ollama zip", lambda out: copy_checked(PREPARED / OLLAMA_ZIP[0], out / "windows" / OLLAMA_ZIP[0], OLLAMA_ZIP[1])),
                         ("model", lambda out: copy_model(out / "models")),
                         ("maven cache", lambda out: zip_tree(Path(os.environ.get("MAVEN_CACHE", PREPARED / "m2")), out / "maven" / "m2.zip")),
                         ("spotbugs tools", lambda out: zip_tree(ROOT / ".runtime" / "tools", out / "tools" / "tools.zip")),
                         ("linux python", lambda out: wsl("tar", "-C", wsl_path(PREPARED), "-czf", wsl_path(out / "linux" / "python-linux.tar.gz"), "python-linux") or "ok"),
                         ("sandbox images", lambda out: save_images(out / "linux")), ("safepatch source", source_bundle)):
        step(name, lambda action=action: action(out))
    if (ROOT / "scripts" / "offline_install.ps1").exists():
        shutil.copy2(ROOT / "scripts" / "offline_install.ps1", out / "offline_install.ps1")
    step("manifest", lambda: write_manifest(out))
    (out / "build.json").write_text(json.dumps({"built_at": started, "seconds": round(time.time() - started, 1), "steps": timings,
                                                "safepatch_commit": subprocess.run(["git", "-C", str(ROOT), "rev-parse", "main"], capture_output=True, text=True).stdout.strip()},
                                               indent=2) + "\n", encoding="utf-8")


def pip_download(target, *args):
    subprocess.run([sys.executable, "-m", "pip", "download", "--disable-pip-version-check", "-q", "--only-binary=:all:", "--no-deps",
                    "-d", str(target), *args], check=True)
    return f"{len(list(target.glob('*.whl')))} wheels"


def windows_wheels(out):
    return pip_download(out / "wheels" / "windows", "-r", str(ROOT / "requirements.lock"))


def linux_wheels(out):
    platforms = [arg for p in LINUX_PLATFORMS for arg in ("--platform", p)]
    return pip_download(out / "wheels" / "linux", "--python-version", "3.12", "--implementation", "cp", *platforms, *semgrep_pins())


def docker_debs(out):
    """Docker and everything it depends on (the clean machine installs only what it lacks)."""
    debs = out / "linux" / "debs"
    debs.mkdir(parents=True, exist_ok=True)
    if any(debs.glob("*.deb")):   # a rebuild keeps what an earlier build fetched
        return f"{len(list(debs.glob('*.deb')))} packages (kept)"
    command = f'cd "{wsl_path(debs)}" && apt-get download -q {" ".join(docker_closure())}'
    try:
        wsl("sh", "-c", command)
    except SystemExit:   # stale package lists name versions the mirror no longer has
        wsl("apt-get", "update", "-q", user="root")
        wsl("sh", "-c", command)
    return f"{len(list(debs.glob('*.deb')))} packages"


def source_bundle(out):
    (out / "safepatch").mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "-C", str(ROOT), "bundle", "create", str(out / "safepatch" / "safepatch.bundle"), "main"], check=True, capture_output=True)
    return "main"


def copy_checked(source, target, expected):
    if digest(source) != expected:
        raise SystemExit(f"{source} does not match its pinned SHA-256")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    return "ok"


def copy_model(target):
    """The product's model only: its manifest and the blobs it names (the experiment's embedding model stays out)."""
    models = PREPARED / "models"
    manifest = models / "manifests" / "registry.ollama.ai" / "library" / MODEL[0] / MODEL[1]
    layers = json.loads(manifest.read_text(encoding="utf-8"))
    blobs = [layers["config"]["digest"]] + [layer["digest"] for layer in layers["layers"]]
    (target / manifest.relative_to(models)).parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(manifest, target / manifest.relative_to(models))
    (target / "blobs").mkdir(parents=True, exist_ok=True)
    for blob in blobs:
        name = blob.replace(":", "-")
        if not (target / "blobs" / name).exists():
            shutil.copy2(models / "blobs" / name, target / "blobs" / name)
    return f"{len(blobs)} blobs"


def save_images(target):
    """The sandbox images by image ID: `docker load` keeps the ID (a content digest), not the
    registry digest the runner pins, so the clean machine pins the same content by ID."""
    sys.path.insert(0, str(ROOT))
    from safepatch.runner import SANDBOX_IMAGES
    ids = {java: wsl("docker", "image", "inspect", image, "--format", "{{.Id}}").strip() for java, image in SANDBOX_IMAGES.items()}
    wsl("docker", "save", "-o", wsl_path(target / "sandbox-images.tar"), *ids.values())
    (target / "sandbox-images.json").write_text(json.dumps({"images": SANDBOX_IMAGES, "ids": ids}, indent=2) + "\n", encoding="utf-8")
    return ids


def write_manifest(out):
    files = sorted(p for p in out.rglob("*") if p.is_file() and p.name not in ("manifest.json", "build.json") and not p.name.endswith(".part"))
    entries = [{"path": p.relative_to(out).as_posix(), "bytes": p.stat().st_size, "sha256": digest(p)} for p in files]
    (out / "manifest.json").write_text(json.dumps({"files": entries, "total_bytes": sum(e["bytes"] for e in entries)}, indent=2) + "\n", encoding="utf-8")
    return f"{len(entries)} files, {sum(e['bytes'] for e in entries) / 1e9:.2f} GB"


def verify(out):
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    bad = [e["path"] for e in manifest["files"] if not (out / e["path"]).exists() or digest(out / e["path"]) != e["sha256"]]
    print(json.dumps({"files": len(manifest["files"]), "bad": bad}))
    return 1 if bad else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("action", choices=("build", "verify", "refresh", "record"))
    parser.add_argument("--out", type=Path, default=ROOT / ".runtime" / "offline-bundle")
    args = parser.parse_args(argv)
    if args.action == "refresh":
        shutil.copy2(ROOT / "scripts" / "offline_install.ps1", args.out / "offline_install.ps1")
        print(write_manifest(args.out))
        return 0
    if args.action == "record":
        sys.path.insert(0, str(ROOT))
        from safepatch.common import evidence
        target = evidence("paket")
        if (target / "build.json").exists():
            raise SystemExit("evidence is never overwritten; use a fresh EVIDENCE_DIR")
        target.mkdir(parents=True, exist_ok=True)
        for name in ("build.json", "manifest.json"):
            shutil.copy2(args.out / name, target / name)
        print("written:", target)
        return 0
    return build(args.out) if args.action == "build" else verify(args.out)


if __name__ == "__main__":
    raise SystemExit(main())
