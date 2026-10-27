"""Explicit allowlist: never package secrets, models, caches or private runtime data."""
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
folder = ROOT / "output"
folder.mkdir(exist_ok=True)
with zipfile.ZipFile(folder / "SafePatch_BiGG_Prototip.zip", "w", zipfile.ZIP_DEFLATED) as archive:
    files = []
    for name in ("safepatch", "scripts", "samples", "rules", "tests", "docs", "evidence", "presentation"):
        files.extend((ROOT / name).rglob("*"))
    files.extend(ROOT / name for name in ("README.md", "LICENSE", ".gitignore", ".gitattributes", ".dockerignore", ".env.example", "pyproject.toml", "requirements.in", "requirements.lock", "Dockerfile", "compose.yml", "compose.sonar.yml", "Jenkinsfile"))
    for file in files:
        if file.is_file() and "__pycache__" not in file.parts and file.suffix not in (".pyc", ".jar"):
            archive.write(file, file.relative_to(ROOT))
print(folder / "SafePatch_BiGG_Prototip.zip")
