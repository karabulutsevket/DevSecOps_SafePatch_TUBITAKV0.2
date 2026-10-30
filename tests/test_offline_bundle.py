import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import offline_bundle as bundle


def test_the_manifest_binds_every_file_and_verify_finds_a_changed_one(tmp_path, capsys):
    (tmp_path / "windows").mkdir()
    (tmp_path / "windows" / "a.msi").write_bytes(b"installer")
    (tmp_path / "wheels" / "linux").mkdir(parents=True)
    (tmp_path / "wheels" / "linux" / "b.whl").write_bytes(b"wheel")
    (tmp_path / "windows" / "c.zip.part").write_bytes(b"half")   # an interrupted download is not part of the bundle
    assert bundle.write_manifest(tmp_path).startswith("2 files")
    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    assert [e["path"] for e in manifest["files"]] == ["wheels/linux/b.whl", "windows/a.msi"] and manifest["total_bytes"] == 14
    assert bundle.verify(tmp_path) == 0
    (tmp_path / "windows" / "a.msi").write_bytes(b"tampered")
    assert bundle.verify(tmp_path) == 1 and "windows/a.msi" in capsys.readouterr().out


def test_the_semgrep_pins_are_the_installed_distributions(tmp_path, monkeypatch):
    site = tmp_path / "semgrep-venv" / "lib" / "python3.12" / "site-packages"
    for name in ("semgrep-1.136.0.dist-info", "charset_normalizer-3.5.1.dist-info", "semgrep"):
        (site / name).mkdir(parents=True)
    monkeypatch.setattr(bundle, "PREPARED", tmp_path)
    assert bundle.semgrep_pins() == ["charset_normalizer==3.5.1", "semgrep==1.136.0"]


def test_only_the_products_model_is_copied(tmp_path, monkeypatch):
    models = tmp_path / "prepared" / "models"
    manifest = models / "manifests" / "registry.ollama.ai" / "library" / "qwen2.5-coder" / "7b-instruct-q4_K_M"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(json.dumps({"config": {"digest": "sha256:c0"}, "layers": [{"digest": "sha256:l1"}, {"digest": "sha256:l2"}]}), encoding="utf-8")
    (models / "blobs").mkdir()
    for blob in ("sha256-c0", "sha256-l1", "sha256-l2", "sha256-embedding"):
        (models / "blobs" / blob).write_bytes(blob.encode())
    monkeypatch.setattr(bundle, "PREPARED", tmp_path / "prepared")
    assert bundle.copy_model(tmp_path / "out") == "3 blobs"
    assert sorted(p.name for p in (tmp_path / "out" / "blobs").iterdir()) == ["sha256-c0", "sha256-l1", "sha256-l2"]
    assert (tmp_path / "out" / manifest.relative_to(models)).is_file()


@pytest.mark.skipif(os.name != "nt", reason="Windows drive paths; the bundle is built on Windows")
def test_paths_reach_wsl_through_mnt(tmp_path):
    assert bundle.wsl_path(Path("C:/TUBITAKClaude/x y/z")) == "/mnt/c/TUBITAKClaude/x y/z"
