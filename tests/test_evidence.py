import pytest

from safepatch import common


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setattr(common, "ROOT", tmp_path)
    monkeypatch.delenv("EVIDENCE_DIR", raising=False)
    return tmp_path


def test_default_location_is_ignored_v02_folder(repo):
    path = common.evidence("unit-tests.xml")
    assert path == (repo / "evidence/v02-local/unit-tests.xml").resolve()
    assert path.parent.is_dir()


@pytest.mark.parametrize("value", ["evidence/v02-retry", "evidence/v02-benchmark/run-1"])
def test_named_v02_folders_are_allowed(repo, monkeypatch, value):
    monkeypatch.setenv("EVIDENCE_DIR", value)
    assert common.evidence("summary.json") == (repo / value / "summary.json").resolve()


def test_folder_outside_archive_is_allowed(repo, tmp_path_factory, monkeypatch):
    outside = tmp_path_factory.mktemp("scratch")
    monkeypatch.setenv("EVIDENCE_DIR", str(outside))
    assert common.evidence("a.json") == outside.resolve() / "a.json"


@pytest.mark.parametrize("value", ["evidence", "evidence/", "evidence/acceptance", "evidence/benchmark/jobs", "evidence/v02", "evidence/v02-x/../raw"])
def test_v01_archive_is_never_writable(repo, monkeypatch, value):
    monkeypatch.setenv("EVIDENCE_DIR", value)
    with pytest.raises(RuntimeError, match="read-only"):
        common.evidence("x.json")


def test_absolute_path_into_archive_is_refused(repo, monkeypatch):
    monkeypatch.setenv("EVIDENCE_DIR", str(repo / "evidence" / "raw"))
    with pytest.raises(RuntimeError, match="read-only"):
        common.evidence()
