import pytest
from safepatch.scanner import SonarAdapter


def test_hotspot_not_accepted_as_required_vulnerability():
    def call(url, **kwargs):
        return {"status": "UP", "version": "25.9.0.112764"} if "system/status" in url else {"rule": {"type": "SECURITY_HOTSPOT", "status": "READY"}}
    with pytest.raises(RuntimeError, match="unsupported"):
        SonarAdapter("http://127.0.0.1:9000", "test", call).preflight("25.9.0.112764", "java:S3649")


def test_server_version_mismatch_is_failure():
    adapter = SonarAdapter("http://127.0.0.1:9000", "test", lambda *a, **k: {"status": "UP", "version": "unknown"})
    with pytest.raises(RuntimeError, match="version_mismatch"):
        adapter.preflight("25.9.0.112764", "java:S3649")
