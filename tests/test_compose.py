from pathlib import Path
import yaml

from safepatch.common import ROOT


def test_compose_boundaries_static_only():
    config = yaml.safe_load((ROOT / "compose.yml").read_text())
    services = config["services"]
    assert services["worker1"]["build"]["target"] != services["worker2"]["build"]["target"]
    assert not services["worker1"].get("volumes")
    assert "runner_token" not in services["worker1"]["secrets"]
    assert "approval_signing_key" not in services["worker2"]["secrets"]
    for name in ("orchestrator", "worker1", "worker2", "runner", "ollama", "deployer"):
        service = services[name]
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert not service.get("privileged", False)
        assert all("docker.sock" not in v for v in service.get("volumes", []))
        assert all(config["networks"][n]["internal"] for n in service["networks"])
        assert all(p.startswith("127.0.0.1:") for p in service.get("ports", []))
