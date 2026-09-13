import json
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest

from gaia_secure_agent.sandbox import OpenShellSandboxManager, SandboxHandle


def test_name_for_job_is_stable_and_safe() -> None:
    job_id = UUID("12345678-1234-5678-1234-567812345678")
    assert OpenShellSandboxManager.name_for_job(job_id) == "gaia-12345678123456781234"


def test_create_uses_fixed_openshell_arguments(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("version: 1\n", encoding="utf-8")
    captured: list[str] = []

    def fake_run(argv: list[str], **_: object) -> SimpleNamespace:
        captured.extend(argv)
        return SimpleNamespace(returncode=0, stdout=json.dumps({"name": "gaia-test"}), stderr="")

    monkeypatch.setattr("gaia_secure_agent.sandbox.subprocess.run", fake_run)
    manager = OpenShellSandboxManager(policy_path=policy)
    handle = manager.create("gaia-test")

    assert handle == SandboxHandle(name="gaia-test")
    assert captured[:3] == ["openshell", "sandbox", "create"]
    assert "--policy" in captured
    assert str(policy) in captured
    assert "--cpu" in captured
    assert "--memory" in captured


def test_delete_targets_exact_sandbox(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("version: 1\n", encoding="utf-8")
    captured: list[str] = []

    def fake_run(argv: list[str], **_: object) -> SimpleNamespace:
        captured.extend(argv)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("gaia_secure_agent.sandbox.subprocess.run", fake_run)
    manager = OpenShellSandboxManager(policy_path=policy)
    manager.delete(SandboxHandle(name="gaia-test"))

    assert captured == ["openshell", "sandbox", "delete", "gaia-test"]


def test_invalid_sandbox_name_is_rejected(tmp_path: Path) -> None:
    manager = OpenShellSandboxManager(policy_path=tmp_path / "policy.yaml")
    with pytest.raises(ValueError):
        manager.delete(SandboxHandle(name="../../escape"))
