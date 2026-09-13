from pathlib import Path
from types import SimpleNamespace

import pytest

from gaia_secure_agent.sandbox import OpenShellSandboxManager, SandboxHandle


def test_claude_version_probe_uses_fixed_repository_workdir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured: list[str] = []

    def fake_run(argv: list[str], **_: object) -> SimpleNamespace:
        captured.extend(argv)
        return SimpleNamespace(returncode=0, stdout="2.1.220 (Claude Code)\n", stderr="")

    monkeypatch.setattr("gaia_secure_agent.sandbox.subprocess.run", fake_run)
    manager = OpenShellSandboxManager(policy_path=tmp_path / "policy.yaml")
    output = manager.claude_version(SandboxHandle(name="gaia-test"))

    assert output.startswith("2.1.220")
    assert captured == [
        "openshell",
        "sandbox",
        "exec",
        "-n",
        "gaia-test",
        "--workdir",
        "/sandbox/repository",
        "--no-login-shell",
        "--",
        "claude",
        "--version",
    ]


def test_headless_canary_is_one_turn_bare_and_noninteractive(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured: list[str] = []

    def fake_run(argv: list[str], **_: object) -> SimpleNamespace:
        captured.extend(argv)
        return SimpleNamespace(returncode=0, stdout="PROBE_OK\n", stderr="")

    monkeypatch.setattr("gaia_secure_agent.sandbox.subprocess.run", fake_run)
    manager = OpenShellSandboxManager(policy_path=tmp_path / "policy.yaml")
    ok = manager.claude_headless_canary(SandboxHandle(name="gaia-test"))

    assert ok is True
    assert "--no-tty" in captured
    assert "--no-login-shell" in captured
    assert "--workdir" in captured
    assert "/sandbox/repository" in captured
    assert captured[captured.index("--") + 1 :] == [
        "claude",
        "--bare",
        "-p",
        "--max-turns",
        "1",
        "--permission-mode",
        "dontAsk",
        "Reply with exactly PROBE_OK. Do not use tools.",
    ]


def test_headless_canary_rejects_unexpected_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def fake_run(_argv: list[str], **_: object) -> SimpleNamespace:
        return SimpleNamespace(returncode=0, stdout="something else\n", stderr="")

    monkeypatch.setattr("gaia_secure_agent.sandbox.subprocess.run", fake_run)
    manager = OpenShellSandboxManager(policy_path=tmp_path / "policy.yaml")

    assert manager.claude_headless_canary(SandboxHandle(name="gaia-test")) is False
