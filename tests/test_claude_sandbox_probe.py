from pathlib import Path
from types import SimpleNamespace

import pytest

from gaia_secure_agent.sandbox import OpenShellSandboxManager, SandboxHandle


def _assert_private_inference_prefix(captured: list[str], timeout: str) -> None:
    assert captured[:5] == ["openshell", "sandbox", "exec", "-n", "gaia-test"]
    assert ["--workdir", "/sandbox/repository"] == captured[5:7]
    assert ["--timeout", timeout] == captured[7:9]
    assert "--no-tty" in captured
    assert "--no-login-shell" in captured
    assert "ANTHROPIC_BASE_URL=https://inference.local" in captured
    assert "ANTHROPIC_API_KEY=unused" in captured


def test_claude_version_probe_uses_private_inference_route(
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
    _assert_private_inference_prefix(captured, "30")
    assert captured[captured.index("--") + 1 :] == ["claude", "--version"]


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
    _assert_private_inference_prefix(captured, "60")
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


def test_claude_task_is_bounded_and_uses_private_inference(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured: list[str] = []

    def fake_run(argv: list[str], **_: object) -> SimpleNamespace:
        captured.extend(argv)
        return SimpleNamespace(returncode=0, stdout="done\n", stderr="")

    monkeypatch.setattr("gaia_secure_agent.sandbox.subprocess.run", fake_run)
    manager = OpenShellSandboxManager(policy_path=tmp_path / "policy.yaml")
    output = manager.run_claude_task(
        SandboxHandle(name="gaia-test"),
        instructions="Fix the failing test without weakening coverage.",
        max_turns=7,
        timeout_seconds=120,
    )

    assert output == "done"
    _assert_private_inference_prefix(captured, "120")
    assert captured[captured.index("--") + 1 :] == [
        "claude",
        "--bare",
        "-p",
        "--max-turns",
        "7",
        "--permission-mode",
        "dontAsk",
        "Fix the failing test without weakening coverage.",
    ]


def test_claude_task_rejects_unbounded_limits(tmp_path: Path) -> None:
    manager = OpenShellSandboxManager(policy_path=tmp_path / "policy.yaml")
    handle = SandboxHandle(name="gaia-test")

    with pytest.raises(ValueError, match="max_turns"):
        manager.run_claude_task(
            handle,
            instructions="Fix issue #42",
            max_turns=101,
            timeout_seconds=120,
        )

    with pytest.raises(ValueError, match="timeout"):
        manager.run_claude_task(
            handle,
            instructions="Fix issue #42",
            max_turns=5,
            timeout_seconds=10,
        )
