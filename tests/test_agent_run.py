from pathlib import Path

import pytest

from gaia_secure_agent.agent_run import run_coding_agent
from gaia_secure_agent.models import CodingJob
from gaia_secure_agent.sandbox import SandboxHandle


class FakeManager:
    def __init__(self, *, canary: bool = True, output: str = "completed") -> None:
        self.canary = canary
        self.output = output
        self.task_called = False
        self.instructions: str | None = None

    def claude_version(self, handle: SandboxHandle) -> str:
        return "2.1.220 (Claude Code)"

    def claude_headless_canary(self, handle: SandboxHandle) -> bool:
        return self.canary

    def run_claude_task(
        self,
        handle: SandboxHandle,
        *,
        instructions: str,
        max_turns: int,
        timeout_seconds: int,
    ) -> str:
        self.task_called = True
        self.instructions = instructions
        assert max_turns == 8
        assert timeout_seconds == 300
        return self.output


def _job(agent: str = "claude") -> CodingJob:
    return CodingJob(
        repository="https://github.com/example/project",
        task="Fix the failing token refresh test",
        agent=agent,
        max_turns=8,
        timeout_seconds=300,
    )


def test_agent_run_requires_successful_canary(tmp_path: Path) -> None:
    manager = FakeManager(canary=False)

    with pytest.raises(RuntimeError, match="canary"):
        run_coding_agent(
            manager,
            job=_job(),
            sandbox_name="gaia-test",
            output_dir=tmp_path,
        )

    assert manager.task_called is False


def test_agent_run_rejects_unsupported_agent_before_task(tmp_path: Path) -> None:
    manager = FakeManager()

    with pytest.raises(RuntimeError, match="Claude Code only"):
        run_coding_agent(
            manager,
            job=_job("codex"),
            sandbox_name="gaia-test",
            output_dir=tmp_path,
        )

    assert manager.task_called is False


def test_agent_run_persists_bounded_output_and_security_instructions(tmp_path: Path) -> None:
    manager = FakeManager(output="agent summary")

    result = run_coding_agent(
        manager,
        job=_job(),
        sandbox_name="gaia-test",
        output_dir=tmp_path,
    )

    assert result.completed is True
    assert result.agent_version == "2.1.220"
    assert result.max_turns == 8
    assert result.timeout_seconds == 300
    assert result.output_path.read_text(encoding="utf-8") == "agent summary"
    assert result.output_bytes == len(b"agent summary")
    assert manager.task_called is True
    assert manager.instructions is not None
    assert "Do not push" in manager.instructions
    assert "Do not access the host filesystem" in manager.instructions
    assert "Fix the failing token refresh test" in manager.instructions


def test_agent_run_refuses_to_overwrite_existing_output(tmp_path: Path) -> None:
    (tmp_path / "agent-output.txt").write_text("existing", encoding="utf-8")
    manager = FakeManager()

    with pytest.raises(RuntimeError, match="already exists"):
        run_coding_agent(
            manager,
            job=_job(),
            sandbox_name="gaia-test",
            output_dir=tmp_path,
        )
