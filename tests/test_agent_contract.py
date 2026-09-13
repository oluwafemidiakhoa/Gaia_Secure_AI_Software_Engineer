import pytest

from gaia_secure_agent.agent_contract import (
    AgentKind,
    build_agent_contract,
    render_agent_instructions,
)
from gaia_secure_agent.models import CodingJob


def test_agent_contract_preserves_security_invariants() -> None:
    job = CodingJob(
        repository="https://github.com/example/project",
        task="Fix the failing token refresh test",
        agent="claude",
        max_turns=12,
    )

    contract = build_agent_contract(job)

    assert contract.agent is AgentKind.CLAUDE
    assert contract.repository_path == "/sandbox/repository"
    assert contract.max_turns == 12
    assert contract.github_write_allowed is False
    assert contract.pull_request_creation_allowed is False
    assert contract.host_filesystem_allowed is False
    assert contract.arbitrary_network_allowed is False
    assert contract.human_approval_required is True


def test_agent_instructions_explicitly_forbid_github_writes() -> None:
    job = CodingJob(
        repository="https://github.com/example/project",
        task="Fix issue #42",
        agent="claude",
    )
    instructions = render_agent_instructions(build_agent_contract(job))

    assert "Do not push" in instructions
    assert "create pull requests" in instructions
    assert "/sandbox/repository" in instructions
    assert "Fix issue #42" in instructions


def test_unknown_agent_is_rejected() -> None:
    job = CodingJob(
        repository="https://github.com/example/project",
        task="Fix issue #42",
        agent="unknown-agent",
    )

    with pytest.raises(ValueError, match="unsupported coding agent"):
        build_agent_contract(job)
