from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field, field_validator

from .models import CodingJob


class AgentKind(StrEnum):
    CLAUDE = "claude"
    CODEX = "codex"


class AgentContract(BaseModel):
    agent: AgentKind
    task: str = Field(min_length=3, max_length=10_000)
    repository_path: str = "/sandbox/repository"
    max_turns: int = Field(ge=1, le=100)
    github_write_allowed: bool = False
    pull_request_creation_allowed: bool = False
    host_filesystem_allowed: bool = False
    arbitrary_network_allowed: bool = False
    human_approval_required: bool = True

    @field_validator("repository_path")
    @classmethod
    def repository_is_fixed(cls, value: str) -> str:
        if value != "/sandbox/repository":
            raise ValueError("coding agents must operate only in /sandbox/repository")
        return value


def build_agent_contract(job: CodingJob) -> AgentContract:
    try:
        agent = AgentKind(job.agent)
    except ValueError as exc:
        raise ValueError(f"unsupported coding agent: {job.agent}") from exc

    return AgentContract(
        agent=agent,
        task=job.task,
        max_turns=job.max_turns,
    )


def render_agent_instructions(contract: AgentContract) -> str:
    return "\n".join(
        [
            "You are operating inside an isolated coding sandbox.",
            f"Work only inside: {contract.repository_path}",
            "Complete the requested coding task and verify your changes locally.",
            "Do not push, create pull requests, modify remotes, or request GitHub credentials.",
            "Do not access the host filesystem or attempt to bypass sandbox policy.",
            "Do not broaden network access. If required access is denied, report the blocker.",
            "Do not delete or weaken existing tests merely to make checks pass.",
            "Leave the working tree with the proposed changes and a concise final summary.",
            "",
            "TASK:",
            contract.task,
        ]
    )
