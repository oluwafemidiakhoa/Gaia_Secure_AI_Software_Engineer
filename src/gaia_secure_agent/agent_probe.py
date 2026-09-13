from __future__ import annotations

import re

from pydantic import BaseModel, Field


_VERSION = re.compile(r"(?P<version>\d+\.\d+\.\d+)")


class AgentProbe(BaseModel):
    agent: str
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    bare_mode_required: bool = True
    print_mode_required: bool = True
    max_turns_required: bool = True
    permission_mode_verified: bool = False
    executable_autonomy_allowed: bool = False


def parse_claude_version(output: str) -> AgentProbe:
    match = _VERSION.search(output.strip())
    if not match:
        raise RuntimeError("Claude Code version probe returned an unrecognized version")
    return AgentProbe(
        agent="claude",
        version=match.group("version"),
    )


def authorize_claude_execution(probe: AgentProbe, *, permission_mode_verified: bool) -> AgentProbe:
    if probe.agent != "claude":
        raise ValueError("Claude execution authorization requires a Claude probe")
    if not permission_mode_verified:
        raise RuntimeError("Claude permission mode has not been verified on this worker")
    return probe.model_copy(
        update={
            "permission_mode_verified": True,
            "executable_autonomy_allowed": True,
        }
    )
