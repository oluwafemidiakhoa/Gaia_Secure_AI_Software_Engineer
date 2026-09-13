from __future__ import annotations

import hashlib
from pathlib import Path

from pydantic import BaseModel, Field

from .agent_contract import AgentKind, build_agent_contract, render_agent_instructions
from .agent_probe import authorize_claude_execution, parse_claude_version
from .models import CodingJob
from .sandbox import OpenShellSandboxManager, SandboxHandle


class AgentRunResult(BaseModel):
    sandbox_name: str
    agent: AgentKind
    agent_version: str
    max_turns: int
    timeout_seconds: int
    output_path: Path
    output_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    output_bytes: int = Field(ge=0, le=1_000_000)
    completed: bool = True


def run_coding_agent(
    manager: OpenShellSandboxManager,
    *,
    job: CodingJob,
    sandbox_name: str,
    output_dir: Path,
) -> AgentRunResult:
    contract = build_agent_contract(job)
    if contract.agent is not AgentKind.CLAUDE:
        raise RuntimeError("v1 execution currently supports Claude Code only")

    handle = SandboxHandle(name=sandbox_name)
    probe = parse_claude_version(manager.claude_version(handle))
    if not manager.claude_headless_canary(handle):
        raise RuntimeError("Claude headless canary did not return the expected response")
    authorized = authorize_claude_execution(probe, permission_mode_verified=True)
    if not authorized.executable_autonomy_allowed:
        raise RuntimeError("Claude execution capability is not authorized")

    instructions = render_agent_instructions(contract)
    output = manager.run_claude_task(
        handle,
        instructions=instructions,
        max_turns=contract.max_turns,
        timeout_seconds=job.timeout_seconds,
    )
    encoded = output.encode("utf-8")
    if len(encoded) > 1_000_000:
        raise RuntimeError("agent output exceeds the control-plane size limit")

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "agent-output.txt"
    if output_path.exists():
        raise RuntimeError(f"agent output already exists: {output_path}")
    output_path.write_bytes(encoded)

    return AgentRunResult(
        sandbox_name=sandbox_name,
        agent=contract.agent,
        agent_version=authorized.version,
        max_turns=contract.max_turns,
        timeout_seconds=job.timeout_seconds,
        output_path=output_path,
        output_sha256=hashlib.sha256(encoded).hexdigest(),
        output_bytes=len(encoded),
    )
