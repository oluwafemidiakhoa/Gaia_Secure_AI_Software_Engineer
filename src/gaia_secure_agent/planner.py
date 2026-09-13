from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from .models import CodingJob


class ExecutionPhase(StrEnum):
    VALIDATE = "validate"
    RESOLVE_BASE = "resolve_base"
    CREATE_SANDBOX = "create_sandbox"
    PREPARE_REPOSITORY = "prepare_repository"
    RUN_AGENT = "run_agent"
    VERIFY = "verify"
    COLLECT_PATCH = "collect_patch"
    REVIEW = "review"
    CLEANUP = "cleanup"


class PlanStep(BaseModel):
    phase: ExecutionPhase
    description: str
    requires_network: bool = False
    requires_repository_write: bool = False
    requires_human_approval: bool = False


class ExecutionPlan(BaseModel):
    repository: str
    base_branch: str
    agent: str
    steps: list[PlanStep] = Field(default_factory=list)
    allowed_network_hosts: list[str] = Field(default_factory=list)
    agent_github_write_allowed: bool = False
    human_approval_before_publish: bool = True


def build_execution_plan(job: CodingJob) -> ExecutionPlan:
    return ExecutionPlan(
        repository=str(job.repository),
        base_branch=job.base_branch,
        agent=job.agent,
        allowed_network_hosts=["github.com", "api.github.com"],
        steps=[
            PlanStep(
                phase=ExecutionPhase.VALIDATE,
                description="Validate repository URL, branch, limits, and policy invariants.",
            ),
            PlanStep(
                phase=ExecutionPhase.RESOLVE_BASE,
                description="Resolve the immutable base commit for the requested branch.",
                requires_network=True,
            ),
            PlanStep(
                phase=ExecutionPhase.CREATE_SANDBOX,
                description="Create a fresh isolated sandbox with deny-by-default policy.",
            ),
            PlanStep(
                phase=ExecutionPhase.PREPARE_REPOSITORY,
                description="Prepare a sandbox-local working copy at the resolved base commit.",
                requires_network=True,
            ),
            PlanStep(
                phase=ExecutionPhase.RUN_AGENT,
                description="Run the selected coding agent without GitHub write authority.",
            ),
            PlanStep(
                phase=ExecutionPhase.VERIFY,
                description="Run only control-plane-approved verification profiles.",
            ),
            PlanStep(
                phase=ExecutionPhase.COLLECT_PATCH,
                description="Collect changed paths, patch material, and execution evidence.",
            ),
            PlanStep(
                phase=ExecutionPhase.REVIEW,
                description="Require human approval before any publication or GitHub write.",
                requires_human_approval=True,
            ),
            PlanStep(
                phase=ExecutionPhase.CLEANUP,
                description="Destroy the sandbox and transient credentials after the run.",
            ),
        ],
    )
