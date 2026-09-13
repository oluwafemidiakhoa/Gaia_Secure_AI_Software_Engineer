from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

from pydantic import BaseModel, Field

from .publication import PublicationPlan


class PullRequestRequest(BaseModel):
    job_id: UUID
    repository: str
    base_branch: str
    base_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    head_branch: str
    patch_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    title: str
    draft: bool = True
    auto_merge_allowed: bool = False
    agent_github_write_allowed: bool = False
    human_approval_verified: bool = True
    evidence_verified: bool = True


def branch_for_job(job_id: UUID) -> str:
    return f"gaia-secure/{job_id.hex[:20]}"


def build_pull_request_request(plan: PublicationPlan) -> PullRequestRequest:
    short_job = plan.job_id.hex[:8]
    return PullRequestRequest(
        job_id=plan.job_id,
        repository=plan.repository,
        base_branch=plan.base_branch,
        base_commit=plan.base_commit,
        head_branch=branch_for_job(plan.job_id),
        patch_sha256=plan.patch_sha256,
        evidence_sha256=plan.evidence_sha256,
        title=f"Gaia secure agent patch {short_job}",
        draft=True,
        auto_merge_allowed=False,
        agent_github_write_allowed=False,
        human_approval_verified=plan.human_approval_verified,
        evidence_verified=plan.evidence_verified,
    )


def write_pull_request_request(request: PullRequestRequest, path: Path) -> Path:
    if path.exists():
        raise RuntimeError(f"pull request request already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(request.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path
