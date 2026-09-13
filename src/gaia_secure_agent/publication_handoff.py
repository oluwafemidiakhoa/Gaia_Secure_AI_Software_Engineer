from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

from pydantic import BaseModel, Field

from .pr_request import PullRequestRequest
from .publication import PublicationPlan
from .publish_guard import TrustedPublicationAuthorization


class PublicationHandoff(BaseModel):
    job_id: UUID
    repository: str
    base_branch: str
    base_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    head_branch: str
    title: str = Field(min_length=1, max_length=200)
    patch_path: Path
    patch_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    approved_by: str
    draft: bool = True
    auto_merge_allowed: bool = False
    credentials_embedded: bool = False
    agent_github_write_allowed: bool = False


def build_publication_handoff(
    *,
    plan: PublicationPlan,
    request: PullRequestRequest,
    authorization: TrustedPublicationAuthorization,
) -> PublicationHandoff:
    if authorization.base_commit != plan.base_commit:
        raise PermissionError("publication authorization base commit does not match plan")
    if authorization.patch_sha256 != plan.patch_sha256:
        raise PermissionError("publication authorization patch digest does not match plan")
    if authorization.evidence_sha256 != plan.evidence_sha256:
        raise PermissionError("publication authorization evidence digest does not match plan")
    if authorization.head_branch != request.head_branch:
        raise PermissionError("publication authorization head branch does not match request")
    if not authorization.draft or not request.draft:
        raise PermissionError("publication handoff requires a draft pull request")
    if authorization.auto_merge_allowed or request.auto_merge_allowed:
        raise PermissionError("publication handoff cannot enable auto-merge")

    return PublicationHandoff(
        job_id=plan.job_id,
        repository=plan.repository,
        base_branch=plan.base_branch,
        base_commit=plan.base_commit,
        head_branch=request.head_branch,
        title=request.title,
        patch_path=plan.patch_path,
        patch_sha256=plan.patch_sha256,
        evidence_sha256=plan.evidence_sha256,
        approved_by=plan.approved_by,
    )


def write_publication_handoff(handoff: PublicationHandoff, path: Path) -> Path:
    if path.exists():
        raise RuntimeError(f"publication handoff already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(handoff.model_dump(mode="json"), indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )
    return path
