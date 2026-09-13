from __future__ import annotations

import hashlib
import re
from pathlib import Path

from pydantic import BaseModel, Field

from .pr_request import PullRequestRequest
from .publication import PublicationPlan


_SHA40 = re.compile(r"^[0-9a-f]{40}$")


class TrustedPublicationAuthorization(BaseModel):
    authorized: bool = True
    base_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    patch_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    head_branch: str
    draft: bool = True
    auto_merge_allowed: bool = False


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def assert_base_head_unchanged(*, expected: str, observed: str) -> None:
    expected_sha = expected.strip().lower()
    observed_sha = observed.strip().lower()
    if not _SHA40.fullmatch(expected_sha):
        raise ValueError("expected base commit is not a valid SHA")
    if not _SHA40.fullmatch(observed_sha):
        raise ValueError("observed base commit is not a valid SHA")
    if observed_sha != expected_sha:
        raise PermissionError("base branch moved after the coding job was resolved")


def assert_pr_request_matches_plan(
    request: PullRequestRequest,
    plan: PublicationPlan,
) -> None:
    if request.job_id != plan.job_id:
        raise PermissionError("PR request belongs to a different coding job")
    if request.repository != plan.repository:
        raise PermissionError("PR request repository does not match publication plan")
    if request.base_branch != plan.base_branch:
        raise PermissionError("PR request base branch does not match publication plan")
    if request.base_commit != plan.base_commit:
        raise PermissionError("PR request base commit does not match publication plan")
    if request.patch_sha256 != plan.patch_sha256:
        raise PermissionError("PR request patch digest does not match publication plan")
    if request.evidence_sha256 != plan.evidence_sha256:
        raise PermissionError("PR request evidence digest does not match publication plan")
    if not request.draft:
        raise PermissionError("trusted publication requires a draft pull request")
    if request.auto_merge_allowed:
        raise PermissionError("auto-merge must remain disabled")
    if request.agent_github_write_allowed:
        raise PermissionError("agent GitHub write authority must remain disabled")


def authorize_trusted_publication(
    *,
    plan: PublicationPlan,
    request: PullRequestRequest,
    observed_base_commit: str,
) -> TrustedPublicationAuthorization:
    assert_pr_request_matches_plan(request, plan)
    assert_base_head_unchanged(expected=plan.base_commit, observed=observed_base_commit)

    if not plan.patch_path.is_file():
        raise PermissionError("verified patch file is missing")
    if _sha256(plan.patch_path) != plan.patch_sha256:
        raise PermissionError("verified patch changed after publication planning")

    return TrustedPublicationAuthorization(
        base_commit=plan.base_commit,
        patch_sha256=plan.patch_sha256,
        evidence_sha256=plan.evidence_sha256,
        head_branch=request.head_branch,
        draft=True,
        auto_merge_allowed=False,
    )
