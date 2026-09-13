from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel

from .publication_handoff import PublicationHandoff


class GitHubWritePort(Protocol):
    def get_branch_head(self, repository: str, branch: str) -> str: ...

    def create_branch(self, repository: str, branch: str, base_commit: str) -> None: ...

    def apply_patch(
        self,
        repository: str,
        branch: str,
        patch_path: Path,
        expected_sha256: str,
    ) -> None: ...

    def open_draft_pull_request(
        self,
        repository: str,
        *,
        head_branch: str,
        base_branch: str,
        title: str,
        body: str,
    ) -> str: ...


class PublicationOutcome(BaseModel):
    repository: str
    head_branch: str
    base_branch: str
    pull_request_url: str
    draft: bool = True
    auto_merge_performed: bool = False
    agent_github_write_performed: bool = False


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def execute_publication_handoff(
    writer: GitHubWritePort,
    handoff: PublicationHandoff,
) -> PublicationOutcome:
    if not handoff.draft:
        raise PermissionError("publication handoff must remain draft-only")
    if handoff.auto_merge_allowed:
        raise PermissionError("auto-merge is not permitted")
    if handoff.credentials_embedded:
        raise PermissionError("publication handoff must not contain credentials")
    if handoff.agent_github_write_allowed:
        raise PermissionError("agent GitHub write authority must remain disabled")
    if not handoff.patch_path.is_file():
        raise PermissionError("verified patch file is missing")
    if _sha256(handoff.patch_path) != handoff.patch_sha256:
        raise PermissionError("verified patch changed before trusted publication")

    observed_base = writer.get_branch_head(handoff.repository, handoff.base_branch)
    if observed_base != handoff.base_commit:
        raise PermissionError("base branch moved before trusted publication")

    writer.create_branch(
        handoff.repository,
        handoff.head_branch,
        handoff.base_commit,
    )
    writer.apply_patch(
        handoff.repository,
        handoff.head_branch,
        handoff.patch_path,
        handoff.patch_sha256,
    )
    body = (
        "Created by Gaia Secure AI Software Engineer.\n\n"
        f"Evidence SHA-256: `{handoff.evidence_sha256}`\n"
        f"Patch SHA-256: `{handoff.patch_sha256}`\n"
        f"Approved by: `{handoff.approved_by}`\n\n"
        "This pull request is draft-only. Automatic merge is disabled."
    )
    pull_request_url = writer.open_draft_pull_request(
        handoff.repository,
        head_branch=handoff.head_branch,
        base_branch=handoff.base_branch,
        title=handoff.title,
        body=body,
    )
    return PublicationOutcome(
        repository=handoff.repository,
        head_branch=handoff.head_branch,
        base_branch=handoff.base_branch,
        pull_request_url=pull_request_url,
    )
