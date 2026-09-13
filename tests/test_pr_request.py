from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from gaia_secure_agent.pr_request import (
    branch_for_job,
    build_pull_request_request,
    write_pull_request_request,
)
from gaia_secure_agent.publication import PublicationPlan


JOB_ID = UUID("12345678-1234-5678-1234-567812345678")


def _plan(tmp_path: Path) -> PublicationPlan:
    patch = tmp_path / "changes.patch"
    patch.write_text("patch\n", encoding="utf-8")
    return PublicationPlan(
        job_id=JOB_ID,
        repository="https://github.com/example/project",
        base_branch="main",
        base_commit="a" * 40,
        source_sha256="b" * 64,
        patch_sha256="c" * 64,
        evidence_sha256="d" * 64,
        patch_path=patch,
        approved_by="reviewer",
        approved_at=datetime.now(UTC),
    )


def test_branch_for_job_is_deterministic() -> None:
    assert branch_for_job(JOB_ID) == "gaia-secure/12345678123456781234"


def test_pr_request_is_draft_and_bound_to_evidence(tmp_path: Path) -> None:
    request = build_pull_request_request(_plan(tmp_path))

    assert request.job_id == JOB_ID
    assert request.base_commit == "a" * 40
    assert request.patch_sha256 == "c" * 64
    assert request.evidence_sha256 == "d" * 64
    assert request.draft is True
    assert request.auto_merge_allowed is False
    assert request.agent_github_write_allowed is False
    assert request.human_approval_verified is True
    assert request.evidence_verified is True


def test_pr_request_manifest_is_write_once(tmp_path: Path) -> None:
    request = build_pull_request_request(_plan(tmp_path))
    destination = tmp_path / "pr-request.json"

    write_pull_request_request(request, destination)

    with pytest.raises(RuntimeError, match="already exists"):
        write_pull_request_request(request, destination)
