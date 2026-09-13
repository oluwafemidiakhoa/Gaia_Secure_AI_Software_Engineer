import hashlib
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from gaia_secure_agent.pr_request import build_pull_request_request
from gaia_secure_agent.publication import PublicationPlan
from gaia_secure_agent.publish_guard import authorize_trusted_publication


JOB_ID = UUID("12345678-1234-5678-1234-567812345678")
BASE_COMMIT = "a" * 40


def _plan(tmp_path: Path) -> PublicationPlan:
    patch_path = tmp_path / "changes.patch"
    patch_bytes = b"diff --git a/a.txt b/a.txt\n"
    patch_path.write_bytes(patch_bytes)
    return PublicationPlan(
        job_id=JOB_ID,
        repository="https://github.com/example/project",
        base_branch="main",
        base_commit=BASE_COMMIT,
        source_sha256="b" * 64,
        patch_sha256=hashlib.sha256(patch_bytes).hexdigest(),
        evidence_sha256="d" * 64,
        patch_path=patch_path,
        approved_by="reviewer",
        approved_at=datetime.now(UTC),
    )


def test_trusted_publication_authorizes_unchanged_base(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    request = build_pull_request_request(plan)

    authorization = authorize_trusted_publication(
        plan=plan,
        request=request,
        observed_base_commit=BASE_COMMIT,
    )

    assert authorization.authorized is True
    assert authorization.base_commit == BASE_COMMIT
    assert authorization.draft is True
    assert authorization.auto_merge_allowed is False


def test_trusted_publication_rejects_moved_base(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    request = build_pull_request_request(plan)

    with pytest.raises(PermissionError, match="base branch moved"):
        authorize_trusted_publication(
            plan=plan,
            request=request,
            observed_base_commit="e" * 40,
        )


def test_trusted_publication_rejects_modified_patch(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    request = build_pull_request_request(plan)
    plan.patch_path.write_bytes(b"tampered")

    with pytest.raises(PermissionError, match="patch changed"):
        authorize_trusted_publication(
            plan=plan,
            request=request,
            observed_base_commit=BASE_COMMIT,
        )


def test_trusted_publication_rejects_mismatched_evidence(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    request = build_pull_request_request(plan).model_copy(update={"evidence_sha256": "f" * 64})

    with pytest.raises(PermissionError, match="evidence digest"):
        authorize_trusted_publication(
            plan=plan,
            request=request,
            observed_base_commit=BASE_COMMIT,
        )


def test_trusted_publication_rejects_non_draft_request(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    request = build_pull_request_request(plan).model_copy(update={"draft": False})

    with pytest.raises(PermissionError, match="draft"):
        authorize_trusted_publication(
            plan=plan,
            request=request,
            observed_base_commit=BASE_COMMIT,
        )
