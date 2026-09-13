import hashlib
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from gaia_secure_agent.pr_request import build_pull_request_request
from gaia_secure_agent.publication import PublicationPlan
from gaia_secure_agent.publication_handoff import (
    build_publication_handoff,
    write_publication_handoff,
)
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


def test_publication_handoff_contains_no_credentials(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    request = build_pull_request_request(plan)
    authorization = authorize_trusted_publication(
        plan=plan,
        request=request,
        observed_base_commit=BASE_COMMIT,
    )

    handoff = build_publication_handoff(
        plan=plan,
        request=request,
        authorization=authorization,
    )

    assert handoff.job_id == JOB_ID
    assert handoff.patch_sha256 == plan.patch_sha256
    assert handoff.evidence_sha256 == plan.evidence_sha256
    assert handoff.credentials_embedded is False
    assert handoff.agent_github_write_allowed is False
    assert handoff.draft is True
    assert handoff.auto_merge_allowed is False


def test_publication_handoff_rejects_mismatched_authorization(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    request = build_pull_request_request(plan)
    authorization = authorize_trusted_publication(
        plan=plan,
        request=request,
        observed_base_commit=BASE_COMMIT,
    ).model_copy(update={"evidence_sha256": "f" * 64})

    with pytest.raises(PermissionError, match="evidence digest"):
        build_publication_handoff(
            plan=plan,
            request=request,
            authorization=authorization,
        )


def test_publication_handoff_manifest_is_write_once(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    request = build_pull_request_request(plan)
    authorization = authorize_trusted_publication(
        plan=plan,
        request=request,
        observed_base_commit=BASE_COMMIT,
    )
    handoff = build_publication_handoff(
        plan=plan,
        request=request,
        authorization=authorization,
    )
    destination = tmp_path / "publication-handoff.json"

    write_publication_handoff(handoff, destination)

    with pytest.raises(RuntimeError, match="already exists"):
        write_publication_handoff(handoff, destination)
