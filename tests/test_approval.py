from uuid import uuid4

import pytest

from gaia_secure_agent.approval import ApprovalDecision, ApprovalRecord, assert_publish_approved


def test_matching_approval_allows_publication_gate() -> None:
    job_id = uuid4()
    digest = "a" * 64
    approval = ApprovalRecord(
        job_id=job_id,
        patch_sha256=digest,
        decision=ApprovalDecision.APPROVE,
        actor="human-reviewer",
    )

    assert_publish_approved(job_id=job_id, patch_sha256=digest, approval=approval)


def test_different_patch_is_denied() -> None:
    job_id = uuid4()
    approval = ApprovalRecord(
        job_id=job_id,
        patch_sha256="a" * 64,
        decision=ApprovalDecision.APPROVE,
        actor="human-reviewer",
    )

    with pytest.raises(PermissionError):
        assert_publish_approved(
            job_id=job_id,
            patch_sha256="b" * 64,
            approval=approval,
        )


def test_rejected_patch_is_denied() -> None:
    job_id = uuid4()
    digest = "c" * 64
    approval = ApprovalRecord(
        job_id=job_id,
        patch_sha256=digest,
        decision=ApprovalDecision.REJECT,
        actor="human-reviewer",
    )

    with pytest.raises(PermissionError):
        assert_publish_approved(job_id=job_id, patch_sha256=digest, approval=approval)
