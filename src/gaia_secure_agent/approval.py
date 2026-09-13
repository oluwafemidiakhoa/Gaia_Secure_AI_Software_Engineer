from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, Field


class ApprovalDecision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"


class ApprovalRecord(BaseModel):
    job_id: UUID
    patch_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision: ApprovalDecision
    actor: str = Field(min_length=1, max_length=200)
    decided_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    note: str | None = Field(default=None, max_length=2000)


def assert_publish_approved(
    *,
    job_id: UUID,
    patch_sha256: str,
    approval: ApprovalRecord,
) -> None:
    if approval.job_id != job_id:
        raise PermissionError("approval belongs to a different coding job")
    if approval.patch_sha256 != patch_sha256:
        raise PermissionError("approval does not match the exact patch digest")
    if approval.decision is not ApprovalDecision.APPROVE:
        raise PermissionError("patch publication has not been approved")
