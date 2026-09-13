from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, HttpUrl, field_validator


class JobStatus(StrEnum):
    CREATED = "created"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"


class CodingJob(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    repository: HttpUrl
    task: str = Field(min_length=3, max_length=10_000)
    base_branch: str = Field(default="main", min_length=1, max_length=255)
    agent: str = Field(default="dry-run", min_length=1, max_length=100)
    timeout_seconds: int = Field(default=900, ge=30, le=7200)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("repository")
    @classmethod
    def github_only_for_mvp(cls, value: HttpUrl) -> HttpUrl:
        if value.host not in {"github.com", "www.github.com"}:
            raise ValueError("MVP accepts github.com repositories only")
        return value


class SecurityEvent(BaseModel):
    category: str
    action: str
    target: str | None = None
    decision: str = "allow"
    detail: str | None = None
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class VerificationResult(BaseModel):
    command: str
    exit_code: int
    passed: bool
    output_tail: str = ""


class ExecutionReceipt(BaseModel):
    job_id: UUID
    status: JobStatus
    repository: str
    base_branch: str
    agent: str
    started_at: datetime
    finished_at: datetime
    workspace: Path
    changed_files: list[str] = Field(default_factory=list)
    verification: list[VerificationResult] = Field(default_factory=list)
    security_events: list[SecurityEvent] = Field(default_factory=list)
    patch_path: Path | None = None
    human_approval_required: bool = True
    notes: list[str] = Field(default_factory=list)
