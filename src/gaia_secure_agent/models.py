from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, HttpUrl, field_validator


_SAFE_BRANCH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")


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
    agent: str = Field(default="claude", min_length=1, max_length=100)
    timeout_seconds: int = Field(default=900, ge=30, le=7200)
    max_turns: int = Field(default=20, ge=1, le=100)
    verification_commands: list[str] = Field(default_factory=list, max_length=10)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("repository")
    @classmethod
    def github_only_for_mvp(cls, value: HttpUrl) -> HttpUrl:
        if value.scheme != "https":
            raise ValueError("MVP requires HTTPS repository URLs")
        if value.host not in {"github.com", "www.github.com"}:
            raise ValueError("MVP accepts github.com repositories only")
        if value.username or value.password:
            raise ValueError("repository URL must not contain credentials")
        if value.port not in {None, 443}:
            raise ValueError("repository URL must use the standard HTTPS port")
        if value.query or value.fragment:
            raise ValueError("repository URL must not contain a query string or fragment")
        return value

    @field_validator("base_branch")
    @classmethod
    def validate_branch(cls, value: str) -> str:
        if not _SAFE_BRANCH.fullmatch(value):
            raise ValueError("base branch contains unsupported characters")
        if ".." in value or "//" in value or value.endswith(("/", ".")):
            raise ValueError("base branch is not a safe Git ref")
        return value

    @field_validator("verification_commands")
    @classmethod
    def validate_verification_commands(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for command in value:
            command = command.strip()
            if not command:
                raise ValueError("verification commands cannot be empty")
            if len(command) > 500:
                raise ValueError("verification command exceeds 500 characters")
            cleaned.append(command)
        return cleaned


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
    base_commit: str | None = None
    agent: str
    started_at: datetime
    finished_at: datetime
    workspace: Path
    changed_files: list[str] = Field(default_factory=list)
    verification: list[VerificationResult] = Field(default_factory=list)
    security_events: list[SecurityEvent] = Field(default_factory=list)
    patch_path: Path | None = None
    patch_sha256: str | None = None
    agent_output_path: Path | None = None
    human_approval_required: bool = True
    notes: list[str] = Field(default_factory=list)
