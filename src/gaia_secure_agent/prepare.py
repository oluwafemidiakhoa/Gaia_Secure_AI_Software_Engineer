from __future__ import annotations

import re

from pydantic import BaseModel, Field

from .sandbox import OpenShellSandboxManager, SandboxHandle


_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class PreparedRepository(BaseModel):
    sandbox_name: str
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    repository_path: str = "/sandbox/repository"
    prepared: bool = True


def prepare_staged_repository(
    manager: OpenShellSandboxManager,
    *,
    sandbox_name: str,
    expected_sha256: str,
) -> PreparedRepository:
    expected = expected_sha256.strip().lower()
    if not _SHA256.fullmatch(expected):
        raise ValueError("expected source SHA-256 must be exactly 64 lowercase hexadecimal characters")

    handle = SandboxHandle(name=sandbox_name)
    actual = manager.sha256(handle, "/sandbox/input/source.tar.gz")
    if actual != expected:
        raise RuntimeError("staged source digest does not match the expected control-plane digest")

    manager.prepare_repository(handle)
    return PreparedRepository(
        sandbox_name=sandbox_name,
        source_sha256=actual,
    )
