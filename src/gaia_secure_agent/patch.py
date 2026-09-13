from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from uuid import UUID

from pydantic import BaseModel, Field

from .sandbox import OpenShellSandboxManager, SandboxHandle


_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class PatchArtifact(BaseModel):
    job_id: UUID
    sandbox_name: str
    sandbox_path: str = "/sandbox/output/changes.patch"
    local_path: Path
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    baseline_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0)
    has_changes: bool


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_patch_manifest(artifact: PatchArtifact, path: Path) -> Path:
    if path.exists():
        raise RuntimeError(f"patch manifest already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(artifact.model_dump(mode="json"), indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )
    return path


def collect_patch(
    manager: OpenShellSandboxManager,
    *,
    job_id: UUID,
    sandbox_name: str,
    source_archive: Path,
    expected_source_sha256: str,
    output_dir: Path,
    max_bytes: int = 10 * 1024 * 1024,
) -> PatchArtifact:
    if max_bytes < 1:
        raise ValueError("patch size limit must be positive")
    expected_source = expected_source_sha256.strip().lower()
    if not _SHA256.fullmatch(expected_source):
        raise ValueError("expected source SHA-256 must be exactly 64 hexadecimal characters")
    if not source_archive.is_file():
        raise ValueError(f"trusted source archive does not exist: {source_archive}")
    if _file_sha256(source_archive) != expected_source:
        raise RuntimeError("control-plane source archive digest changed before patch collection")

    handle = SandboxHandle(name=sandbox_name)
    manager.reset_post_agent_control(handle)

    trusted_source_path = "/sandbox/input/original-after-agent.tar.gz"
    manager.upload(handle, source_archive, trusted_source_path)
    if manager.sha256(handle, trusted_source_path) != expected_source:
        raise RuntimeError("re-uploaded source archive digest does not match trusted source")

    baseline_commit = manager.prepare_patch_baseline(handle, trusted_source_path)
    sandbox_path = manager.materialize_patch(handle)
    size_bytes = manager.file_size(handle, sandbox_path)
    if size_bytes > max_bytes:
        raise RuntimeError("patch exceeds the control-plane size limit")

    sandbox_digest = manager.sha256(handle, sandbox_path)
    local_path = output_dir / "changes.patch"
    manager.download(handle, sandbox_path, local_path)

    if local_path.stat().st_size != size_bytes:
        local_path.unlink(missing_ok=True)
        raise RuntimeError("downloaded patch size does not match sandbox patch size")

    local_digest = _file_sha256(local_path)
    if local_digest != sandbox_digest:
        local_path.unlink(missing_ok=True)
        raise RuntimeError("downloaded patch digest does not match sandbox patch digest")

    return PatchArtifact(
        job_id=job_id,
        sandbox_name=sandbox_name,
        sandbox_path=sandbox_path,
        local_path=local_path,
        source_sha256=expected_source,
        baseline_commit=baseline_commit,
        sha256=local_digest,
        size_bytes=size_bytes,
        has_changes=size_bytes > 0,
    )
