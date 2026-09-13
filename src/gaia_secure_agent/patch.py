from __future__ import annotations

import hashlib
from pathlib import Path

from pydantic import BaseModel, Field

from .sandbox import OpenShellSandboxManager, SandboxHandle


class PatchArtifact(BaseModel):
    sandbox_name: str
    sandbox_path: str = "/sandbox/output/changes.patch"
    local_path: Path
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0)
    has_changes: bool


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_patch(
    manager: OpenShellSandboxManager,
    *,
    sandbox_name: str,
    output_dir: Path,
    max_bytes: int = 10 * 1024 * 1024,
) -> PatchArtifact:
    if max_bytes < 1:
        raise ValueError("patch size limit must be positive")

    handle = SandboxHandle(name=sandbox_name)
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
        sandbox_name=sandbox_name,
        sandbox_path=sandbox_path,
        local_path=local_path,
        sha256=local_digest,
        size_bytes=size_bytes,
        has_changes=size_bytes > 0,
    )
