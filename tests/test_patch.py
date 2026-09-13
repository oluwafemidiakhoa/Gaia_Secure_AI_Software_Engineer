import hashlib
from pathlib import Path

import pytest

from gaia_secure_agent.patch import collect_patch
from gaia_secure_agent.sandbox import SandboxHandle


class FakeManager:
    def __init__(self, patch: bytes, *, sandbox_digest: str | None = None) -> None:
        self.patch = patch
        self.sandbox_digest = sandbox_digest or hashlib.sha256(patch).hexdigest()
        self.downloaded = False

    def materialize_patch(self, handle: SandboxHandle) -> str:
        return "/sandbox/output/changes.patch"

    def file_size(self, handle: SandboxHandle, path: str) -> int:
        return len(self.patch)

    def sha256(self, handle: SandboxHandle, path: str) -> str:
        return self.sandbox_digest

    def download(self, handle: SandboxHandle, source: str, destination: Path) -> Path:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(self.patch)
        self.downloaded = True
        return destination


def test_collect_patch_verifies_size_and_digest(tmp_path: Path) -> None:
    patch = b"diff --git a/a.txt b/a.txt\n"
    manager = FakeManager(patch)

    result = collect_patch(manager, sandbox_name="gaia-test", output_dir=tmp_path)

    assert result.size_bytes == len(patch)
    assert result.sha256 == hashlib.sha256(patch).hexdigest()
    assert result.has_changes is True
    assert result.local_path.read_bytes() == patch


def test_collect_patch_refuses_oversized_patch(tmp_path: Path) -> None:
    manager = FakeManager(b"123456")

    with pytest.raises(RuntimeError, match="size limit"):
        collect_patch(
            manager,
            sandbox_name="gaia-test",
            output_dir=tmp_path,
            max_bytes=5,
        )

    assert manager.downloaded is False


def test_collect_patch_deletes_mismatched_download(tmp_path: Path) -> None:
    manager = FakeManager(b"patch", sandbox_digest="a" * 64)

    with pytest.raises(RuntimeError, match="digest"):
        collect_patch(manager, sandbox_name="gaia-test", output_dir=tmp_path)

    assert not (tmp_path / "changes.patch").exists()
