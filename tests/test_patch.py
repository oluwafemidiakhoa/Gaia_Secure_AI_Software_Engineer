import hashlib
from pathlib import Path

import pytest

from gaia_secure_agent.patch import collect_patch
from gaia_secure_agent.sandbox import SandboxHandle


class FakeManager:
    def __init__(self, patch: bytes, source_digest: str, *, patch_digest: str | None = None) -> None:
        self.patch = patch
        self.source_digest = source_digest
        self.patch_digest = patch_digest or hashlib.sha256(patch).hexdigest()
        self.downloaded = False
        self.uploaded_source = False
        self.baseline_built = False

    def upload(self, handle: SandboxHandle, source: Path, destination: str) -> None:
        assert destination == "/sandbox/input/original-after-agent.tar.gz"
        self.uploaded_source = True

    def sha256(self, handle: SandboxHandle, path: str) -> str:
        if path == "/sandbox/input/original-after-agent.tar.gz":
            return self.source_digest
        return self.patch_digest

    def prepare_patch_baseline(self, handle: SandboxHandle, source_path: str) -> str:
        assert source_path == "/sandbox/input/original-after-agent.tar.gz"
        self.baseline_built = True
        return "b" * 40

    def materialize_patch(self, handle: SandboxHandle) -> str:
        return "/sandbox/output/changes.patch"

    def file_size(self, handle: SandboxHandle, path: str) -> int:
        return len(self.patch)

    def download(self, handle: SandboxHandle, source: str, destination: Path) -> Path:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(self.patch)
        self.downloaded = True
        return destination


def _source_archive(tmp_path: Path) -> tuple[Path, str]:
    path = tmp_path / "source.tar.gz"
    path.write_bytes(b"trusted-source")
    return path, hashlib.sha256(b"trusted-source").hexdigest()


def test_collect_patch_reconstructs_trusted_baseline(tmp_path: Path) -> None:
    source, source_digest = _source_archive(tmp_path)
    patch = b"diff --git a/a.txt b/a.txt\n"
    manager = FakeManager(patch, source_digest)

    result = collect_patch(
        manager,
        sandbox_name="gaia-test",
        source_archive=source,
        expected_source_sha256=source_digest,
        output_dir=tmp_path / "out",
    )

    assert manager.uploaded_source is True
    assert manager.baseline_built is True
    assert result.source_sha256 == source_digest
    assert result.baseline_commit == "b" * 40
    assert result.size_bytes == len(patch)
    assert result.sha256 == hashlib.sha256(patch).hexdigest()
    assert result.has_changes is True


def test_collect_patch_refuses_changed_control_plane_source(tmp_path: Path) -> None:
    source, source_digest = _source_archive(tmp_path)
    source.write_bytes(b"tampered")
    manager = FakeManager(b"patch", source_digest)

    with pytest.raises(RuntimeError, match="control-plane source archive digest changed"):
        collect_patch(
            manager,
            sandbox_name="gaia-test",
            source_archive=source,
            expected_source_sha256=source_digest,
            output_dir=tmp_path / "out",
        )

    assert manager.uploaded_source is False


def test_collect_patch_refuses_oversized_patch(tmp_path: Path) -> None:
    source, source_digest = _source_archive(tmp_path)
    manager = FakeManager(b"123456", source_digest)

    with pytest.raises(RuntimeError, match="size limit"):
        collect_patch(
            manager,
            sandbox_name="gaia-test",
            source_archive=source,
            expected_source_sha256=source_digest,
            output_dir=tmp_path / "out",
            max_bytes=5,
        )

    assert manager.downloaded is False


def test_collect_patch_deletes_mismatched_download(tmp_path: Path) -> None:
    source, source_digest = _source_archive(tmp_path)
    manager = FakeManager(b"patch", source_digest, patch_digest="a" * 64)

    with pytest.raises(RuntimeError, match="digest"):
        collect_patch(
            manager,
            sandbox_name="gaia-test",
            source_archive=source,
            expected_source_sha256=source_digest,
            output_dir=tmp_path / "out",
        )

    assert not (tmp_path / "out" / "changes.patch").exists()
