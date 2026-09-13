import pytest

from gaia_secure_agent.prepare import prepare_staged_repository
from gaia_secure_agent.sandbox import SandboxHandle


class FakeManager:
    def __init__(self, digest: str) -> None:
        self.digest = digest
        self.prepared: list[str] = []
        self.baselines: list[str] = []

    def sha256(self, handle: SandboxHandle, path: str) -> str:
        assert path == "/sandbox/input/source.tar.gz"
        return self.digest

    def prepare_repository(self, handle: SandboxHandle) -> None:
        self.prepared.append(handle.name)

    def initialize_git_baseline(self, handle: SandboxHandle) -> str:
        self.baselines.append(handle.name)
        return "c" * 40


def test_prepare_requires_matching_digest() -> None:
    digest = "a" * 64
    manager = FakeManager(digest)

    result = prepare_staged_repository(
        manager,
        sandbox_name="gaia-test",
        expected_sha256=digest,
    )

    assert result.prepared is True
    assert result.repository_path == "/sandbox/repository"
    assert result.source_sha256 == digest
    assert result.baseline_commit == "c" * 40
    assert manager.prepared == ["gaia-test"]
    assert manager.baselines == ["gaia-test"]


def test_prepare_refuses_digest_mismatch() -> None:
    manager = FakeManager("b" * 64)

    with pytest.raises(RuntimeError, match="digest"):
        prepare_staged_repository(
            manager,
            sandbox_name="gaia-test",
            expected_sha256="a" * 64,
        )

    assert manager.prepared == []
    assert manager.baselines == []


def test_prepare_rejects_invalid_expected_digest() -> None:
    manager = FakeManager("a" * 64)

    with pytest.raises(ValueError, match="SHA-256"):
        prepare_staged_repository(
            manager,
            sandbox_name="gaia-test",
            expected_sha256="not-a-digest",
        )

    assert manager.prepared == []
    assert manager.baselines == []
