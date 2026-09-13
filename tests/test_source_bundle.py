from io import BytesIO
from pathlib import Path

import pytest

from gaia_secure_agent.repository import ResolvedRepository
from gaia_secure_agent.source_bundle import acquire_public_source_bundle


def _resolved() -> ResolvedRepository:
    return ResolvedRepository(
        owner="example",
        name="project",
        branch="main",
        commit_sha="a" * 40,
        source_url="https://github.com/example/project",
        manifest_sha256="b" * 64,
    )


def test_source_bundle_hashes_exact_bytes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "gaia_secure_agent.source_bundle.urllib.request.urlopen",
        lambda *_args, **_kwargs: BytesIO(b"trusted-source"),
    )
    destination = tmp_path / "source.tar.gz"
    bundle = acquire_public_source_bundle(_resolved(), destination)

    assert destination.read_bytes() == b"trusted-source"
    assert bundle.size_bytes == len(b"trusted-source")
    assert bundle.archive_sha256 == "991650c3475e0f1cde99965ce6a0ac2fe64c43b2fa5bd41c938c8e80f15ef02f"


def test_source_bundle_enforces_size_limit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        "gaia_secure_agent.source_bundle.urllib.request.urlopen",
        lambda *_args, **_kwargs: BytesIO(b"123456"),
    )
    destination = tmp_path / "source.tar.gz"

    with pytest.raises(RuntimeError, match="size limit"):
        acquire_public_source_bundle(_resolved(), destination, max_bytes=5)

    assert not destination.exists()
    assert not (tmp_path / "source.tar.gz.part").exists()
