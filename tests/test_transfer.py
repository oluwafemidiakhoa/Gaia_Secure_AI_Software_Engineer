import pytest

from gaia_secure_agent.repository import ResolvedRepository
from gaia_secure_agent.transfer import RepositoryTransfer, build_repository_transfer


def _resolved() -> ResolvedRepository:
    return ResolvedRepository(
        owner="example",
        name="project",
        branch="main",
        commit_sha="a" * 40,
        source_url="https://github.com/example/project",
        manifest_sha256="b" * 64,
    )


def test_transfer_is_bound_to_exact_commit() -> None:
    transfer = build_repository_transfer(_resolved())
    assert transfer.commit_sha == "a" * 40
    assert transfer.github_write_allowed is False
    assert transfer.credentials_embedded is False
    assert len(transfer.transfer_sha256) == 64


def test_transfer_digest_changes_with_target_path() -> None:
    first = build_repository_transfer(_resolved(), target_path="/workspace/repository")
    second = build_repository_transfer(_resolved(), target_path="/workspace/other")
    assert first.transfer_sha256 != second.transfer_sha256


@pytest.mark.parametrize("path", ["workspace/repository", "/", "/workspace", "/workspace/../etc"])
def test_transfer_rejects_unsafe_target_path(path: str) -> None:
    with pytest.raises(ValueError):
        RepositoryTransfer(
            owner="example",
            name="project",
            commit_sha="a" * 40,
            source_url="https://github.com/example/project",
            target_path=path,
            transfer_sha256="c" * 64,
        )
