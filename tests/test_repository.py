from pathlib import Path

import pytest

from gaia_secure_agent.repository import (
    ResolvedRepository,
    parse_github_repository,
    write_resolution_manifest,
)


def test_parse_exact_github_repository() -> None:
    identity = parse_github_repository("https://github.com/example/project")
    assert identity.owner == "example"
    assert identity.name == "project"


def test_parse_strips_git_suffix() -> None:
    identity = parse_github_repository("https://github.com/example/project.git")
    assert identity.name == "project"


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/example/project",
        "https://example.com/example/project",
        "https://github.com/example/project/issues/1",
        "https://github.com/example",
    ],
)
def test_parse_rejects_noncanonical_repository_urls(url: str) -> None:
    with pytest.raises(ValueError):
        parse_github_repository(url)


def test_resolution_manifest_is_written(tmp_path: Path) -> None:
    resolved = ResolvedRepository(
        owner="example",
        name="project",
        branch="main",
        commit_sha="a" * 40,
        source_url="https://github.com/example/project",
        manifest_sha256="b" * 64,
    )
    path = write_resolution_manifest(resolved, tmp_path / "repository.json")
    text = path.read_text(encoding="utf-8")
    assert '"commit_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' in text
    assert '"manifest_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' in text
