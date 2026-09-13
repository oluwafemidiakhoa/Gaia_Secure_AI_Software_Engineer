import pytest

from gaia_secure_agent.security import SecurityPolicy


def test_github_repository_is_allowed() -> None:
    SecurityPolicy().validate_repository("https://github.com/example/project")


def test_non_github_repository_is_denied() -> None:
    with pytest.raises(PermissionError):
        SecurityPolicy().validate_repository("https://example.com/project")


def test_agent_github_writes_are_denied_by_default() -> None:
    SecurityPolicy().assert_agent_git_write_denied()


def test_enabling_agent_push_breaks_mvp_invariant() -> None:
    with pytest.raises(PermissionError):
        SecurityPolicy(allow_agent_push=True).assert_agent_git_write_denied()
