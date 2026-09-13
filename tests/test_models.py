import pytest
from pydantic import ValidationError

from gaia_secure_agent.models import CodingJob


def test_rejects_non_https_repository() -> None:
    with pytest.raises(ValidationError):
        CodingJob(repository="http://github.com/example/project", task="Fix the bug")


def test_rejects_repository_credentials() -> None:
    with pytest.raises(ValidationError):
        CodingJob(repository="https://user:secret@github.com/example/project", task="Fix the bug")


def test_rejects_unsafe_branch() -> None:
    with pytest.raises(ValidationError):
        CodingJob(
            repository="https://github.com/example/project",
            task="Fix the bug",
            base_branch="../main",
        )


def test_accepts_normal_feature_branch() -> None:
    job = CodingJob(
        repository="https://github.com/example/project",
        task="Fix the bug",
        base_branch="feature/safe-change",
    )
    assert job.base_branch == "feature/safe-change"
