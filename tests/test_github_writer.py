import hashlib
from pathlib import Path
from uuid import UUID

import pytest

from gaia_secure_agent.github_writer import execute_publication_handoff
from gaia_secure_agent.publication_handoff import PublicationHandoff


JOB_ID = UUID("12345678-1234-5678-1234-567812345678")
BASE_COMMIT = "a" * 40


class FakeWriter:
    def __init__(self, observed_base: str = BASE_COMMIT) -> None:
        self.observed_base = observed_base
        self.calls: list[tuple] = []

    def get_branch_head(self, repository: str, branch: str) -> str:
        self.calls.append(("get_branch_head", repository, branch))
        return self.observed_base

    def create_branch(self, repository: str, branch: str, base_commit: str) -> None:
        self.calls.append(("create_branch", repository, branch, base_commit))

    def apply_patch(
        self,
        repository: str,
        branch: str,
        patch_path: Path,
        expected_sha256: str,
    ) -> None:
        self.calls.append(("apply_patch", repository, branch, patch_path, expected_sha256))

    def open_draft_pull_request(
        self,
        repository: str,
        *,
        head_branch: str,
        base_branch: str,
        title: str,
        body: str,
    ) -> str:
        self.calls.append(
            (
                "open_draft_pull_request",
                repository,
                head_branch,
                base_branch,
                title,
                body,
            )
        )
        return "https://github.com/example/project/pull/1"


def _handoff(tmp_path: Path) -> PublicationHandoff:
    patch = tmp_path / "changes.patch"
    patch_bytes = b"diff --git a/a.txt b/a.txt\n"
    patch.write_bytes(patch_bytes)
    return PublicationHandoff(
        job_id=JOB_ID,
        repository="https://github.com/example/project",
        base_branch="main",
        base_commit=BASE_COMMIT,
        head_branch="gaia-secure/12345678123456781234",
        title="Gaia secure agent patch 12345678",
        patch_path=patch,
        patch_sha256=hashlib.sha256(patch_bytes).hexdigest(),
        evidence_sha256="d" * 64,
        approved_by="reviewer",
    )


def test_trusted_writer_creates_draft_pr_in_fixed_order(tmp_path: Path) -> None:
    writer = FakeWriter()
    handoff = _handoff(tmp_path)

    outcome = execute_publication_handoff(writer, handoff)

    assert [call[0] for call in writer.calls] == [
        "get_branch_head",
        "create_branch",
        "apply_patch",
        "open_draft_pull_request",
    ]
    assert outcome.pull_request_url.endswith("/pull/1")
    assert outcome.draft is True
    assert outcome.auto_merge_performed is False
    assert outcome.agent_github_write_performed is False


def test_trusted_writer_refuses_moved_base_before_any_write(tmp_path: Path) -> None:
    writer = FakeWriter(observed_base="e" * 40)

    with pytest.raises(PermissionError, match="base branch moved"):
        execute_publication_handoff(writer, _handoff(tmp_path))

    assert [call[0] for call in writer.calls] == ["get_branch_head"]


def test_trusted_writer_refuses_modified_patch_before_any_write(tmp_path: Path) -> None:
    writer = FakeWriter()
    handoff = _handoff(tmp_path)
    handoff.patch_path.write_bytes(b"tampered")

    with pytest.raises(PermissionError, match="patch changed"):
        execute_publication_handoff(writer, handoff)

    assert writer.calls == []


def test_trusted_writer_refuses_auto_merge_flag(tmp_path: Path) -> None:
    writer = FakeWriter()
    handoff = _handoff(tmp_path).model_copy(update={"auto_merge_allowed": True})

    with pytest.raises(PermissionError, match="auto-merge"):
        execute_publication_handoff(writer, handoff)

    assert writer.calls == []
