from pathlib import Path
from uuid import UUID

import pytest

from gaia_secure_agent.acquire import AcquisitionResult
from gaia_secure_agent.agent_contract import AgentKind
from gaia_secure_agent.agent_run import AgentRunResult
from gaia_secure_agent.archive_inspect import ArchiveInspection
from gaia_secure_agent.models import CodingJob
from gaia_secure_agent.patch import PatchArtifact
from gaia_secure_agent.prepare import PreparedRepository
from gaia_secure_agent.repository import ResolvedRepository
from gaia_secure_agent.sandbox import SandboxHandle
from gaia_secure_agent.secure_run import secure_autonomous_run
from gaia_secure_agent.source_bundle import SourceBundle
from gaia_secure_agent.stage import StagedSource
from gaia_secure_agent.transfer import RepositoryTransfer


class FakeManager:
    def __init__(self, source_digest: str) -> None:
        self.source_digest = source_digest
        self.deleted: list[str] = []

    def sha256(self, handle: SandboxHandle, path: str) -> str:
        return self.source_digest

    def delete(self, handle: SandboxHandle) -> None:
        self.deleted.append(handle.name)


def _staged(job: CodingJob, tmp_path: Path, source_digest: str) -> StagedSource:
    source_dir = tmp_path / "source"
    source_dir.mkdir(parents=True, exist_ok=True)
    archive = source_dir / "source.tar.gz"
    archive.write_bytes(b"source")
    manifests = []
    for name in ("repository.json", "transfer.json", "bundle.json", "archive-inspection.json"):
        path = source_dir / name
        path.write_text("{}\n", encoding="utf-8")
        manifests.append(path)

    resolved = ResolvedRepository(
        owner="example",
        name="project",
        branch="main",
        commit_sha="a" * 40,
        source_url="https://github.com/example/project",
        manifest_sha256="b" * 64,
    )
    transfer = RepositoryTransfer(
        owner="example",
        name="project",
        commit_sha="a" * 40,
        source_url="https://github.com/example/project",
        transfer_sha256="c" * 64,
    )
    bundle = SourceBundle(
        commit_sha="a" * 40,
        archive_path=archive,
        archive_sha256=source_digest,
        size_bytes=6,
    )
    inspection = ArchiveInspection(
        top_level_root="project-root",
        member_count=1,
        regular_file_count=1,
        total_uncompressed_bytes=6,
        manifest_sha256="d" * 64,
    )
    acquisition = AcquisitionResult(
        resolved=resolved,
        transfer=transfer,
        bundle=bundle,
        inspection=inspection,
        repository_manifest=manifests[0],
        transfer_manifest=manifests[1],
        bundle_manifest=manifests[2],
        inspection_manifest=manifests[3],
    )
    return StagedSource(
        sandbox_name=f"gaia-{job.id.hex[:20]}",
        acquisition=acquisition,
        uploaded_paths=["/sandbox/input/source.tar.gz"],
    )


def test_secure_run_keeps_one_job_identity_and_deletes_sandbox(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    job = CodingJob(
        repository="https://github.com/example/project",
        task="Fix issue #42",
        agent="claude",
    )
    source_digest = "e" * 64
    staged = _staged(job, tmp_path, source_digest)
    manager = FakeManager(source_digest)

    monkeypatch.setattr("gaia_secure_agent.secure_run.stage_job_source", lambda *_args: staged)
    monkeypatch.setattr(
        "gaia_secure_agent.secure_run.prepare_staged_repository",
        lambda *_args, **_kwargs: PreparedRepository(
            sandbox_name=staged.sandbox_name,
            source_sha256=source_digest,
        ),
    )

    def fake_agent(*_args, **kwargs) -> AgentRunResult:
        output_path = tmp_path / "run" / "agent" / "agent-output.txt"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("done", encoding="utf-8")
        return AgentRunResult(
            job_id=job.id,
            sandbox_name=staged.sandbox_name,
            agent=AgentKind.CLAUDE,
            agent_version="2.1.220",
            max_turns=job.max_turns,
            timeout_seconds=job.timeout_seconds,
            output_path=output_path,
            output_sha256="f" * 64,
            output_bytes=4,
        )

    monkeypatch.setattr("gaia_secure_agent.secure_run.run_coding_agent", fake_agent)

    def fake_patch(*_args, **kwargs) -> PatchArtifact:
        patch_path = tmp_path / "run" / "patch" / "changes.patch"
        patch_path.parent.mkdir(parents=True, exist_ok=True)
        patch_path.write_text("patch", encoding="utf-8")
        return PatchArtifact(
            job_id=job.id,
            sandbox_name=staged.sandbox_name,
            local_path=patch_path,
            source_sha256=source_digest,
            baseline_commit="1" * 40,
            sha256="2" * 64,
            size_bytes=5,
            has_changes=True,
        )

    monkeypatch.setattr("gaia_secure_agent.secure_run.collect_patch", fake_patch)

    result = secure_autonomous_run(manager, job=job, output_dir=tmp_path / "run")

    assert result.job_id == job.id
    assert result.agent.job_id == job.id
    assert result.patch.job_id == job.id
    assert result.human_approval_required is True
    assert result.github_write_performed is False
    assert result.run_manifest.is_file()
    assert manager.deleted == [staged.sandbox_name]


def test_secure_run_deletes_sandbox_when_agent_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    job = CodingJob(
        repository="https://github.com/example/project",
        task="Fix issue #42",
        agent="claude",
    )
    source_digest = "e" * 64
    staged = _staged(job, tmp_path, source_digest)
    manager = FakeManager(source_digest)

    monkeypatch.setattr("gaia_secure_agent.secure_run.stage_job_source", lambda *_args: staged)
    monkeypatch.setattr(
        "gaia_secure_agent.secure_run.prepare_staged_repository",
        lambda *_args, **_kwargs: PreparedRepository(
            sandbox_name=staged.sandbox_name,
            source_sha256=source_digest,
        ),
    )

    def fail_agent(*_args, **_kwargs):
        raise RuntimeError("simulated agent failure")

    monkeypatch.setattr("gaia_secure_agent.secure_run.run_coding_agent", fail_agent)

    with pytest.raises(RuntimeError, match="simulated agent failure"):
        secure_autonomous_run(manager, job=job, output_dir=tmp_path / "run")

    assert manager.deleted == [staged.sandbox_name]
    assert not (tmp_path / "run" / "run.json").exists()
