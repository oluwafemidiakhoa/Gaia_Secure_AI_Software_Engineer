from pathlib import Path
from uuid import UUID

import pytest

from gaia_secure_agent.acquire import AcquisitionResult
from gaia_secure_agent.archive_inspect import ArchiveInspection
from gaia_secure_agent.models import CodingJob
from gaia_secure_agent.repository import ResolvedRepository
from gaia_secure_agent.sandbox import SandboxHandle
from gaia_secure_agent.source_bundle import SourceBundle
from gaia_secure_agent.stage import stage_job_source
from gaia_secure_agent.transfer import RepositoryTransfer


class FakeManager:
    def __init__(self, *, fail_on_upload: int | None = None) -> None:
        self.fail_on_upload = fail_on_upload
        self.uploads: list[tuple[str, str]] = []
        self.deleted: list[str] = []

    @staticmethod
    def name_for_job(job_id: UUID) -> str:
        return f"gaia-{job_id.hex[:20]}"

    def create(self, name: str) -> SandboxHandle:
        return SandboxHandle(name=name)

    def upload(self, handle: SandboxHandle, source: Path, destination: str) -> None:
        self.uploads.append((str(source), destination))
        if self.fail_on_upload == len(self.uploads):
            raise RuntimeError("simulated upload failure")

    def delete(self, handle: SandboxHandle) -> None:
        self.deleted.append(handle.name)


def _acquisition(tmp_path: Path) -> AcquisitionResult:
    output_dir = tmp_path / "acquired"
    output_dir.mkdir()
    repository_manifest = output_dir / "repository.json"
    transfer_manifest = output_dir / "transfer.json"
    bundle_manifest = output_dir / "bundle.json"
    inspection_manifest = output_dir / "archive-inspection.json"
    archive = output_dir / "source.tar.gz"
    for path in (
        repository_manifest,
        transfer_manifest,
        bundle_manifest,
        inspection_manifest,
    ):
        path.write_text("{}\n", encoding="utf-8")
    archive.write_bytes(b"bundle")

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
        target_path="/sandbox/repository",
        transfer_sha256="d" * 64,
    )
    bundle = SourceBundle(
        commit_sha="a" * 40,
        archive_path=archive,
        archive_sha256="c" * 64,
        size_bytes=6,
    )
    inspection = ArchiveInspection(
        top_level_root="project-aaaaaaaa",
        member_count=2,
        regular_file_count=1,
        total_uncompressed_bytes=6,
        manifest_sha256="e" * 64,
    )
    return AcquisitionResult(
        resolved=resolved,
        transfer=transfer,
        bundle=bundle,
        inspection=inspection,
        repository_manifest=repository_manifest,
        transfer_manifest=transfer_manifest,
        bundle_manifest=bundle_manifest,
        inspection_manifest=inspection_manifest,
    )


def test_stage_uploads_only_expected_artifacts(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    acquisition = _acquisition(tmp_path)
    monkeypatch.setattr("gaia_secure_agent.stage.acquire_job_source", lambda *_args: acquisition)
    manager = FakeManager()
    job = CodingJob(repository="https://github.com/example/project", task="stage source")

    staged = stage_job_source(job, manager, tmp_path / "unused")

    assert staged.sandbox_name.startswith("gaia-")
    assert [destination for _, destination in manager.uploads] == [
        "/sandbox/input/source.tar.gz",
        "/sandbox/input/repository.json",
        "/sandbox/input/transfer.json",
        "/sandbox/input/bundle.json",
    ]
    assert manager.deleted == []


def test_stage_deletes_sandbox_on_upload_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    acquisition = _acquisition(tmp_path)
    monkeypatch.setattr("gaia_secure_agent.stage.acquire_job_source", lambda *_args: acquisition)
    manager = FakeManager(fail_on_upload=2)
    job = CodingJob(repository="https://github.com/example/project", task="stage source")

    with pytest.raises(RuntimeError, match="simulated upload failure"):
        stage_job_source(job, manager, tmp_path / "unused")

    assert manager.deleted == [manager.name_for_job(job.id)]
