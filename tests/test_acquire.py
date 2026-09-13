from pathlib import Path

from gaia_secure_agent.acquire import acquire_job_source
from gaia_secure_agent.archive_inspect import ArchiveInspection
from gaia_secure_agent.models import CodingJob
from gaia_secure_agent.repository import ResolvedRepository
from gaia_secure_agent.source_bundle import SourceBundle


def test_acquire_job_source_writes_all_manifests(monkeypatch, tmp_path: Path) -> None:
    job = CodingJob(
        repository="https://github.com/example/project",
        task="acquire source",
    )
    resolved = ResolvedRepository(
        owner="example",
        name="project",
        branch="main",
        commit_sha="a" * 40,
        source_url="https://github.com/example/project",
        manifest_sha256="b" * 64,
    )

    monkeypatch.setattr("gaia_secure_agent.acquire.resolve_github_commit", lambda _job: resolved)

    def fake_bundle(_resolved, destination: Path) -> SourceBundle:
        destination.write_bytes(b"bundle")
        return SourceBundle(
            commit_sha="a" * 40,
            archive_path=destination,
            archive_sha256="c" * 64,
            size_bytes=6,
        )

    monkeypatch.setattr("gaia_secure_agent.acquire.acquire_public_source_bundle", fake_bundle)
    monkeypatch.setattr(
        "gaia_secure_agent.acquire.inspect_source_archive",
        lambda _path: ArchiveInspection(
            top_level_root="project-aaaaaaaa",
            member_count=2,
            regular_file_count=1,
            total_uncompressed_bytes=6,
            manifest_sha256="d" * 64,
        ),
    )

    result = acquire_job_source(job, tmp_path / "acquired")

    assert result.resolved.commit_sha == "a" * 40
    assert result.transfer.github_write_allowed is False
    assert result.transfer.credentials_embedded is False
    assert result.bundle.archive_sha256 == "c" * 64
    assert result.inspection.accepted is True
    assert result.repository_manifest.is_file()
    assert result.transfer_manifest.is_file()
    assert result.bundle_manifest.is_file()
    assert result.inspection_manifest.is_file()
    assert result.bundle.archive_path.read_bytes() == b"bundle"
