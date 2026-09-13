from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel

from .acquire import AcquisitionResult, acquire_job_source
from .models import CodingJob
from .sandbox import OpenShellSandboxManager, SandboxHandle


class StagedSource(BaseModel):
    sandbox_name: str
    acquisition: AcquisitionResult
    uploaded_paths: list[str]


def stage_job_source(
    job: CodingJob,
    manager: OpenShellSandboxManager,
    output_dir: Path,
) -> StagedSource:
    acquisition = acquire_job_source(job, output_dir)
    sandbox_name = manager.name_for_job(job.id)
    handle = manager.create(sandbox_name)

    uploads = [
        (acquisition.bundle.archive_path, "/sandbox/input/source.tar.gz"),
        (acquisition.repository_manifest, "/sandbox/input/repository.json"),
        (acquisition.transfer_manifest, "/sandbox/input/transfer.json"),
        (acquisition.bundle_manifest, "/sandbox/input/bundle.json"),
    ]

    uploaded: list[str] = []
    try:
        for source, destination in uploads:
            manager.upload(handle, source, destination)
            uploaded.append(destination)
    except (OSError, RuntimeError, ValueError):
        manager.delete(handle)
        raise

    return StagedSource(
        sandbox_name=handle.name,
        acquisition=acquisition,
        uploaded_paths=uploaded,
    )


def cleanup_staged_source(manager: OpenShellSandboxManager, sandbox_name: str) -> None:
    manager.delete(SandboxHandle(name=sandbox_name))
