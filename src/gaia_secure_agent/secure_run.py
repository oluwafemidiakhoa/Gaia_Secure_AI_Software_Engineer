from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

from pydantic import BaseModel

from .agent_run import AgentRunResult, run_coding_agent
from .models import CodingJob
from .patch import PatchArtifact, collect_patch, write_patch_manifest
from .prepare import PreparedRepository, prepare_staged_repository
from .sandbox import OpenShellSandboxManager, SandboxHandle
from .stage import StagedSource, stage_job_source


class SecureRunResult(BaseModel):
    job_id: UUID
    sandbox_name: str
    staged: StagedSource
    prepared: PreparedRepository
    agent: AgentRunResult
    patch: PatchArtifact
    run_manifest: Path
    human_approval_required: bool = True
    github_write_performed: bool = False
    sandbox_deleted: bool = True


def _write_run_manifest(result: dict[str, object], path: Path) -> Path:
    if path.exists():
        raise RuntimeError(f"secure run manifest already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    return path


def secure_autonomous_run(
    manager: OpenShellSandboxManager,
    *,
    job: CodingJob,
    output_dir: Path,
    patch_max_bytes: int = 10 * 1024 * 1024,
) -> SecureRunResult:
    if output_dir.exists() and any(output_dir.iterdir()):
        raise RuntimeError(f"secure run output directory is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    staged: StagedSource | None = None
    try:
        staged = stage_job_source(job, manager, output_dir / "source")
        handle = SandboxHandle(name=staged.sandbox_name)
        expected_source = staged.acquisition.bundle.archive_sha256
        if manager.sha256(handle, "/sandbox/input/source.tar.gz") != expected_source:
            raise RuntimeError("staged source digest does not match acquired source")

        prepared = prepare_staged_repository(
            manager,
            sandbox_name=staged.sandbox_name,
            expected_sha256=expected_source,
        )
        agent = run_coding_agent(
            manager,
            job=job,
            sandbox_name=staged.sandbox_name,
            output_dir=output_dir / "agent",
        )
        patch = collect_patch(
            manager,
            job_id=job.id,
            sandbox_name=staged.sandbox_name,
            source_archive=staged.acquisition.bundle.archive_path,
            expected_source_sha256=expected_source,
            output_dir=output_dir / "patch",
            max_bytes=patch_max_bytes,
        )
        write_patch_manifest(patch, output_dir / "patch" / "patch.json")

        manifest_payload = {
            "job_id": str(job.id),
            "repository": str(job.repository),
            "base_branch": job.base_branch,
            "sandbox_name": staged.sandbox_name,
            "source_commit": staged.acquisition.resolved.commit_sha,
            "source_sha256": expected_source,
            "agent": agent.model_dump(mode="json"),
            "patch": patch.model_dump(mode="json"),
            "human_approval_required": True,
            "github_write_performed": False,
        }
        run_manifest = _write_run_manifest(manifest_payload, output_dir / "run.json")
    finally:
        if staged is not None:
            manager.delete(SandboxHandle(name=staged.sandbox_name))

    return SecureRunResult(
        job_id=job.id,
        sandbox_name=staged.sandbox_name,
        staged=staged,
        prepared=prepared,
        agent=agent,
        patch=patch,
        run_manifest=run_manifest,
    )
