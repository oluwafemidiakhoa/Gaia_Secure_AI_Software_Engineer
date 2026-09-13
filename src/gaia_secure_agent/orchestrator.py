from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from .models import CodingJob, ExecutionReceipt, JobStatus
from .runtime import Runtime
from .security import SecurityPolicy


class Orchestrator:
    def __init__(self, runtime: Runtime, policy: SecurityPolicy | None = None) -> None:
        self.runtime = runtime
        self.policy = policy or SecurityPolicy()

    def run(self, job: CodingJob, runs_dir: Path = Path("runs")) -> ExecutionReceipt:
        self.policy.validate_repository(str(job.repository))
        self.policy.assert_agent_git_write_denied()

        started_at = datetime.now(UTC)
        workspace = runs_dir / str(job.id)

        try:
            result = self.runtime.execute(job, workspace)
            status = JobStatus.SUCCEEDED
        except (PermissionError, RuntimeError, ValueError) as exc:
            return ExecutionReceipt(
                job_id=job.id,
                status=JobStatus.FAILED,
                repository=str(job.repository),
                base_branch=job.base_branch,
                agent=job.agent,
                started_at=started_at,
                finished_at=datetime.now(UTC),
                workspace=workspace,
                notes=[f"runtime failure: {type(exc).__name__}: {exc}"],
            )

        return ExecutionReceipt(
            job_id=job.id,
            status=status,
            repository=str(job.repository),
            base_branch=job.base_branch,
            agent=job.agent,
            started_at=started_at,
            finished_at=datetime.now(UTC),
            workspace=workspace,
            changed_files=result.changed_files,
            verification=result.verification,
            security_events=result.security_events,
            patch_path=result.patch_path,
            notes=result.notes,
        )
