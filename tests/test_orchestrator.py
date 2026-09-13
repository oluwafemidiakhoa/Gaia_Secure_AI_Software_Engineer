from pathlib import Path

from gaia_secure_agent.models import CodingJob, JobStatus
from gaia_secure_agent.orchestrator import Orchestrator
from gaia_secure_agent.runtime import DryRunRuntime


def test_dry_run_produces_receipt(tmp_path: Path) -> None:
    job = CodingJob(
        repository="https://github.com/example/project",
        task="Fix issue #42",
    )

    receipt = Orchestrator(DryRunRuntime()).run(job, runs_dir=tmp_path)

    assert receipt.status is JobStatus.SUCCEEDED
    assert receipt.human_approval_required is True
    assert receipt.changed_files == []
    assert any(event.action == "push" and event.decision == "deny" for event in receipt.security_events)
    assert (tmp_path / str(job.id) / "job.json").exists()
