from __future__ import annotations

import json
import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from .models import CodingJob, SecurityEvent, VerificationResult


@dataclass
class RuntimeResult:
    changed_files: list[str]
    verification: list[VerificationResult]
    security_events: list[SecurityEvent]
    patch_path: Path | None
    notes: list[str]


class Runtime(ABC):
    @abstractmethod
    def execute(self, job: CodingJob, workspace: Path) -> RuntimeResult:
        raise NotImplementedError


class DryRunRuntime(Runtime):
    """Safe local runtime that proves orchestration without executing an AI coding agent."""

    def execute(self, job: CodingJob, workspace: Path) -> RuntimeResult:
        workspace.mkdir(parents=True, exist_ok=True)
        request_path = workspace / "job.json"
        request_path.write_text(
            json.dumps(job.model_dump(mode="json"), indent=2, default=str), encoding="utf-8"
        )

        return RuntimeResult(
            changed_files=[],
            verification=[],
            security_events=[
                SecurityEvent(
                    category="control_plane",
                    action="job_materialized",
                    target=str(request_path),
                    decision="allow",
                ),
                SecurityEvent(
                    category="github",
                    action="push",
                    target=str(job.repository),
                    decision="deny",
                    detail="MVP agents cannot push to GitHub",
                ),
            ],
            patch_path=None,
            notes=[
                "Dry-run completed; no repository clone or agent execution occurred.",
                "Use the OpenShell runtime adapter only on a host with a configured OpenShell gateway.",
            ],
        )


class OpenShellRuntime(Runtime):
    """Fail-closed OpenShell CLI adapter."""

    def __init__(self, policy_path: Path) -> None:
        self.policy_path = policy_path

    def execute(self, job: CodingJob, workspace: Path) -> RuntimeResult:
        if shutil.which("openshell") is None:
            raise RuntimeError("openshell CLI is not installed on this worker")
        if not self.policy_path.exists():
            raise RuntimeError(f"OpenShell policy missing: {self.policy_path}")

        probe = subprocess.run(
            ["openshell", "status"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if probe.returncode != 0:
            raise RuntimeError(f"OpenShell gateway is unavailable: {probe.stderr.strip()}")

        raise RuntimeError(
            "OpenShell is reachable, but autonomous execution remains intentionally disabled until "
            "provider credentials and the repository-copy flow are configured."
        )
