from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID


_SANDBOX_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


@dataclass(frozen=True)
class SandboxHandle:
    name: str


class OpenShellSandboxManager:
    def __init__(
        self,
        *,
        policy_path: Path,
        cpu: str = "2",
        memory: str = "4Gi",
        command_timeout: int = 30,
    ) -> None:
        self.policy_path = policy_path
        self.cpu = cpu
        self.memory = memory
        self.command_timeout = command_timeout

    @staticmethod
    def name_for_job(job_id: UUID) -> str:
        return f"gaia-{job_id.hex[:20]}"

    @staticmethod
    def _validate_name(name: str) -> str:
        if not _SANDBOX_NAME.fullmatch(name):
            raise ValueError("sandbox name contains unsupported characters")
        return name

    def create(self, name: str) -> SandboxHandle:
        self._validate_name(name)
        if not self.policy_path.is_file():
            raise RuntimeError(f"OpenShell policy missing: {self.policy_path}")

        completed = subprocess.run(
            [
                "openshell",
                "sandbox",
                "create",
                "--name",
                name,
                "--detach",
                "--output",
                "json",
                "--policy",
                str(self.policy_path),
                "--cpu",
                self.cpu,
                "--memory",
                self.memory,
            ],
            capture_output=True,
            text=True,
            timeout=self.command_timeout,
            check=False,
        )
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise RuntimeError(f"OpenShell sandbox creation failed: {detail}")

        try:
            payload = json.loads(completed.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise RuntimeError("OpenShell returned invalid JSON for sandbox creation") from exc

        reported_name = payload.get("name")
        if reported_name and reported_name != name:
            raise RuntimeError("OpenShell returned an unexpected sandbox name")
        return SandboxHandle(name=name)

    def upload(self, handle: SandboxHandle, source: Path, destination: str) -> None:
        name = self._validate_name(handle.name)
        if not source.is_file():
            raise ValueError(f"upload source must be a regular file: {source}")
        if not destination.startswith("/sandbox/"):
            raise ValueError("upload destination must stay inside /sandbox")
        if "/../" in f"{destination}/" or destination.endswith("/.."):
            raise ValueError("upload destination cannot traverse parent directories")

        completed = subprocess.run(
            ["openshell", "sandbox", "upload", name, str(source), destination],
            capture_output=True,
            text=True,
            timeout=max(self.command_timeout, 120),
            check=False,
        )
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise RuntimeError(f"OpenShell sandbox upload failed: {detail}")

    def delete(self, handle: SandboxHandle) -> None:
        name = self._validate_name(handle.name)
        completed = subprocess.run(
            ["openshell", "sandbox", "delete", name],
            capture_output=True,
            text=True,
            timeout=self.command_timeout,
            check=False,
        )
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise RuntimeError(f"OpenShell sandbox cleanup failed: {detail}")
