from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel

from .acquire import acquire_job_source
from .models import CodingJob
from .orchestrator import Orchestrator
from .planner import build_execution_plan
from .repository import resolve_github_commit, write_resolution_manifest
from .runtime import DryRunRuntime, OpenShellRuntime
from .sandbox import OpenShellSandboxManager
from .stage import cleanup_staged_source, stage_job_source
from .worker import inspect_worker

app = typer.Typer(no_args_is_help=True, help="Gaia Secure AI Software Engineer")
console = Console()


def _build_job(
    repo: str,
    task: str,
    base_branch: str,
    agent: str,
    timeout: int,
    max_turns: int,
) -> CodingJob:
    return CodingJob(
        repository=repo,
        task=task,
        base_branch=base_branch,
        agent=agent,
        timeout_seconds=timeout,
        max_turns=max_turns,
    )


@app.command()
def doctor(
    agent: Annotated[str, typer.Option("--agent", help="claude or codex")] = "claude",
    policy: Annotated[Path, typer.Option("--policy")] = Path("policies/openshell-mvp.yaml"),
) -> None:
    """Check whether the current machine is ready to act as a secure coding worker."""

    report = inspect_worker(policy, agent=agent)
    rendered = json.dumps(report.model_dump(mode="json"), indent=2, default=str)
    console.print(Panel.fit(rendered, title="Secure Worker Readiness"))
    if not report.ready:
        raise typer.Exit(code=1)


@app.command()
def resolve(
    repo: Annotated[str, typer.Option("--repo", help="GitHub repository URL")],
    base_branch: Annotated[str, typer.Option("--base-branch")] = "main",
    output: Annotated[Path, typer.Option("--output")] = Path("repository.json"),
) -> None:
    """Resolve a mutable GitHub branch to an immutable commit and write a manifest."""

    job = _build_job(repo, "resolve immutable repository base", base_branch, "resolver", 60, 1)
    resolved = resolve_github_commit(job)
    write_resolution_manifest(resolved, output)
    rendered = json.dumps(resolved.model_dump(mode="json"), indent=2, default=str)
    console.print(Panel.fit(rendered, title="Immutable Repository Resolution"))


@app.command()
def acquire(
    repo: Annotated[str, typer.Option("--repo", help="Public GitHub repository URL")],
    base_branch: Annotated[str, typer.Option("--base-branch")] = "main",
    output_dir: Annotated[Path, typer.Option("--output-dir")] = Path("acquired-source"),
) -> None:
    """Resolve and download an immutable source bundle plus trust manifests."""

    job = _build_job(repo, "acquire immutable repository source", base_branch, "acquirer", 120, 1)
    result = acquire_job_source(job, output_dir)
    rendered = json.dumps(result.model_dump(mode="json"), indent=2, default=str)
    console.print(Panel.fit(rendered, title="Immutable Source Acquisition"))


@app.command()
def stage(
    repo: Annotated[str, typer.Option("--repo", help="Public GitHub repository URL")],
    base_branch: Annotated[str, typer.Option("--base-branch")] = "main",
    output_dir: Annotated[Path, typer.Option("--output-dir")] = Path("staged-source"),
    policy: Annotated[Path, typer.Option("--policy")] = Path("policies/openshell-mvp.yaml"),
) -> None:
    """Create an isolated sandbox and upload verified source artifacts without executing code."""

    job = _build_job(repo, "stage immutable repository source", base_branch, "stager", 180, 1)
    manager = OpenShellSandboxManager(policy_path=policy)
    staged = stage_job_source(job, manager, output_dir)

    sandbox_digest = manager.sha256(staged.sandbox_name and __import__("gaia_secure_agent.sandbox", fromlist=["SandboxHandle"]).SandboxHandle(name=staged.sandbox_name), "/sandbox/input/source.tar.gz")
    expected_digest = staged.acquisition.bundle.archive_sha256
    if sandbox_digest != expected_digest:
        cleanup_staged_source(manager, staged.sandbox_name)
        console.print("Staged source digest mismatch; sandbox deleted.")
        raise typer.Exit(code=1)

    payload = staged.model_dump(mode="json")
    payload["sandbox_bundle_sha256"] = sandbox_digest
    payload["digest_verified"] = True
    rendered = json.dumps(payload, indent=2, default=str)
    console.print(Panel.fit(rendered, title="Verified Source Staging"))


@app.command()
def cleanup(
    sandbox: Annotated[str, typer.Option("--sandbox", help="Sandbox name returned by sca stage")],
    policy: Annotated[Path, typer.Option("--policy")] = Path("policies/openshell-mvp.yaml"),
) -> None:
    """Delete one staged OpenShell sandbox by its exact validated name."""

    manager = OpenShellSandboxManager(policy_path=policy)
    cleanup_staged_source(manager, sandbox)
    console.print(f"Deleted sandbox: {sandbox}")


@app.command()
def plan(
    repo: Annotated[str, typer.Option("--repo", help="GitHub repository URL")],
    task: Annotated[str, typer.Option("--task", help="Coding task or issue description")],
    base_branch: Annotated[str, typer.Option("--base-branch")] = "main",
    agent: Annotated[str, typer.Option("--agent")] = "claude",
    timeout: Annotated[int, typer.Option("--timeout")] = 900,
    max_turns: Annotated[int, typer.Option("--max-turns")] = 20,
) -> None:
    """Render the security-constrained execution plan without starting a worker."""

    job = _build_job(repo, task, base_branch, agent, timeout, max_turns)
    execution_plan = build_execution_plan(job)
    rendered = json.dumps(execution_plan.model_dump(mode="json"), indent=2, default=str)
    console.print(Panel.fit(rendered, title="Secure Coding Execution Plan"))


@app.command()
def run(
    repo: Annotated[str, typer.Option("--repo", help="GitHub repository URL")],
    task: Annotated[str, typer.Option("--task", help="Coding task or issue description")],
    base_branch: Annotated[str, typer.Option("--base-branch")] = "main",
    agent: Annotated[str, typer.Option("--agent")] = "dry-run",
    runtime: Annotated[str, typer.Option("--runtime", help="dry-run or openshell")] = "dry-run",
    timeout: Annotated[int, typer.Option("--timeout")] = 900,
    max_turns: Annotated[int, typer.Option("--max-turns")] = 20,
    output: Annotated[Path | None, typer.Option("--output")] = None,
) -> None:
    """Create a bounded coding job and return an execution receipt."""

    job = _build_job(repo, task, base_branch, agent, timeout, max_turns)

    if runtime == "dry-run":
        runtime_impl = DryRunRuntime()
    elif runtime == "openshell":
        runtime_impl = OpenShellRuntime(Path("policies/openshell-mvp.yaml"))
    else:
        raise typer.BadParameter("runtime must be 'dry-run' or 'openshell'")

    receipt = Orchestrator(runtime_impl).run(job)
    rendered = json.dumps(receipt.model_dump(mode="json"), indent=2, default=str)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered + "\n", encoding="utf-8")

    console.print(Panel.fit(rendered, title="Secure Coding Execution Receipt"))

    if receipt.status.value != "succeeded":
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
