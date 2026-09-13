from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel

from .models import CodingJob
from .orchestrator import Orchestrator
from .planner import build_execution_plan
from .runtime import DryRunRuntime, OpenShellRuntime
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
