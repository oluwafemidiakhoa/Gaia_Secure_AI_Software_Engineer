from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel

from .models import CodingJob
from .orchestrator import Orchestrator
from .runtime import DryRunRuntime, OpenShellRuntime

app = typer.Typer(no_args_is_help=True, help="Gaia Secure AI Software Engineer")
console = Console()


@app.command()
def run(
    repo: Annotated[str, typer.Option("--repo", help="GitHub repository URL")],
    task: Annotated[str, typer.Option("--task", help="Coding task or issue description")],
    base_branch: Annotated[str, typer.Option("--base-branch")] = "main",
    agent: Annotated[str, typer.Option("--agent")] = "dry-run",
    runtime: Annotated[str, typer.Option("--runtime", help="dry-run or openshell")] = "dry-run",
    timeout: Annotated[int, typer.Option("--timeout")] = 900,
    output: Annotated[Path | None, typer.Option("--output")] = None,
) -> None:
    """Create a bounded coding job and return an execution receipt."""

    job = CodingJob(
        repository=repo,
        task=task,
        base_branch=base_branch,
        agent=agent,
        timeout_seconds=timeout,
    )

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
