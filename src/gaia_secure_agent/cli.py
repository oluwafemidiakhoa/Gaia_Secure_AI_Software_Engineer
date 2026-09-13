from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated
from uuid import UUID

import typer
from rich.console import Console
from rich.panel import Panel

from .acquire import acquire_job_source
from .agent_probe import authorize_claude_execution, parse_claude_version
from .agent_run import run_coding_agent
from .approval import ApprovalDecision
from .models import CodingJob
from .orchestrator import Orchestrator
from .patch import collect_patch, write_patch_manifest
from .planner import build_execution_plan
from .prepare import prepare_staged_repository
from .repository import resolve_github_commit, write_resolution_manifest
from .review import create_approval_record, write_approval_record
from .runtime import DryRunRuntime, OpenShellRuntime
from .sandbox import OpenShellSandboxManager, SandboxHandle
from .stage import cleanup_staged_source, stage_job_source
from .worker import inspect_worker

app = typer.Typer(no_args_is_help=True, help="Gaia Secure AI Software Engineer")
console = Console()


def _build_job(repo: str, task: str, base_branch: str, agent: str, timeout: int, max_turns: int) -> CodingJob:
    return CodingJob(repository=repo, task=task, base_branch=base_branch, agent=agent, timeout_seconds=timeout, max_turns=max_turns)


@app.command()
def doctor(agent: Annotated[str, typer.Option("--agent", help="claude or codex")] = "claude", policy: Annotated[Path, typer.Option("--policy")] = Path("policies/openshell-mvp.yaml")) -> None:
    report = inspect_worker(policy, agent=agent)
    console.print(Panel.fit(json.dumps(report.model_dump(mode="json"), indent=2, default=str), title="Secure Worker Readiness"))
    if not report.ready:
        raise typer.Exit(code=1)


@app.command()
def resolve(repo: Annotated[str, typer.Option("--repo")], base_branch: Annotated[str, typer.Option("--base-branch")] = "main", output: Annotated[Path, typer.Option("--output")] = Path("repository.json")) -> None:
    job = _build_job(repo, "resolve immutable repository base", base_branch, "resolver", 60, 1)
    resolved = resolve_github_commit(job)
    write_resolution_manifest(resolved, output)
    console.print(Panel.fit(json.dumps(resolved.model_dump(mode="json"), indent=2, default=str), title="Immutable Repository Resolution"))


@app.command()
def acquire(repo: Annotated[str, typer.Option("--repo")], base_branch: Annotated[str, typer.Option("--base-branch")] = "main", output_dir: Annotated[Path, typer.Option("--output-dir")] = Path("acquired-source")) -> None:
    job = _build_job(repo, "acquire immutable repository source", base_branch, "acquirer", 120, 1)
    result = acquire_job_source(job, output_dir)
    console.print(Panel.fit(json.dumps(result.model_dump(mode="json"), indent=2, default=str), title="Immutable Source Acquisition"))


@app.command()
def stage(repo: Annotated[str, typer.Option("--repo")], base_branch: Annotated[str, typer.Option("--base-branch")] = "main", output_dir: Annotated[Path, typer.Option("--output-dir")] = Path("staged-source"), policy: Annotated[Path, typer.Option("--policy")] = Path("policies/openshell-mvp.yaml")) -> None:
    job = _build_job(repo, "stage immutable repository source", base_branch, "stager", 180, 1)
    manager = OpenShellSandboxManager(policy_path=policy)
    staged = stage_job_source(job, manager, output_dir)
    handle = SandboxHandle(name=staged.sandbox_name)
    sandbox_digest = manager.sha256(handle, "/sandbox/input/source.tar.gz")
    if sandbox_digest != staged.acquisition.bundle.archive_sha256:
        cleanup_staged_source(manager, staged.sandbox_name)
        raise typer.Exit(code=1)
    payload = staged.model_dump(mode="json")
    payload["sandbox_bundle_sha256"] = sandbox_digest
    payload["digest_verified"] = True
    console.print(Panel.fit(json.dumps(payload, indent=2, default=str), title="Verified Source Staging"))


@app.command()
def prepare(sandbox: Annotated[str, typer.Option("--sandbox")], expected_sha256: Annotated[str, typer.Option("--expected-sha256")], policy: Annotated[Path, typer.Option("--policy")] = Path("policies/openshell-mvp.yaml")) -> None:
    manager = OpenShellSandboxManager(policy_path=policy)
    try:
        prepared = prepare_staged_repository(manager, sandbox_name=sandbox, expected_sha256=expected_sha256)
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--expected-sha256") from exc
    except RuntimeError as exc:
        console.print(f"Repository preparation refused: {exc}")
        raise typer.Exit(code=1) from exc
    console.print(Panel.fit(json.dumps(prepared.model_dump(mode="json"), indent=2, default=str), title="Verified Repository Preparation"))


@app.command("probe-agent")
def probe_agent(sandbox: Annotated[str, typer.Option("--sandbox")], policy: Annotated[Path, typer.Option("--policy")] = Path("policies/openshell-mvp.yaml")) -> None:
    manager = OpenShellSandboxManager(policy_path=policy)
    output = manager.claude_version(SandboxHandle(name=sandbox))
    probe = parse_claude_version(output)
    console.print(Panel.fit(json.dumps(probe.model_dump(mode="json"), indent=2, default=str), title="Sandbox Coding Agent Probe"))


@app.command("verify-agent")
def verify_agent(sandbox: Annotated[str, typer.Option("--sandbox")], policy: Annotated[Path, typer.Option("--policy")] = Path("policies/openshell-mvp.yaml")) -> None:
    manager = OpenShellSandboxManager(policy_path=policy)
    handle = SandboxHandle(name=sandbox)
    probe = parse_claude_version(manager.claude_version(handle))
    if not manager.claude_headless_canary(handle):
        console.print("Claude headless canary returned unexpected output; autonomy remains disabled.")
        raise typer.Exit(code=1)
    authorized = authorize_claude_execution(probe, permission_mode_verified=True)
    console.print(Panel.fit(json.dumps(authorized.model_dump(mode="json"), indent=2, default=str), title="Verified Sandbox Coding Agent"))


@app.command("execute-agent")
def execute_agent(
    sandbox: Annotated[str, typer.Option("--sandbox")],
    repo: Annotated[str, typer.Option("--repo")],
    task: Annotated[str, typer.Option("--task")],
    base_branch: Annotated[str, typer.Option("--base-branch")] = "main",
    max_turns: Annotated[int, typer.Option("--max-turns")] = 20,
    timeout: Annotated[int, typer.Option("--timeout")] = 900,
    output_dir: Annotated[Path, typer.Option("--output-dir")] = Path("agent-run"),
    policy: Annotated[Path, typer.Option("--policy")] = Path("policies/openshell-mvp.yaml"),
) -> None:
    """Run one canary-gated Claude coding task without GitHub write authority."""

    job = _build_job(repo, task, base_branch, "claude", timeout, max_turns)
    manager = OpenShellSandboxManager(policy_path=policy)
    try:
        result = run_coding_agent(manager, job=job, sandbox_name=sandbox, output_dir=output_dir)
    except (RuntimeError, ValueError) as exc:
        console.print(f"Agent execution refused: {exc}")
        raise typer.Exit(code=1) from exc
    console.print(Panel.fit(json.dumps(result.model_dump(mode="json"), indent=2, default=str), title="Gated Coding Agent Result"))


@app.command("collect-patch")
def collect_patch_command(
    job_id: Annotated[str, typer.Option("--job-id")],
    sandbox: Annotated[str, typer.Option("--sandbox")],
    source_archive: Annotated[Path, typer.Option("--source-archive")],
    source_sha256: Annotated[str, typer.Option("--source-sha256")],
    output_dir: Annotated[Path, typer.Option("--output-dir")] = Path("patch-artifact"),
    max_bytes: Annotated[int, typer.Option("--max-bytes")] = 10 * 1024 * 1024,
    policy: Annotated[Path, typer.Option("--policy")] = Path("policies/openshell-mvp.yaml"),
) -> None:
    """Reconstruct a trusted post-agent baseline and collect a verified bounded patch."""

    try:
        parsed_job_id = UUID(job_id)
    except ValueError as exc:
        raise typer.BadParameter("job id must be a valid UUID", param_hint="--job-id") from exc
    manager = OpenShellSandboxManager(policy_path=policy)
    try:
        artifact = collect_patch(
            manager,
            job_id=parsed_job_id,
            sandbox_name=sandbox,
            source_archive=source_archive,
            expected_source_sha256=source_sha256,
            output_dir=output_dir,
            max_bytes=max_bytes,
        )
        write_patch_manifest(artifact, output_dir / "patch.json")
    except (RuntimeError, ValueError) as exc:
        console.print(f"Patch collection refused: {exc}")
        raise typer.Exit(code=1) from exc
    console.print(Panel.fit(json.dumps(artifact.model_dump(mode="json"), indent=2, default=str), title="Verified Patch Artifact"))


@app.command("approve-patch")
def approve_patch(
    job_id: Annotated[str, typer.Option("--job-id")],
    patch_sha256: Annotated[str, typer.Option("--patch-sha256")],
    actor: Annotated[str, typer.Option("--actor")],
    decision: Annotated[str, typer.Option("--decision", help="approve or reject")] = "approve",
    note: Annotated[str | None, typer.Option("--note")] = None,
    output: Annotated[Path, typer.Option("--output")] = Path("approval.json"),
) -> None:
    """Record a non-overwritable human decision bound to one exact patch digest."""

    try:
        parsed_job_id = UUID(job_id)
    except ValueError as exc:
        raise typer.BadParameter("job id must be a valid UUID", param_hint="--job-id") from exc
    try:
        parsed_decision = ApprovalDecision(decision)
    except ValueError as exc:
        raise typer.BadParameter("decision must be 'approve' or 'reject'", param_hint="--decision") from exc
    try:
        record = create_approval_record(job_id=parsed_job_id, patch_sha256=patch_sha256, actor=actor, decision=parsed_decision, note=note)
        write_approval_record(record, output)
    except (RuntimeError, ValueError) as exc:
        console.print(f"Approval record refused: {exc}")
        raise typer.Exit(code=1) from exc
    console.print(Panel.fit(json.dumps(record.model_dump(mode="json"), indent=2, default=str), title="Human Patch Decision"))


@app.command()
def cleanup(sandbox: Annotated[str, typer.Option("--sandbox")], policy: Annotated[Path, typer.Option("--policy")] = Path("policies/openshell-mvp.yaml")) -> None:
    manager = OpenShellSandboxManager(policy_path=policy)
    cleanup_staged_source(manager, sandbox)
    console.print(f"Deleted sandbox: {sandbox}")


@app.command()
def plan(repo: Annotated[str, typer.Option("--repo")], task: Annotated[str, typer.Option("--task")], base_branch: Annotated[str, typer.Option("--base-branch")] = "main", agent: Annotated[str, typer.Option("--agent")] = "claude", timeout: Annotated[int, typer.Option("--timeout")] = 900, max_turns: Annotated[int, typer.Option("--max-turns")] = 20) -> None:
    job = _build_job(repo, task, base_branch, agent, timeout, max_turns)
    execution_plan = build_execution_plan(job)
    console.print(Panel.fit(json.dumps(execution_plan.model_dump(mode="json"), indent=2, default=str), title="Secure Coding Execution Plan"))


@app.command()
def run(repo: Annotated[str, typer.Option("--repo")], task: Annotated[str, typer.Option("--task")], base_branch: Annotated[str, typer.Option("--base-branch")] = "main", agent: Annotated[str, typer.Option("--agent")] = "dry-run", runtime: Annotated[str, typer.Option("--runtime")] = "dry-run", timeout: Annotated[int, typer.Option("--timeout")] = 900, max_turns: Annotated[int, typer.Option("--max-turns")] = 20, output: Annotated[Path | None, typer.Option("--output")] = None) -> None:
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
