import asyncio
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

import typer
from dotenv import load_dotenv

from cipherloop.core.state import AuditState
from cipherloop.core.trajectory import PRODUCTION_CONTRACT_VERSION, TrajectoryRecorder

load_dotenv()
app = typer.Typer(help="CipherLoop: Context-Compressed Hybrid Code Auditing Agent")

def check_prerequisites(target_dir: str):
    typer.echo("🔍 Running pre-flight checks...")
    if not Path(target_dir).is_dir():
        typer.echo(f"❌ Error: Target directory '{target_dir}' does not exist.", err=True)
        sys.exit(1)
    typer.echo(f"✅ Target directory found: {target_dir}")

    try:
        subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except subprocess.CalledProcessError:
        typer.echo("❌ Error: Docker daemon is not running or accessible.", err=True)
        sys.exit(1)

    try:
        subprocess.run(["ollama", "ls"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except subprocess.CalledProcessError:
        typer.echo("❌ Error: Ollama is not running. Start it with 'ollama serve'.", err=True)
        sys.exit(1)

def _sandbox_mount_matches(container_id: str, target_dir: str) -> bool:
    """Return whether the named sandbox mounts exactly the requested target."""
    inspection = subprocess.run(
        ["docker", "inspect", container_id], capture_output=True, text=True
    )
    if inspection.returncode != 0:
        return False

    try:
        mounts = json.loads(inspection.stdout)[0].get("Mounts", [])
    except (IndexError, TypeError, json.JSONDecodeError):
        return False

    expected = os.path.normcase(os.path.normpath(target_dir))
    for mount in mounts:
        if mount.get("Destination") != "/workspace/target_repo":
            continue
        source = mount.get("Source")
        if source and os.path.normcase(os.path.normpath(source)) == expected:
            return True
    return False


def _provision_sandbox(abs_target: str) -> None:
    typer.echo("⚠️ Sandbox needs provisioning.")
    subprocess.run(["docker", "build", "-t", "cipherloop-sandbox-img", "./sandbox"], check=True)
    subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            "cipherloop-sandbox",
            "--network",
            "none",
            "-v",
            f"{abs_target}:/workspace/target_repo:ro",
            "cipherloop-sandbox-img",
        ],
        check=True,
    )
    typer.echo("✅ Sandbox container started successfully.")


def ensure_sandbox_running(target_dir: str):
    typer.echo("📦 Checking sandbox container status...")
    abs_target = str(Path(target_dir).resolve())
    
    result = subprocess.run(
        ["docker", "ps", "-q", "-f", "name=cipherloop-sandbox"],
        capture_output=True, text=True
    )
    
    container_id = result.stdout.strip()

    if container_id and _sandbox_mount_matches(container_id, abs_target):
        typer.echo("✅ Sandbox container is already running.")
        return

    try:
        if container_id:
            typer.echo("⚠️ Sandbox target differs; replacing stale container.")
            subprocess.run(["docker", "rm", "-f", "cipherloop-sandbox"], check=True)
        else:
            subprocess.run(
                ["docker", "rm", "-f", "cipherloop-sandbox"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        _provision_sandbox(abs_target)
    except subprocess.CalledProcessError:
        typer.echo("❌ Failed to start sandbox.", err=True)
        sys.exit(1)

def _lifecycle_error(stage: str, exc: BaseException) -> dict[str, str]:
    return {
        "stage": stage,
        "type": type(exc).__name__,
        "message": str(exc) or type(exc).__name__,
    }


def _record_failed_lifecycle(
    recorder: TrajectoryRecorder,
    final_state: AuditState,
    execution_status: str,
    error: dict[str, str],
) -> None:
    """Best-effort failure capture that never replaces the original failure."""
    try:
        recorder.finish_run(execution_status, error)
        recorder.finalize(final_state)
    except Exception as capture_error:  # noqa: BLE001 - retain the original failure.
        typer.echo(f"Production evidence capture failed: {capture_error}", err=True)


@app.command()
def audit(
    target: str = typer.Argument(..., help="Path to the target codebase directory"),
    plan: str = typer.Option("Find hardcoded secrets and remote code execution vulnerabilities.", help="Initial high-level audit plan")
):
    """Kick off a CipherLoop audit on a target directory."""
    typer.echo("\n🚀 Initializing CipherLoop Graph...")
    abs_target = str(Path(target).resolve())
    
    run_id = str(uuid.uuid4())
    recorder = TrajectoryRecorder(
        run_id=run_id,
        contract_version=PRODUCTION_CONTRACT_VERSION,
    )
    config = {"configurable": {"__trajectory_recorder__": recorder}}
    
    initial_state: AuditState = {
        "messages": [],
        "current_plan": plan,
        "target_directory": abs_target,
        "compressed_findings": [],
        "verified_findings": [],
        "active_tool": "",
        "retries": 0
    }
    
    final_state = initial_state
    
    async def run_audit():
        nonlocal final_state
        async for state_snapshot in graph.astream(initial_state, config=config, stream_mode="values"):
            final_state = state_snapshot
            
            msgs = state_snapshot.get("messages", [])
            if msgs:
                last_msg = msgs[-1]
                if hasattr(last_msg, "content") and not str(type(last_msg)).endswith("RemoveMessage'>"):
                    content_preview = str(last_msg.content)[:100].replace('\n', ' ')
                    typer.echo(f"🔄 State updated: {content_preview}...")
            
            verified = [v for v in state_snapshot.get("verified_findings", []) if v.get("status") == "VERIFIED"]
            if verified:
                typer.echo(f"   🛡️ Verified Findings Count: {len(verified)}")
    
    recorder.start_run(task_description=plan, target_directory=abs_target)
    stage = "preflight"
    try:
        check_prerequisites(target)
        stage = "sandbox_setup"
        ensure_sandbox_running(target)

        stage = "graph_build"
        from cipherloop.orchestrator.graph import build_graph

        graph = build_graph()
        typer.echo(f"⏳ Executing audit loop [Run ID: {run_id}]...\n")
        stage = "graph_execution"
        asyncio.run(run_audit())
    except (KeyboardInterrupt, asyncio.CancelledError) as exc:
        _record_failed_lifecycle(
            recorder,
            final_state,
            "interrupted",
            _lifecycle_error(stage, exc),
        )
        raise
    except (Exception, SystemExit) as exc:
        _record_failed_lifecycle(
            recorder,
            final_state,
            "failed",
            _lifecycle_error(stage, exc),
        )
        raise

    recorder.finish_run("completed", None)
    recorder.finalize(final_state)
    typer.echo(f"\n✅ Audit complete. Trajectory and metadata saved to {recorder.output_dir}")

if __name__ == "__main__":
    app()
