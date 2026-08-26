import os
import sys
import asyncio
import subprocess
import typer
import uuid
import time
from pathlib import Path
from dotenv import load_dotenv

from cipherloop.core.state import AuditState
from cipherloop.orchestrator.graph import build_graph
from cipherloop.core.trajectory import TrajectoryRecorder

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

def ensure_sandbox_running(target_dir: str):
    typer.echo("📦 Checking sandbox container status...")
    abs_target = str(Path(target_dir).resolve())
    
    result = subprocess.run(
        ["docker", "ps", "-q", "-f", "name=cipherloop-sandbox"],
        capture_output=True, text=True
    )
    
    if not result.stdout.strip():
        typer.echo("⚠️ Sandbox not running. Provisioning now...")
        try:
            subprocess.run(["docker", "rm", "-f", "cipherloop-sandbox"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["docker", "build", "-t", "cipherloop-sandbox-img", "./sandbox"], check=True)
            subprocess.run([
                "docker", "run", "-d", "--name", "cipherloop-sandbox",
                "--network", "none",
                "-v", f"{abs_target}:/workspace/target_repo:ro",
                "cipherloop-sandbox-img"
            ], check=True)
            typer.echo("✅ Sandbox container started successfully.")
        except subprocess.CalledProcessError:
            typer.echo("❌ Failed to start sandbox.", err=True)
            sys.exit(1)
    else:
        typer.echo("✅ Sandbox container is already running.")

@app.command()
def audit(
    target: str = typer.Argument(..., help="Path to the target codebase directory"),
    plan: str = typer.Option("Find hardcoded secrets and potential remote code execution vulnerabilities.", help="Initial high-level audit plan")
):
    """Kick off a CipherLoop audit on a target directory."""
    check_prerequisites(target)
    ensure_sandbox_running(target)
    
    typer.echo("\n🚀 Initializing CipherLoop Graph...")
    abs_target = str(Path(target).resolve())
    
    # 1. Initialize the Trajectory Recorder
    run_id = str(uuid.uuid4())[:8]
    recorder = TrajectoryRecorder(run_id=run_id)
    
    # 2. Inject recorder into graph config
    config = {"configurable": {"__trajectory_recorder__": recorder}}
    
    initial_state: AuditState = {
        "messages": [],
        "current_plan": plan,
        "target_directory": abs_target,
        "compressed_findings": [],
        "active_tool": "",
        "retries": 0
    }
    
    graph = build_graph()
    typer.echo(f"⏳ Executing audit loop [Run ID: {run_id}]...\n")
    
    final_state = initial_state
    
    async def run_audit():
        nonlocal final_state
        # Pass the config to astream so the compressor_node can access the recorder
        async for state_snapshot in graph.astream(initial_state, config=config, stream_mode="values"):
            final_state = state_snapshot
            
            msgs = state_snapshot.get("messages", [])
            if msgs:
                last_msg = msgs[-1]
                if hasattr(last_msg, "content") and not str(type(last_msg)).endswith("RemoveMessage'>"):
                    content_preview = str(last_msg.content)[:100].replace('\n', ' ')
                    typer.echo(f"🔄 State updated: {content_preview}...")
            
            findings = state_snapshot.get("compressed_findings", [])
            if findings:
                typer.echo(f"   📌 Compressor: {len(findings)} total finding batches processed.")
    
    asyncio.run(run_audit())
    
    # 3. Finalize the TraceForge trajectory ledger
    recorder.finalize(final_state)
    typer.echo(f"\n✅ Audit complete. Trajectory and metadata saved to {recorder.output_dir}")

if __name__ == "__main__":
    app()
