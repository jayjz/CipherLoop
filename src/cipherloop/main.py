import os
import sys
import asyncio
import subprocess
import typer
import json
import time
from pathlib import Path
from dotenv import load_dotenv

from cipherloop.core.state import AuditState
from cipherloop.orchestrator.graph import build_graph

load_dotenv()
app = typer.Typer(help="CipherLoop: Context-Compressed Hybrid Code Auditing Agent")

def check_prerequisites(target_dir: str):
    """Pre-flight checks to fail fast if the environment is misconfigured."""
    typer.echo("🔍 Running pre-flight checks...")
    
    if not Path(target_dir).is_dir():
        typer.echo(f"❌ Error: Target directory '{target_dir}' does not exist.", err=True)
        sys.exit(1)
    typer.echo(f"✅ Target directory found: {target_dir}")

    try:
        subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        typer.echo("✅ Docker daemon is running.")
    except subprocess.CalledProcessError:
        typer.echo("❌ Error: Docker daemon is not running or accessible.", err=True)
        sys.exit(1)

    try:
        subprocess.run(["ollama", "ls"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        typer.echo("✅ Ollama is running.")
    except subprocess.CalledProcessError:
        typer.echo("❌ Error: Ollama is not running. Start it with 'ollama serve'.", err=True)
        sys.exit(1)

def ensure_sandbox_running(target_dir: str):
    """Automatically manages the sandbox container lifecycle."""
    typer.echo("📦 Checking sandbox container status...")
    abs_target = str(Path(target_dir).resolve())
    
    # Check if container is currently running
    result = subprocess.run(
        ["docker", "ps", "-q", "-f", "name=cipherloop-sandbox"],
        capture_output=True, text=True
    )
    
    if not result.stdout.strip():
        typer.echo("⚠️ Sandbox not running. Provisioning now...")
        try:
            # Clean up any previously exited container with the same name
            subprocess.run(["docker", "rm", "-f", "cipherloop-sandbox"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Build the sandbox image
            typer.echo("🔨 Building sandbox image (this may take a minute)...")
            subprocess.run(["docker", "build", "-t", "cipherloop-sandbox-img", "./sandbox"], check=True)
            
            # Run with network none and read-only mount of the target
            subprocess.run([
                "docker", "run", "-d", "--name", "cipherloop-sandbox",
                "--network", "none",
                "-v", f"{abs_target}:/workspace/target_repo:ro",
                "cipherloop-sandbox-img"
            ], check=True)
            typer.echo("✅ Sandbox container started successfully.")
        except subprocess.CalledProcessError:
            typer.echo("❌ Failed to start sandbox. Ensure Docker is running and ./sandbox/Dockerfile is valid.", err=True)
            sys.exit(1)
    else:
        typer.echo("✅ Sandbox container is already running.")

@app.command()
def audit(
    target: str = typer.Argument(..., help="Path to the target codebase directory"),
    plan: str = typer.Option("Find hardcoded secrets and potential SSTI vulnerabilities.", help="Initial high-level audit plan")
):
    """Kick off a CipherLoop audit on a target directory."""
    check_prerequisites(target)
    ensure_sandbox_running(target)
    
    typer.echo("\n🚀 Initializing CipherLoop Graph...")
    abs_target = str(Path(target).resolve())
    
    initial_state: AuditState = {
        "messages": [],
        "current_plan": plan,
        "target_directory": abs_target,
        "compressed_findings": [],
        "active_tool": "",
        "retries": 0
    }
    
    graph = build_graph()
    typer.echo("⏳ Executing audit loop (this may take a few minutes)...\n")
    
    final_state = initial_state
    
    async def run_audit():
        nonlocal final_state
        # stream_mode="values" yields the complete state at each step, making it easy to capture the final snapshot
        async for state_snapshot in graph.astream(initial_state, stream_mode="values"):
            final_state = state_snapshot
            
            # Clean console output for the latest state update
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
    
    # MOVE 3: TraceForge Export
    trace_dir = Path("./traces")
    trace_dir.mkdir(exist_ok=True)
    trace_file = trace_dir / f"audit_trace_{Path(target).name}_{int(time.time())}.json"
    
    typer.echo(f"\n💾 Exporting execution trace to {trace_file} for TraceForge evaluation...")
    
    # Serialize the final state safely (handling non-serializable LangChain objects gracefully)
    serializable_state = {
        "target_directory": final_state.get("target_directory"),
        "final_plan": final_state.get("current_plan"),
        "retries": final_state.get("retries"),
        "compressed_findings": final_state.get("compressed_findings"),
        "message_count": len(final_state.get("messages", []))
    }
    
    with open(trace_file, "w") as f:
        json.dump(serializable_state, f, indent=2, default=str)
        
    typer.echo(f"✅ Audit complete. Trace saved. Review the final report above or in the trace file.")

if __name__ == "__main__":
    app()
