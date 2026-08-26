import os
import sys
import asyncio
import subprocess
import typer
from pathlib import Path
from dotenv import load_dotenv

from cipherloop.core.state import AuditState
from cipherloop.orchestrator.graph import build_graph

load_dotenv()
app = typer.Typer(help="CipherLoop: Context-Compressed Hybrid Code Auditing Agent")

def check_prerequisites(target_dir: str):
    """Pre-flight checks to fail fast if the environment is misconfigured."""
    typer.echo("🔍 Running pre-flight checks...")
    
    # 1. Check Target Directory
    if not Path(target_dir).is_dir():
        typer.echo(f"❌ Error: Target directory '{target_dir}' does not exist.", err=True)
        sys.exit(1)
    typer.echo(f"✅ Target directory found: {target_dir}")

    # 2. Check Docker Daemon
    try:
        subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        typer.echo("✅ Docker daemon is running.")
    except subprocess.CalledProcessError:
        typer.echo("❌ Error: Docker daemon is not running or accessible.", err=True)
        sys.exit(1)

    # 3. Check Ollama
    try:
        subprocess.run(["ollama", "ls"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        typer.echo("✅ Ollama is running.")
    except subprocess.CalledProcessError:
        typer.echo("❌ Error: Ollama is not running. Start it with 'ollama serve'.", err=True)
        sys.exit(1)

@app.command()
def audit(
    target: str = typer.Argument(..., help="Path to the target codebase directory"),
    plan: str = typer.Option("Find hardcoded secrets and potential SSTI vulnerabilities.", help="Initial high-level audit plan")
):
    """Kick off a CipherLoop audit on a target directory."""
    check_prerequisites(target)
    
    typer.echo("\n🚀 Initializing CipherLoop Graph...")
    
    # Resolve absolute path for the sandbox mount
    abs_target = str(Path(target).resolve())
    
    initial_state: AuditState = {
        "messages": [],
        "current_plan": plan,
        "target_directory": abs_target,
        "compressed_findings": [],
        "active_tool": "",
        "retries": 0
    }
    
    # Build and run the graph
    graph = build_graph()
    
    typer.echo("⏳ Executing audit loop (this may take a few minutes)...\n")
    
    # Use astream to show real-time progress
    async def run_audit():
        async for event in graph.astream(initial_state, stream_mode="updates"):
            for node, output in event.items():
                typer.echo(f"🔄 [Node: {node.upper()}]")
                if "compressed_findings" in output and output["compressed_findings"]:
                    for finding in output["compressed_findings"]:
                        typer.echo(f"   📌 {finding.get('tool')}: {finding.get('critical_findings_count', 'N/A')} findings")
                if "messages" in output and isinstance(output["messages"], list):
                    # Filter out RemoveMessage noise for console output
                    clean_msgs = [m for m in output["messages"] if hasattr(m, "content") and not str(type(m)).endswith("RemoveMessage'>")]
                    if clean_msgs:
                        typer.echo(f"   💬 {clean_msgs[-1].content[:100]}...")
    
    asyncio.run(run_audit())
    typer.echo("\n✅ Audit complete. Check the final state for the synthesized report.")

if __name__ == "__main__":
    app()
