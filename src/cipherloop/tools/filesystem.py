import docker
from typing import List, Optional
from langchain_core.tools import tool

CONTAINER_NAME = "cipherloop-sandbox"
WORKDIR = "/workspace/target_repo"

def _get_docker_client() -> Optional[docker.DockerClient]:
    """Lazy-load the Docker client to avoid import-time crashes."""
    try:
        return docker.from_env()
    except Exception:
        return None

def execute_in_sandbox(cmd_list: List[str]) -> str:
    """
    Executes a command inside the isolated Docker sandbox container.
    Bypasses shell execution (/bin/sh) to prevent injection flaws.
    """
    client = _get_docker_client()
    if client is None:
        return "System Error: Cannot connect to Docker daemon. Is Docker running?"

    try:
        container = client.containers.get(CONTAINER_NAME)
        exit_code, output = container.exec_run(
            cmd=cmd_list,
            workdir=WORKDIR,
            demux=False,
        )
        
        result = output.decode("utf-8", errors="replace").strip()
        if exit_code != 0:
            return f"Tool Execution Error (Code {exit_code}):\n{result}"
            
        return result or "Command executed successfully with no output."
        
    except docker.errors.NotFound:
        return f"System Error: Sandbox container '{CONTAINER_NAME}' is not running."
    except Exception as e:
        return f"System Error: Sandbox execution failed - {str(e)}"


# ---------------------------------------------------------
# LangChain Tool Bindings
# ---------------------------------------------------------

@tool
def list_directory(path: str = ".") -> str:
    """
    Lists the directory tree up to 2 levels deep.
    Use this first to understand folder layout.
    """
    safe_path = path.strip() or "."
    return execute_in_sandbox(["tree", "-L", "2", safe_path])

@tool
def read_file(filepath: str, start_line: int = 1, end_line: int = 100) -> str:
    """
    Reads a line slice from a target file.
    Use to inspect source code snippets without blowing the context window.
    """
    start = max(1, int(start_line))
    end = max(start, int(end_line))
    sed_expr = f"{start},{end}p"
    return execute_in_sandbox(["sed", "-n", sed_expr, filepath.strip()])

@tool
def search_code(query: str, path: str = ".") -> str:
    """
    Searches for a string or regex pattern using ripgrep with line numbers.
    """
    safe_path = path.strip() or "."
    return execute_in_sandbox(["rg", "-n", query.strip(), safe_path])

@tool
def run_semgrep(target_path: str = ".") -> str:
    """
    Runs Semgrep static analysis with the default auto ruleset on a path.
    Returns findings formatted as JSON.
    """
    safe_path = target_path.strip() or "."
    return execute_in_sandbox(["semgrep", "scan", "--config=p/secrets", "--config=p/rce", "--json", safe_path])


SANDBOX_TOOLS = [list_directory, read_file, search_code, run_semgrep]