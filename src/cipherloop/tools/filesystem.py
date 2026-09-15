import posixpath

import docker
from langchain_core.tools import tool

CONTAINER_NAME = "cipherloop-sandbox"
WORKDIR = "/workspace/target_repo"
SANDBOX_EXECUTION_TIMEOUT_SECONDS = 30
_TIMEOUT_EXIT_CODES = frozenset({124, 137})
_SEMGREP_ENVIRONMENT = {
    "SEMGREP_SEND_METRICS": "off",
    "SEMGREP_ENABLE_VERSION_CHECK": "0",
}


def _get_docker_client() -> docker.DockerClient | None:
    try:
        return docker.from_env()
    except Exception:  # noqa: BLE001 - preserve the established unavailable-Docker result.
        return None

def _validate_path(filepath: str) -> str:
    """
    Prevents path traversal attacks. 
    Uses posixpath to enforce Linux path rules even on a Windows host.
    """
    # Normalize slashes to POSIX standard
    safe_filepath = filepath.strip().replace("\\", "/")
    
    # Resolve the path strictly within the Linux container context
    clean_path = posixpath.normpath(posixpath.join(WORKDIR, safe_filepath))
    
    # Strict boundary check: Must be exactly the workdir, or start with workdir + "/"
    if not (clean_path == WORKDIR or clean_path.startswith(WORKDIR + "/")):
        raise ValueError(f"Path traversal detected. Access denied for: {filepath}")
        
    return posixpath.relpath(clean_path, WORKDIR)

def _bounded_command(cmd_list: list[str]) -> list[str]:
    """Return a list-form GNU timeout invocation for a sandbox command."""
    return [
        "timeout",
        "--signal=TERM",
        "--kill-after=5s",
        f"{SANDBOX_EXECUTION_TIMEOUT_SECONDS}s",
        *cmd_list,
    ]


def execute_in_sandbox(cmd_list: list[str]) -> str:
    client = _get_docker_client()
    if client is None:
        return "System Error: Cannot connect to Docker daemon. Is Docker running?"

    try:
        environment = _SEMGREP_ENVIRONMENT if cmd_list and cmd_list[0] == "semgrep" else None
        container = client.containers.get(CONTAINER_NAME)
        exit_code, output = container.exec_run(
            cmd=_bounded_command(cmd_list),
            workdir=WORKDIR,
            demux=False,
            environment=environment,
        )
        result = output.decode("utf-8", errors="replace").strip()
        if exit_code in _TIMEOUT_EXIT_CODES:
            return (
                "Tool Execution Timeout: "
                f"Sandbox command exceeded {SANDBOX_EXECUTION_TIMEOUT_SECONDS} seconds."
            )
        if exit_code != 0:
            return f"Tool Execution Error (Code {exit_code}):\n{result}"
        return result or "Command executed successfully with no output."
    except docker.errors.NotFound:
        return f"System Error: Sandbox container '{CONTAINER_NAME}' is not running."
    except Exception as exc:  # noqa: BLE001 - preserve the existing tool error contract.
        return f"System Error: Sandbox execution failed - {exc!s}"

@tool
def list_directory(path: str = ".") -> str:
    """Lists the directory tree up to 2 levels deep."""
    try:
        safe_path = _validate_path(path)
        return execute_in_sandbox(["tree", "-L", "2", safe_path])
    except ValueError as e:
        return str(e)

@tool
def read_file(filepath: str, start_line: int = 1, end_line: int = 100) -> str:
    """Reads a line slice from a target file."""
    try:
        safe_path = _validate_path(filepath)
        start = max(1, int(start_line))
        end = max(start, int(end_line))
        sed_expr = f"{start},{end}p"
        return execute_in_sandbox(["sed", "-n", sed_expr, safe_path])
    except ValueError as e:
        return str(e)

@tool
def search_code(query: str, path: str = ".") -> str:
    """Searches for a string or regex pattern using ripgrep with line numbers."""
    try:
        safe_path = _validate_path(path)
        return execute_in_sandbox(["rg", "-n", query.strip(), safe_path])
    except ValueError as e:
        return str(e)

@tool
def run_semgrep(target_path: str = ".") -> str:
    """Runs Semgrep static analysis with high-signal rulesets."""
    try:
        safe_path = _validate_path(target_path)
        return execute_in_sandbox(["semgrep", "scan", "--config=p/secrets", "--config=p/rce", "--json", safe_path])
    except ValueError as e:
        return str(e)

SANDBOX_TOOLS = [list_directory, read_file, search_code, run_semgrep]
