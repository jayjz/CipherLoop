import json
import logging
import re
import subprocess
from typing import Any, Literal
from uuid import uuid4

from langchain_core.messages import AIMessage, SystemMessage
from langchain_core.tools import tool
from langgraph.prebuilt import ToolNode
from pydantic import ValidationError

from cipherloop.core.llm import get_local_llm
from cipherloop.core.state import AuditState
from cipherloop.tools.fallback_tool import fallback_result_json
from cipherloop.tools.filesystem import SANDBOX_TOOLS, WORKDIR
from cipherloop.tools.filesystem import run_semgrep as sandbox_semgrep

logger = logging.getLogger(__name__)

local_llm = None

_WINDOWS_HOST_PATH = re.compile(r"^(?:[a-zA-Z]:|[\\/]{2})")
_PATH_ARGUMENT_NAMES = frozenset({"path", "filepath", "target_path"})


def _run_semgrep(target_path: str) -> str:
    """Invoke the original sandbox Semgrep tool behind a testable boundary."""
    return sandbox_semgrep.invoke({"target_path": target_path})


def _semgrep_failure(result: str) -> str | None:
    """Return a crash reason for a failed Semgrep response, if present."""
    if result.startswith(("System Error:", "Tool Execution Error", "Tool Execution Timeout:")):
        return result

    try:
        payload: dict[str, Any] = json.loads(result)
    except (TypeError, json.JSONDecodeError):
        return "Semgrep returned malformed JSON."

    if payload.get("status") == "crash" or payload.get("returncode", 0) not in (0, 1):
        return f"Semgrep process crashed with return code {payload.get('returncode')}"
    if payload.get("error") or payload.get("errors"):
        return f"Semgrep reported errors: {payload.get('error') or payload['errors']}"
    return None


def _run_fallback_tool(target_path: str, error: str) -> str:
    """Run the configured default fallback and preserve the tool JSON contract."""
    return fallback_result_json(target_path, original_error=error)


def _fallback_error_result(original_error: str, fallback_error: Exception) -> str:
    """Return valid structured output even if both scanners are unavailable."""
    return json.dumps(
        {
            "results": [],
            "errors": [{"message": f"Fallback scanner failed: {fallback_error}"}],
            "fallback_used": True,
            "original_error": original_error,
        }
    )


def _use_fallback(target_path: str, exc: Exception) -> str:
    """Log the primary failure and guarantee a structured fallback response."""
    error = str(exc)
    logger.warning("[WARN] Semgrep execution failed/crashed. Invoking fallback tool... %s", error)
    try:
        return _run_fallback_tool(target_path, error)
    except Exception as fallback_exc:  # noqa: BLE001 - preserve a valid tool response.
        logger.warning("Fallback tool failed after Semgrep crash: %s", fallback_exc)
        return _fallback_error_result(error, fallback_exc)


@tool("run_semgrep")
def run_semgrep_with_fallback(target_path: str = ".") -> str:
    """Run Semgrep, falling back to a sandboxed regex scan after a crash."""
    try:
        result = _run_semgrep(target_path)
        failure = _semgrep_failure(result)
        if failure:
            raise RuntimeError(failure)
        return result
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        return _use_fallback(target_path, exc)
    except Exception as exc:  # noqa: BLE001 - the fallback must contain all scanner crashes.
        return _use_fallback(target_path, exc)


def call_local_model(state: AuditState) -> dict:
    plan = state.get("current_plan", "No active plan.")

    system_prompt = SystemMessage(
        content=(
            "You are a tactical security execution agent operating inside an isolated Linux sandbox.\n"
            "Your ONLY purpose is to execute tools to fulfill the current plan.\n"
            f"The target root is {WORKDIR}; use POSIX paths only.\n"
            "Never use PowerShell, cmd.exe, drive-letter paths, or host filesystem paths.\n"
            "Available structured tools: list_directory, read_file, search_code, run_semgrep.\n"
            "Do not explain your reasoning. Do not generate reports. Just call the appropriate tools.\n\n"
            f"CURRENT PLAN:\n{plan}"
        )
    )

    clean_messages = state.get("messages", [])
    response = _normalize_text_tool_call(
        _get_local_llm().invoke([system_prompt] + clean_messages)
    )

    return {"messages": [response]}


# Replace only the primary scanner; all other tools retain their existing names
# and sandbox-only execution behavior.
LOCAL_TOOLS = [tool for tool in SANDBOX_TOOLS if tool.name != "run_semgrep"] + [
    run_semgrep_with_fallback
]
execute_sandbox_tools = ToolNode(LOCAL_TOOLS)


def _get_local_llm():
    """Create the model binding only when the local-execution node is invoked."""
    global local_llm
    if local_llm is None:
        local_llm = get_local_llm(temperature=0.1).bind_tools(LOCAL_TOOLS)
    return local_llm


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _is_windows_host_path(value: str) -> bool:
    """Reject drive-letter and UNC paths before they reach a Linux sandbox tool."""
    return bool(_WINDOWS_HOST_PATH.match(value))


def _validated_text_tool_call(content: object) -> dict[str, Any] | None:
    """Convert only the observed Ollama JSON tool-call shape into a ToolNode call.

    Some Ollama models emit a JSON object as assistant text despite receiving native
    tool definitions. This is intentionally not a general-purpose parser: prose,
    fenced JSON, multiple calls, unknown fields, unknown tools, malformed JSON, and
    invalid arguments all remain ordinary assistant text.
    """
    if not isinstance(content, str):
        return None

    try:
        payload = json.loads(content, object_pairs_hook=_reject_duplicate_json_keys)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None

    if not isinstance(payload, dict) or set(payload) != {"name", "arguments"}:
        return None
    tool_name = payload["name"]
    arguments = payload["arguments"]
    if not isinstance(tool_name, str) or not isinstance(arguments, dict):
        return None

    selected_tool = next((item for item in LOCAL_TOOLS if item.name == tool_name), None)
    if selected_tool is None or selected_tool.args_schema is None:
        return None

    schema = selected_tool.args_schema.model_json_schema()
    allowed_arguments = set(schema.get("properties", {}))
    if set(arguments) - allowed_arguments:
        return None
    if any(
        name in _PATH_ARGUMENT_NAMES
        and isinstance(value, str)
        and _is_windows_host_path(value)
        for name, value in arguments.items()
    ):
        return None

    try:
        validated_arguments = selected_tool.args_schema.model_validate(arguments).model_dump()
    except ValidationError:
        return None

    return {
        "id": f"compat-{uuid4()}",
        "name": tool_name,
        "args": validated_arguments,
        "type": "tool_call",
    }


def _normalize_text_tool_call(response: AIMessage) -> AIMessage:
    """Preserve native calls and normalize one strictly validated text call, if any."""
    if response.tool_calls:
        return response

    tool_call = _validated_text_tool_call(response.content)
    if tool_call is None:
        return response
    return response.model_copy(update={"tool_calls": [tool_call]})


def route_local_execution(state: AuditState) -> Literal["execute_sandbox_tools", "compressor_node"]:
    last_message = state["messages"][-1]
    if hasattr(last_message, "tool_calls") and last_message.tool_calls:
        return "execute_sandbox_tools"
    return "compressor_node"
