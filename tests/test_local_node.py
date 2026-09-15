import json
import subprocess
import uuid

from langchain_core.messages import AIMessage, ToolMessage
from langgraph.graph import END, START, StateGraph

from cipherloop.core.state import AuditState
from cipherloop.core.trajectory import PRODUCTION_CONTRACT_VERSION, TrajectoryRecorder
from cipherloop.executor import local_node
from cipherloop.executor.compressor import compressor_node
from cipherloop.tools import filesystem


def test_semgrep_success_does_not_trigger_fallback(monkeypatch):
    success = '{"results": [], "errors": []}'
    monkeypatch.setattr(local_node, "_run_semgrep", lambda path: success)
    monkeypatch.setattr(
        local_node,
        "_run_fallback_tool",
        lambda path, error: (_ for _ in ()).throw(AssertionError()),
    )

    assert local_node.run_semgrep_with_fallback.invoke({"target_path": "."}) == success


def test_semgrep_crash_triggers_fallback(monkeypatch):
    monkeypatch.setattr(
        local_node,
        "_run_semgrep",
        lambda path: (_ for _ in ()).throw(subprocess.CalledProcessError(2, "semgrep")),
    )
    monkeypatch.setattr(
        local_node,
        "_run_fallback_tool",
        lambda path, error: json.dumps(
            {"results": [], "fallback_used": True, "original_error": error}
        ),
    )

    result = json.loads(local_node.run_semgrep_with_fallback.invoke({"target_path": "src"}))
    assert result["fallback_used"] is True
    assert "returned non-zero exit status 2" in result["original_error"]


def test_semgrep_timeout_triggers_fallback(monkeypatch):
    monkeypatch.setattr(
        local_node,
        "_run_semgrep",
        lambda path: "Tool Execution Timeout: Sandbox command exceeded 30 seconds.",
    )
    monkeypatch.setattr(
        local_node,
        "_run_fallback_tool",
        lambda path, error: json.dumps({"results": [], "fallback_used": True}),
    )

    assert (
        json.loads(local_node.run_semgrep_with_fallback.invoke({"target_path": "."}))[
            "fallback_used"
        ]
        is True
    )


def test_semgrep_timeout_fallback_reaches_tool_message_and_compressor(monkeypatch):
    monkeypatch.setattr(
        local_node,
        "_run_semgrep",
        lambda path: "Tool Execution Timeout: Sandbox command exceeded 30 seconds.",
    )
    monkeypatch.setattr(
        local_node,
        "_run_fallback_tool",
        lambda path, error: json.dumps(
            {
                "results": [],
                "errors": [],
                "fallback_used": True,
                "original_error": error,
            }
        ),
    )

    assistant = AIMessage(
        content="",
        tool_calls=[{"id": "scan", "name": "run_semgrep", "args": {"target_path": "."}}],
    )
    graph = StateGraph(AuditState)
    graph.add_node("tools", local_node.execute_sandbox_tools)
    graph.add_edge(START, "tools")
    graph.add_edge("tools", END)
    tool_message = graph.compile().invoke({"messages": [assistant]})["messages"][-1]

    assert isinstance(tool_message, ToolMessage)
    assert json.loads(tool_message.content)["original_error"] == (
        "Tool Execution Timeout: Sandbox command exceeded 30 seconds."
    )
    compressed = compressor_node(
        {"messages": [assistant, tool_message], "compressed_findings": []}
    )["compressed_findings"][0]
    assert compressed["scanner_status"] == "fallback"
    assert compressed["primary_error"].startswith("Tool Execution Timeout:")
    assert compressed["total_findings"] == 0


def test_both_tools_fail_gracefully(monkeypatch):
    monkeypatch.setattr(
        local_node, "_run_semgrep", lambda path: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    monkeypatch.setattr(
        local_node,
        "_run_fallback_tool",
        lambda path, error: (_ for _ in ()).throw(RuntimeError("fallback boom")),
    )

    result = json.loads(local_node.run_semgrep_with_fallback.invoke({"target_path": "."}))
    assert result["results"] == []
    assert result["fallback_used"] is True
    assert "fallback boom" in result["errors"][0]["message"]


def test_native_tool_calls_still_route_to_tool_node():
    message = AIMessage(
        content="",
        tool_calls=[{"id": "native-1", "name": "list_directory", "args": {"path": "."}}],
    )

    assert local_node._normalize_text_tool_call(message) is message
    assert local_node.route_local_execution({"messages": [message]}) == "execute_sandbox_tools"


def test_plain_text_does_not_route_to_tool_node():
    message = AIMessage(content="I would inspect the repository next.")

    normalized = local_node._normalize_text_tool_call(message)

    assert normalized.tool_calls == []
    assert local_node.route_local_execution({"messages": [normalized]}) == "compressor_node"


def test_valid_ollama_json_text_becomes_a_schema_valid_tool_call():
    message = AIMessage(
        content='{"name": "search_code", "arguments": {"query": "subprocess", "path": "."}}'
    )

    normalized = local_node._normalize_text_tool_call(message)

    assert normalized.tool_calls[0]["name"] == "search_code"
    assert normalized.tool_calls[0]["args"] == {"query": "subprocess", "path": "."}
    assert normalized.tool_calls[0]["id"].startswith("compat-")
    assert local_node.route_local_execution({"messages": [normalized]}) == "execute_sandbox_tools"


def test_invalid_ollama_json_text_never_routes_to_tool_node():
    rejected_contents = [
        '{"name": "unknown_tool", "arguments": {}}',
        '{"name": "list_directory", "arguments":',
        '{"name": "shell", "arguments": {"command": "powershell -Command whoami"}}',
        '{"name": "read_file", "arguments": {"filepath": "C:\\\\Users\\\\target\\\\secret.py"}}',
        '{"name": "search_code", "arguments": {"query": "x", "unexpected": true}}',
    ]

    for content in rejected_contents:
        normalized = local_node._normalize_text_tool_call(AIMessage(content=content))
        assert normalized.tool_calls == []
        assert local_node.route_local_execution({"messages": [normalized]}) == "compressor_node"


def test_call_local_model_normalizes_observed_ollama_text_shape(monkeypatch):
    class _TextOnlyToolModel:
        def invoke(self, _messages):
            return AIMessage(
                content='{"name": "list_directory", "arguments": {"path": "/workspace/target_repo"}}'
            )

    monkeypatch.setattr(local_node, "local_llm", _TextOnlyToolModel())
    state = {"messages": [], "current_plan": "inspect the repository"}

    response = local_node.call_local_model(state)["messages"][0]

    assert response.tool_calls[0]["name"] == "list_directory"
    assert response.tool_calls[0]["args"] == {"path": "/workspace/target_repo"}


def test_tool_node_output_reaches_compressor_with_full_production_observation(monkeypatch, tmp_path):
    monkeypatch.setattr(filesystem, "execute_in_sandbox", lambda _command: "sandbox listing")
    recorder = TrajectoryRecorder(
        run_id=str(uuid.uuid4()),
        output_dir=str(tmp_path),
        contract_version=PRODUCTION_CONTRACT_VERSION,
    )
    recorder.start_run("audit", "/target")
    assistant = local_node._normalize_text_tool_call(
        AIMessage(content='{"name": "list_directory", "arguments": {"path": "."}}')
    )

    graph = StateGraph(AuditState)
    graph.add_node("tools", local_node.execute_sandbox_tools)
    graph.add_edge(START, "tools")
    graph.add_edge("tools", END)
    tool_message = graph.compile().invoke({"messages": [assistant]})["messages"][-1]
    assert isinstance(tool_message, ToolMessage)
    assert tool_message.content == "sandbox listing"

    compressed = compressor_node(
        {"messages": [assistant, tool_message], "compressed_findings": []},
        {"configurable": {"__trajectory_recorder__": recorder}},
    )
    rows = [
        json.loads(line)
        for line in recorder.trajectory_file.read_text(encoding="utf-8").splitlines()
    ]
    messages = [row["payload"] for row in rows if row["step_type"] == "message"]
    compression = next(row["payload"] for row in rows if row["step_type"] == "compression")

    assert messages[0]["role"] == "assistant"
    assert messages[0]["tool_calls"][0]["name"] == "list_directory"
    assert messages[1]["role"] == "tool"
    assert compression["finding"] == compressed["compressed_findings"][0]
    assert compression["finding"]["raw_char_count"] > 0
    assert compression["finding"]["compressed_char_count"] > 0
