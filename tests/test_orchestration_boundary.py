import json
import uuid
from pathlib import Path
from types import SimpleNamespace

from langchain_core.messages import AIMessage, ToolMessage
from langgraph.graph import END, START, StateGraph

from cipherloop.core.state import AuditState
from cipherloop.core.trajectory import PRODUCTION_CONTRACT_VERSION, TrajectoryRecorder
from cipherloop.executor import local_node
from cipherloop.executor.compressor import compressor_node
from cipherloop.executor.validator import validator_node
from cipherloop.orchestrator import graph as graph_module
from cipherloop.orchestrator import nodes
from cipherloop.tools.filesystem import WORKDIR


class _PlannerModel:
    def __init__(self, instructions: list[str]) -> None:
        self.instructions = iter(instructions)
        self.calls = []

    def with_structured_output(self, _schema):
        return self

    def invoke(self, messages):
        self.calls.append(messages)
        return SimpleNamespace(instruction=next(self.instructions))


def _state(host_target: str, **updates) -> AuditState:
    state = {
        "messages": [],
        "current_plan": "inspect the repository",
        "requested_plan": "Find command injection",
        "target_directory": host_target,
        "plan_history": [],
        "compressed_findings": [],
        "verified_findings": [],
        "active_tool": "",
        "retries": 0,
    }
    state.update(updates)
    return state


def test_planner_uses_logical_container_target_not_host_path(monkeypatch, tmp_path):
    host_target = str((tmp_path / "WindowsTarget").resolve())
    model = _PlannerModel(["search_code for subprocess usage"])
    monkeypatch.setattr(nodes, "get_cloud_llm", lambda **_kwargs: model)

    result = nodes.planner_node(
        _state(host_target, requested_plan=f"Find command injection in {host_target}")
    )

    prompt = "\n".join(message.content for message in model.calls[0])
    assert host_target not in prompt
    assert f"Tactical target root: {WORKDIR}" in prompt
    assert f"Audit objective: Find command injection in {WORKDIR}" in prompt
    assert "isolated Linux container" in prompt
    assert "POSIX paths only" in prompt
    assert "Do not emit PowerShell commands" in prompt
    assert "cmd.exe commands" in prompt
    assert "drive-letter paths" in prompt
    assert "list_directory, read_file, search_code, run_semgrep" in prompt
    assert result["current_plan"] == "search_code for subprocess usage"


def test_repeated_equivalent_windows_plans_have_a_deterministic_bound(monkeypatch, tmp_path):
    model = _PlannerModel(
        [
            r"Get-ChildItem C:\\Users\\target",
            r"  get-childitem   c:\\users\\target  ",
            r"GET-CHILDITEM C:\\USERS\\TARGET",
            r"Get-ChildItem C:\\Users\\target",
        ]
    )
    monkeypatch.setattr(nodes, "get_cloud_llm", lambda **_kwargs: model)
    state = _state(str(tmp_path.resolve()))

    for _ in range(nodes.MAX_IDENTICAL_PLAN_ATTEMPTS):
        result = nodes.planner_node(state)
        assert "terminal_error" not in result
        state["current_plan"] = result["current_plan"]
        state["plan_history"].extend(result["plan_history"])
        state["retries"] = result["retries"]

    result = nodes.planner_node(state)

    assert result["current_plan"] == "AUDIT_COMPLETE"
    assert "terminal_error" in result
    assert "Repeated tactical plan limit" in result["terminal_error"]
    assert len(model.calls) == nodes.MAX_IDENTICAL_PLAN_ATTEMPTS + 1


def test_local_model_prompt_describes_linux_tools_and_posix_target(monkeypatch):
    captured = []

    class _LocalModel:
        def invoke(self, messages):
            captured.extend(messages)
            return AIMessage(content="", tool_calls=[])

    monkeypatch.setattr(local_node, "local_llm", _LocalModel())
    local_node.call_local_model(_state("C:\\Users\\target"))

    prompt = captured[0].content
    assert "isolated Linux sandbox" in prompt
    assert WORKDIR in prompt
    assert "POSIX paths only" in prompt
    assert "PowerShell, cmd.exe, drive-letter paths" in prompt
    assert "list_directory, read_file, search_code, run_semgrep" in prompt


def test_repeated_failed_read_action_is_blocked_after_path_drift(monkeypatch):
    """A repeated failed read is stopped even when a distinct bad path intervenes."""
    from cipherloop.tools import filesystem

    dispatched = []

    def failed_read(command):
        dispatched.append(command)
        return "Tool Execution Error: file does not exist"

    monkeypatch.setattr(filesystem, "execute_in_sandbox", failed_read)
    state = {
        "messages": [],
        "compressed_findings": [],
        "verified_findings": [],
        "action_progress": [],
    }
    tool_graph = StateGraph(AuditState)
    tool_graph.add_node("tools", local_node.execute_sandbox_tools)
    tool_graph.add_edge(START, "tools")
    tool_graph.add_edge("tools", END)
    tool_graph = tool_graph.compile()

    def execute_and_compress(call_id, filepath):
        assistant = AIMessage(
            content="",
            tool_calls=[
                {
                    "id": call_id,
                    "name": "read_file",
                    "args": {"filepath": filepath, "start_line": 1, "end_line": 30},
                }
            ],
        )
        state["messages"] = [assistant]
        tool_state = tool_graph.invoke(state)
        state["messages"] = tool_state["messages"]
        compressed = compressor_node(state)
        state["compressed_findings"].extend(compressed["compressed_findings"])
        state["action_progress"].extend(compressed["action_progress"])
        state["messages"] = []

    execute_and_compress("missing-one", f"{WORKDIR}/_app.py")
    execute_and_compress("missing-drift", f"{WORKDIR}/._app.py")

    repeated = AIMessage(
        content="",
        tool_calls=[
            {
                "id": "missing-repeat",
                "name": "read_file",
                "args": {"filepath": f"{WORKDIR}/_app.py", "start_line": 1, "end_line": 30},
            }
        ],
    )
    state["messages"] = [repeated]
    blocked = tool_graph.invoke(state)

    assert len(dispatched) == 2
    assert blocked["current_plan"] == "AUDIT_COMPLETE"
    assert "Non-progress action blocked" in blocked["terminal_error"]
    blocked_results = [
        message for message in blocked["messages"] if isinstance(message, ToolMessage)
    ]
    assert len(blocked_results) == 1
    assert blocked_results[0].content.startswith("Tool Execution Blocked:")


def test_action_signature_normalizes_safe_posix_paths_but_keeps_distinct_ranges():
    first = local_node.canonical_action_signature(
        {
            "name": "read_file",
            "args": {
                "filepath": f"{WORKDIR}/./app.py",
                "start_line": 1,
                "end_line": 30,
            },
        }
    )
    same_path = local_node.canonical_action_signature(
        {
            "name": "read_file",
            "args": {"filepath": "app.py", "start_line": 1, "end_line": 30},
        }
    )
    later_range = local_node.canonical_action_signature(
        {
            "name": "read_file",
            "args": {"filepath": "app.py", "start_line": 31, "end_line": 60},
        }
    )

    assert first == same_path
    assert first != later_range


def test_production_graph_consumes_fallback_evidence_before_another_tool_dispatch(
    monkeypatch, tmp_path
):
    """A ToolNode result must cross the real compressor and validator before looping."""
    fixture = Path("fixtures/toy/app.py").read_text(encoding="utf-8")
    sink_line = next(
        number
        for number, line in enumerate(fixture.splitlines(), start=1)
        if "subprocess.run" in line
    )
    timeout = "Tool Execution Timeout: Sandbox command exceeded 30 seconds."
    fallback_result = json.dumps(
        {
            "results": [
                {
                    "check_id": "cipherloop.fallback-regex",
                    "path": "app.py",
                    "start": {"line": sink_line},
                    "extra": {
                        "severity": "WARNING",
                        "message": "Fallback regex scanner matched a potentially risky pattern.",
                        "metadata": {"fallback_used": True},
                    },
                }
            ],
            "errors": [],
            "fallback_used": True,
            "original_error": timeout,
        }
    )
    recorder = TrajectoryRecorder(
        run_id=str(uuid.uuid4()),
        output_dir=str(tmp_path),
        contract_version=PRODUCTION_CONTRACT_VERSION,
    )
    recorder.start_run("audit", WORKDIR)
    execution_order: list[str] = []
    local_responses = iter(
        [
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "id": "scan-one",
                        "name": "run_semgrep",
                        "args": {"target_path": WORKDIR},
                    }
                ],
            ),
            # The old ToolNode -> local_model edge consumes this response and dispatches again.
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "id": "scan-two",
                        "name": "run_semgrep",
                        "args": {"target_path": WORKDIR},
                    }
                ],
            ),
            AIMessage(content="analysis complete"),
        ]
    )

    def planner(state):
        return {
            "current_plan": "Run Semgrep for command execution.",
            "plan_history": ["run semgrep for command execution."],
            "messages": [AIMessage(content="Run Semgrep for command execution.")],
            # The retry ceiling supplies a normal graph exit after validation.  The
            # plan itself remains tactical, so the test does not pre-mark completion.
            "retries": state["retries"] + 1,
        }

    def local_model(_state):
        return {"messages": [next(local_responses)]}

    def run_primary(_target_path):
        execution_order.append("tool")
        return timeout

    def run_fallback(_target_path, error):
        assert error == timeout
        return fallback_result

    def observe_compression(state, config=None):
        execution_order.append("compressor")
        return compressor_node(state, config)

    def validate_evidence(state, config=None):
        execution_order.append("validator")
        return validator_node(state, config)

    monkeypatch.setattr(graph_module, "planner_node", planner)
    monkeypatch.setattr(graph_module, "call_local_model", local_model)
    monkeypatch.setattr(graph_module, "compressor_node", observe_compression)
    monkeypatch.setattr(graph_module, "validator_node", validate_evidence)
    monkeypatch.setattr(
        graph_module,
        "synthesizer_node",
        lambda _state: {"messages": [AIMessage(content="final report")]},
    )
    monkeypatch.setattr(local_node, "_run_semgrep", run_primary)
    monkeypatch.setattr(local_node, "_run_fallback_tool", run_fallback)
    monkeypatch.setattr(
        "cipherloop.executor.validator.read_file", SimpleNamespace(invoke=lambda _: fixture)
    )

    final_state = graph_module.build_graph().invoke(
        {
            "messages": [],
            "current_plan": "audit command execution",
            "requested_plan": "audit command execution",
            "target_directory": WORKDIR,
            "plan_history": [],
            "compressed_findings": [],
            "verified_findings": [],
            "active_tool": "",
            "retries": 24,
        },
        {"configurable": {"__trajectory_recorder__": recorder}},
    )
    rows = [
        json.loads(line)
        for line in recorder.trajectory_file.read_text(encoding="utf-8").splitlines()
    ]

    assert execution_order == ["tool", "compressor", "validator"]
    assert final_state["compressed_findings"][0]["scanner_status"] == "fallback"
    assert final_state["compressed_findings"][0]["primary_error"] == timeout
    assert final_state["compressed_findings"][0]["top_findings"] == [
        f"[WARNING] app.py:{sink_line} - Fallback regex scanner matched a potentially risky pattern."
    ]
    assert final_state["verified_findings"][0]["status"] == "VERIFIED"
    assert [row["step_type"] for row in rows] == [
        "run.started",
        "message",
        "message",
        "compression",
        "validation.started",
        "validation.candidate",
        "source.read",
        "validation.decision",
        "validation",
    ]
    decision = rows[-2]["payload"]
    assert decision["disposition"] == "verified"
    assert decision["finding"] == final_state["verified_findings"][0]


def test_production_graph_blocks_repeated_semgrep_after_fallback_evidence(
    monkeypatch, tmp_path
):
    fixture = Path("fixtures/toy/app.py").read_text(encoding="utf-8")
    sink_line = next(
        number
        for number, line in enumerate(fixture.splitlines(), start=1)
        if "subprocess.run" in line
    )
    timeout = "Tool Execution Timeout: Sandbox command exceeded 30 seconds."
    fallback_result = json.dumps(
        {
            "results": [
                {
                    "check_id": "cipherloop.fallback-regex",
                    "path": "app.py",
                    "start": {"line": sink_line},
                    "extra": {
                        "severity": "WARNING",
                        "message": "Fallback regex scanner matched a potentially risky pattern.",
                    },
                }
            ],
            "errors": [],
            "fallback_used": True,
            "original_error": timeout,
        }
    )
    recorder = TrajectoryRecorder(
        run_id=str(uuid.uuid4()),
        output_dir=str(tmp_path),
        contract_version=PRODUCTION_CONTRACT_VERSION,
    )
    recorder.start_run("audit", WORKDIR)
    planner_calls = 0
    primary_calls = []
    local_responses = iter(
        [
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "id": "scan-one",
                        "name": "run_semgrep",
                        "args": {"target_path": WORKDIR},
                    }
                ],
            ),
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "id": "scan-two",
                        "name": "run_semgrep",
                        "args": {"target_path": WORKDIR},
                    }
                ],
            ),
            AIMessage(content="complete"),
        ]
    )

    def planner(state):
        nonlocal planner_calls
        planner_calls += 1
        if planner_calls == 3:
            return {"current_plan": "AUDIT_COMPLETE", "messages": [AIMessage(content="done")]}
        return {
            "current_plan": f"Run Semgrep, wording {planner_calls}.",
            "messages": [AIMessage(content=f"Run Semgrep, wording {planner_calls}.")],
            "retries": state["retries"] + 1,
        }

    monkeypatch.setattr(graph_module, "planner_node", planner)
    monkeypatch.setattr(
        graph_module, "call_local_model", lambda _state: {"messages": [next(local_responses)]}
    )
    monkeypatch.setattr(
        graph_module,
        "synthesizer_node",
        lambda _state: {"messages": [AIMessage(content="final report")]},
    )
    monkeypatch.setattr(
        local_node,
        "_run_semgrep",
        lambda target: primary_calls.append(target) or timeout,
    )
    monkeypatch.setattr(local_node, "_run_fallback_tool", lambda _target, _error: fallback_result)
    monkeypatch.setattr(
        "cipherloop.executor.validator.read_file", SimpleNamespace(invoke=lambda _: fixture)
    )

    final_state = graph_module.build_graph().invoke(
        {
            "messages": [],
            "current_plan": "audit command execution",
            "requested_plan": "audit command execution",
            "target_directory": WORKDIR,
            "plan_history": [],
            "compressed_findings": [],
            "verified_findings": [],
            "action_progress": [],
            "active_tool": "",
            "retries": 0,
        },
        {"configurable": {"__trajectory_recorder__": recorder}},
    )

    assert primary_calls == [WORKDIR]
    assert planner_calls == 2
    assert final_state["compressed_findings"][0]["scanner_status"] == "fallback"
    assert final_state["verified_findings"][0]["status"] == "VERIFIED"
    assert final_state["validated_compression_count"] == 2
    assert "Non-progress action blocked" in final_state["terminal_error"]
    recorder.finish_run(
        "failed",
        {
            "stage": "graph_execution",
            "type": "NonProgressError",
            "message": final_state["terminal_error"],
        },
    )
    recorder.finalize(final_state)
    metadata = json.loads(recorder.metadata_file.read_text(encoding="utf-8"))
    rows = [
        json.loads(line)
        for line in recorder.trajectory_file.read_text(encoding="utf-8").splitlines()
    ]
    assert metadata["execution_status"] == "failed"
    assert any(
        row["step_type"] == "message"
        and row["payload"].get("content", "").startswith("Tool Execution Blocked:")
        for row in rows
    )


def test_terminal_planner_state_bypasses_local_model_and_reaches_synthesizer(monkeypatch):
    calls = []

    monkeypatch.setattr(
        graph_module,
        "planner_node",
        lambda _state: {
            "current_plan": "AUDIT_COMPLETE",
            "terminal_error": "No further tactical work is justified.",
        },
    )
    monkeypatch.setattr(
        graph_module,
        "call_local_model",
        lambda _state: (_ for _ in ()).throw(AssertionError("local model must not run")),
    )
    monkeypatch.setattr(
        graph_module,
        "synthesizer_node",
        lambda state: calls.append(state["terminal_error"])
        or {"messages": [AIMessage(content="final incomplete report")]},
    )

    final_state = graph_module.build_graph().invoke(_state(WORKDIR))

    assert calls == ["No further tactical work is justified."]
    assert final_state["current_plan"] == "AUDIT_COMPLETE"
    assert final_state["terminal_error"] == "No further tactical work is justified."


def test_completed_planner_state_bypasses_local_model_after_empty_validation(monkeypatch):
    calls = []

    monkeypatch.setattr(
        graph_module,
        "planner_node",
        lambda _state: {"current_plan": "AUDIT_COMPLETE"},
    )
    monkeypatch.setattr(
        graph_module,
        "call_local_model",
        lambda _state: (_ for _ in ()).throw(AssertionError("local model must not run")),
    )
    monkeypatch.setattr(
        graph_module,
        "synthesizer_node",
        lambda state: calls.append(state["validated_compression_count"])
        or {"messages": [AIMessage(content="final complete report")]},
    )

    final_state = graph_module.build_graph().invoke(_state(WORKDIR))

    assert calls == [0]
    assert final_state["current_plan"] == "AUDIT_COMPLETE"
