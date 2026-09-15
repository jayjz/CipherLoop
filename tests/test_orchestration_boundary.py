from types import SimpleNamespace

from langchain_core.messages import AIMessage

from cipherloop.core.state import AuditState
from cipherloop.executor import local_node
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
