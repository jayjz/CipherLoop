import importlib
from pathlib import Path
from types import SimpleNamespace

from langchain_core.messages import AIMessage


def test_safe_fixture_produces_no_verified_findings_and_a_safe_report(monkeypatch):
    monkeypatch.setenv("CLOUD_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("ANTHROPIC_MODEL", "test-model")
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://localhost:11434")
    monkeypatch.setenv("OLLAMA_MODEL", "test-model")

    import cipherloop.core.llm as llm_module

    importlib.reload(llm_module)
    graph_module = importlib.import_module("cipherloop.orchestrator.graph")
    validator_module = importlib.import_module("cipherloop.executor.validator")
    safe_app = Path("fixtures/safe/app.py").read_text(encoding="utf-8")
    monkeypatch.setattr(
        validator_module,
        "read_file",
        SimpleNamespace(invoke=lambda _: safe_app),
    )

    def planner(state):
        return {
            "current_plan": "AUDIT_COMPLETE",
            "messages": [AIMessage(content="safe audit plan")],
            "retries": state["retries"] + 1,
        }

    def local_model(_state):
        return {"messages": [AIMessage(content="analysis complete")]}

    def compressor(_state, config=None):
        return {
            "compressed_findings": [
                {"top_findings": ["[ERROR] app.py:11 - Possible command execution"]}
            ],
            "messages": [],
        }

    monkeypatch.setattr(graph_module, "planner_node", planner)
    monkeypatch.setattr(graph_module, "call_local_model", local_model)
    monkeypatch.setattr(graph_module, "compressor_node", compressor)

    graph = graph_module.build_graph()
    final_state = graph.invoke(
        {
            "messages": [],
            "current_plan": "audit",
            "target_directory": str(Path("fixtures/safe").resolve()),
            "compressed_findings": [],
            "verified_findings": [],
            "active_tool": "",
            "retries": 0,
        }
    )

    assert final_state["compressed_findings"]
    assert final_state["verified_findings"] == []
    report = final_state["messages"][-1].content
    assert "No verified high-confidence vulnerabilities were found" in report
