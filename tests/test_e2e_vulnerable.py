import importlib
from pathlib import Path
from types import SimpleNamespace

from langchain_core.messages import AIMessage


def test_vulnerable_fixture_produces_an_ast_verified_report(monkeypatch):
    """The offline graph must carry a Semgrep signal through AST verification."""
    monkeypatch.setenv("CLOUD_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("ANTHROPIC_MODEL", "test-model")
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://localhost:11434")
    monkeypatch.setenv("OLLAMA_MODEL", "test-model")

    import cipherloop.core.llm as llm_module

    importlib.reload(llm_module)
    graph_module = importlib.import_module("cipherloop.orchestrator.graph")
    validator_module = importlib.import_module("cipherloop.executor.validator")
    vulnerable_app = Path("fixtures/toy/app.py").read_text(encoding="utf-8")
    monkeypatch.setattr(
        validator_module,
        "read_file",
        SimpleNamespace(invoke=lambda _: vulnerable_app),
    )

    def planner(state):
        return {
            "current_plan": "AUDIT_COMPLETE",
            "messages": [AIMessage(content="run Semgrep for command execution")],
            "retries": state["retries"] + 1,
        }

    def local_model(_state):
        return {"messages": [AIMessage(content="Semgrep discovered a command-execution sink")]}

    def compressor(_state, config=None):
        return {
            "compressed_findings": [
                {"top_findings": ["[ERROR] app.py:10 - Command injection"]}
            ],
            "messages": [],
        }

    def synthesizer(state):
        finding = state["verified_findings"][0]
        report = (
            "## Verified Vulnerability\n"
            f"{finding['vulnerability_class']}: "
            f"{finding['source']['symbol']} -> {finding['sink']['symbol']}"
        )
        return {
            "messages": [AIMessage(content="--- FINAL REPORT ---\n" + report)],
            "current_plan": "AUDIT_COMPLETE",
        }

    monkeypatch.setattr(graph_module, "planner_node", planner)
    monkeypatch.setattr(graph_module, "call_local_model", local_model)
    monkeypatch.setattr(graph_module, "compressor_node", compressor)
    monkeypatch.setattr(graph_module, "synthesizer_node", synthesizer)

    graph = graph_module.build_graph()
    final_state = graph.invoke(
        {
            "messages": [],
            "current_plan": "audit",
            "target_directory": str(Path("fixtures/toy").resolve()),
            "compressed_findings": [],
            "verified_findings": [],
            "active_tool": "",
            "retries": 0,
        }
    )

    assert final_state["compressed_findings"]
    assert len(final_state["verified_findings"]) == 1
    finding = final_state["verified_findings"][0]
    assert finding["status"] == "VERIFIED"
    assert finding["source"]["symbol"] == "request.args.get"
    assert finding["sink"]["symbol"] == "subprocess.run"
    assert "Command injection" in final_state["messages"][-1].content
