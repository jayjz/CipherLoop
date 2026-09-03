import pytest
from langchain_core.messages import ToolMessage, AIMessage
from cipherloop.executor.compressor import compressor_node, process_semgrep_output, process_generic_tool

def test_process_semgrep_output_parses_and_ranks():
    raw_json = """{
        "results": [
            {"path": "app.py", "start": {"line": 10}, "extra": {"severity": "ERROR", "message": "Command injection"}},
            {"path": "config.py", "start": {"line": 5}, "extra": {"severity": "WARNING", "message": "Weak key"}},
            {"path": "test.py", "start": {"line": 1}, "extra": {"severity": "INFO", "message": "Debug print"}}
        ]
    }"""
    result = process_semgrep_output(raw_json)
    assert result["total_findings"] == 3
    assert result["critical_findings_count"] == 2
    assert len(result["top_findings"]) == 2
    assert "[ERROR]" in result["top_findings"][0]

def test_process_generic_tool_truncates_large_payloads():
    massive_line = "A" * 4000
    res = process_generic_tool("search_code", massive_line)
    assert res["truncated"] is True
    assert len(res["snippet"]) <= 3100
    assert "[TRUNCATED:" in res["snippet"]

def test_compressor_node_memory_sweeping():
    mock_state = {
        "messages": [
            ToolMessage(content='{"results": []}', name="run_semgrep", tool_call_id="call_123", id="tool-msg-1"),
            AIMessage(content="", tool_calls=[{"name": "read_file", "args": {}, "id": "call_123"}], id="ai-call-1")
        ],
        "compressed_findings": [],
        "verified_findings": [],
        "current_plan": "audit",
        "target_directory": "/tmp",
        "active_tool": "",
        "retries": 0
    }
    
    result = compressor_node(mock_state, config={})
    
    assert len(result["compressed_findings"]) == 1
    assert len(result["messages"]) == 2
    assert {m.id for m in result["messages"]} == {"tool-msg-1", "ai-call-1"}
