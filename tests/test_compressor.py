import json
import uuid

from langchain_core.messages import AIMessage, ToolMessage

from cipherloop.core.trajectory import PRODUCTION_CONTRACT_VERSION, TrajectoryRecorder
from cipherloop.executor.compressor import (
    compressor_node,
    process_generic_tool,
    process_semgrep_output,
)


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


def test_production_compressor_records_exact_observation_compression_and_global_indices(tmp_path):
    recorder = TrajectoryRecorder(
        run_id=str(uuid.uuid4()),
        output_dir=str(tmp_path),
        contract_version=PRODUCTION_CONTRACT_VERSION,
    )
    recorder.start_run("audit", "/target")
    messages = [
        ToolMessage(
            content='{"results": []}', name="run_semgrep", tool_call_id="first", id="tool-1"
        ),
        ToolMessage(content="result", name="search_code", tool_call_id="second", id="tool-2"),
    ]
    state = {"messages": messages, "compressed_findings": [{"previous": True}]}

    result = compressor_node(
        state, {"configurable": {"__trajectory_recorder__": recorder}}
    )
    rows = [
        json.loads(line)
        for line in recorder.trajectory_file.read_text(encoding="utf-8").splitlines()
    ]
    observations = [row for row in rows if row["step_type"] == "message"]
    compressions = [row for row in rows if row["step_type"] == "compression"]

    assert len(observations) == len(compressions) == 2
    assert [row["payload"]["raw_result_ref"] for row in compressions] == [
        row["seq"] for row in observations
    ]
    assert [row["payload"]["state_index"] for row in compressions] == [1, 2]
    assert [row["payload"]["finding"] for row in compressions] == result["compressed_findings"]
    assert [recorder.compression_ref_for_state_index(index) for index in (1, 2)] == [
        row["seq"] for row in compressions
    ]
    assert {message.id for message in result["messages"]} == {"tool-1", "tool-2"}


def test_legacy_compressor_keeps_message_only_ledger_payload(tmp_path):
    recorder = TrajectoryRecorder(run_id="legacy", output_dir=str(tmp_path))
    message = ToolMessage(
        content="result", name="search_code", tool_call_id="call", id="tool-message"
    )

    compressor_node(
        {"messages": [message], "compressed_findings": []},
        {"configurable": {"__trajectory_recorder__": recorder}},
    )
    rows = [
        json.loads(line)
        for line in recorder.trajectory_file.read_text(encoding="utf-8").splitlines()
    ]

    assert len(rows) == 1
    assert set(rows[0]) == {"timestamp", "run_id", "step_type", "payload"}
    assert rows[0]["step_type"] == "message"
    assert rows[0]["payload"] == {
        "type": "ToolMessage",
        "role": "tool",
        "content": "result",
        "tool_name": "search_code",
        "tool_call_id": "call",
    }
