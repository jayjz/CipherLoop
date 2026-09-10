import hashlib
import json
import uuid
from types import SimpleNamespace

import pytest
from langchain_core.messages import ToolMessage

from cipherloop.core.trajectory import PRODUCTION_CONTRACT_VERSION, TrajectoryRecorder
from cipherloop.executor.compressor import compressor_node
from cipherloop.executor.validator import find_taint_trace, validator_node

VULNERABLE_SOURCE = """import subprocess
from flask import request

def ping():
    host = request.args.get('host')
    return subprocess.run(f'ping -c 1 {host}', shell=True)
"""


def test_ast_trace_finds_request_argument_flowing_to_subprocess_run():
    trace = find_taint_trace(VULNERABLE_SOURCE, "app.py", expected_sink_line=6)

    assert trace is not None
    assert trace.source == {"file": "app.py", "line": 5, "symbol": "request.args.get"}
    assert trace.sink == {"file": "app.py", "line": 6, "symbol": "subprocess.run"}
    assert trace.path == [
        "app.py:5:request.args.get",
        "app.py:5:host",
        "app.py:6:subprocess.run",
    ]


def test_ast_trace_rejects_sink_without_an_untrusted_source():
    trace = find_taint_trace(
        "import subprocess\nsubprocess.run(['echo', 'safe'])\n",
        "safe.py",
        expected_sink_line=2,
    )

    assert trace is None


def test_validator_emits_only_a_complete_ast_verified_finding(monkeypatch):
    monkeypatch.setattr(
        "cipherloop.executor.validator.read_file",
        SimpleNamespace(invoke=lambda _: VULNERABLE_SOURCE),
    )
    state = {
        "messages": [],
        "compressed_findings": [
            {"top_findings": ["[ERROR] app.py:6 - Command injection"]}
        ],
        "verified_findings": [],
        "current_plan": "audit",
        "target_directory": "/workspace/target_repo",
        "active_tool": "",
        "retries": 0,
    }

    result = validator_node(state, config={})

    assert len(result["verified_findings"]) == 1
    finding = result["verified_findings"][0]
    assert finding["status"] == "VERIFIED"
    assert finding["source"]["symbol"] == "request.args.get"
    assert finding["sink"]["symbol"] == "subprocess.run"
    assert finding["taint_path"]


def _production_recorder(tmp_path):
    recorder = TrajectoryRecorder(
        run_id=str(uuid.uuid4()),
        output_dir=str(tmp_path),
        contract_version=PRODUCTION_CONTRACT_VERSION,
    )
    recorder.start_run("audit", "/target")
    return recorder


def _rows(recorder):
    return [
        json.loads(line)
        for line in recorder.trajectory_file.read_text(encoding="utf-8").splitlines()
    ]


def _production_state(recorder, summary):
    if summary != "[ERROR] app.py:6 - Command injection":
        raw_result_ref = recorder.record_step(
            "message", {"type": "ToolMessage", "role": "tool", "content": "retained"}
        )
        finding = {"top_findings": [summary]}
        recorder.record_compression(raw_result_ref, 0, finding)
        return {"messages": [], "compressed_findings": [finding]}

    message = ToolMessage(
        content=json.dumps(
            {
                "results": [
                    {
                        "path": "app.py",
                        "start": {"line": 6},
                        "extra": {"severity": "ERROR", "message": "Command injection"},
                    }
                ]
            }
        ),
        name="run_semgrep",
        tool_call_id="scan",
        id="tool-message",
    )
    compression = compressor_node(
        {"messages": [message], "compressed_findings": []},
        {"configurable": {"__trajectory_recorder__": recorder}},
    )
    return {"messages": [], "compressed_findings": compression["compressed_findings"]}


def test_production_validator_retains_verified_source_backed_event_chain(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "cipherloop.executor.validator.read_file",
        SimpleNamespace(invoke=lambda _: VULNERABLE_SOURCE),
    )
    recorder = _production_recorder(tmp_path)
    state = _production_state(recorder, "[ERROR] app.py:6 - Command injection")

    result = validator_node(state, {"configurable": {"__trajectory_recorder__": recorder}})
    rows = _rows(recorder)
    events = {row["step_type"]: row for row in rows if row["step_type"] != "message"}
    candidate = events["validation.candidate"]
    compression = events["compression"]
    source_read = events["source.read"]
    decision = events["validation.decision"]

    assert source_read["payload"]["candidate_ref"] == candidate["seq"]
    assert candidate["payload"]["compression_ref"] == compression["seq"]
    assert source_read["payload"]["text"] == VULNERABLE_SOURCE
    assert source_read["payload"]["text_sha256"] == hashlib.sha256(
        VULNERABLE_SOURCE.encode("utf-8")
    ).hexdigest()
    assert decision["payload"]["candidate_ref"] == candidate["seq"]
    assert decision["payload"]["source_read_ref"] == source_read["seq"]
    assert decision["payload"]["finding"] == result["verified_findings"][0]
    assert decision["payload"]["source_slice"] == {
        "source_read_ref": source_read["seq"], "start_line": 5, "end_line": 6
    }
    assert events["validation"]["payload"] == {
        "total_candidates": 1,
        "verified_count": 1,
        "rejected_count": 0,
        "candidate_to_verified_ratio": 1.0,
        "cycle": 1,
    }


@pytest.mark.parametrize(
    ("summary", "source", "read_error", "reason", "has_source_read"),
    [
        ("malformed", None, None, "malformed_summary", False),
        ("[ERROR] app.py:6 - Command injection", None, RuntimeError("read failed"), "read_exception", True),
        ("[ERROR] app.py:6 - Command injection", "Tool Execution Error", None, "read_error_marker", True),
        ("[ERROR] app.py:6 - Command injection", "System Error", None, "read_error_marker", True),
        ("[ERROR] app.py:6 - Command injection", "def broken(:\n", None, "syntax_error", True),
        (
            "[ERROR] app.py:6 - Command injection",
            "import subprocess\nsubprocess.run(['echo', 'safe'])\n",
            None,
            "no_taint_trace",
            True,
        ),
    ],
)
def test_production_validator_records_each_rejection_branch(
    monkeypatch, tmp_path, summary, source, read_error, reason, has_source_read
):
    def read(_arguments):
        if read_error:
            raise read_error
        return source

    monkeypatch.setattr("cipherloop.executor.validator.read_file", SimpleNamespace(invoke=read))
    recorder = _production_recorder(tmp_path)
    state = _production_state(recorder, summary)

    result = validator_node(state, {"configurable": {"__trajectory_recorder__": recorder}})
    rows = _rows(recorder)
    candidates = [row for row in rows if row["step_type"] == "validation.candidate"]
    reads = [row for row in rows if row["step_type"] == "source.read"]
    decisions = [row for row in rows if row["step_type"] == "validation.decision"]

    assert result["verified_findings"] == []
    assert len(candidates) == len(decisions) == 1
    assert len(reads) == int(has_source_read)
    assert decisions[0]["payload"]["reason"] == reason
    assert decisions[0]["payload"]["finding"] is None
    assert decisions[0]["payload"]["source_slice"] is None
    assert decisions[0]["payload"]["disposition"] == (
        "skipped" if reason == "malformed_summary" else "rejected"
    )
    if read_error:
        assert reads[0]["payload"]["error"] == {
            "stage": "validation_read", "type": "RuntimeError", "message": "read failed"
        }


def test_production_validator_cycles_zero_candidates_and_duplicate_attempts(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "cipherloop.executor.validator.read_file",
        SimpleNamespace(invoke=lambda _: VULNERABLE_SOURCE),
    )
    recorder = _production_recorder(tmp_path)
    validator_node({"messages": [], "compressed_findings": []}, {"configurable": {"__trajectory_recorder__": recorder}})
    state = _production_state(recorder, "[ERROR] app.py:6 - Command injection")
    validator_node(state, {"configurable": {"__trajectory_recorder__": recorder}})
    validator_node(state, {"configurable": {"__trajectory_recorder__": recorder}})
    rows = _rows(recorder)
    aggregates = [row["payload"] for row in rows if row["step_type"] == "validation"]
    candidates = [row for row in rows if row["step_type"] == "validation.candidate"]

    assert aggregates[0] == {
        "total_candidates": 0,
        "verified_count": 0,
        "rejected_count": 0,
        "candidate_to_verified_ratio": None,
        "cycle": 1,
    }
    assert [payload["cycle"] for payload in aggregates] == [1, 2, 3]
    assert len(candidates) == 2
    assert candidates[0]["payload"]["summary"] == candidates[1]["payload"]["summary"]
    assert candidates[0]["seq"] != candidates[1]["seq"]


def test_production_validator_refuses_unproven_compressed_provenance(tmp_path):
    recorder = _production_recorder(tmp_path)

    with pytest.raises(RuntimeError, match="Missing production compression evidence"):
        validator_node(
            {"messages": [], "compressed_findings": [{"top_findings": ["malformed"]}]},
            {"configurable": {"__trajectory_recorder__": recorder}},
        )


def test_production_validator_retains_read_before_analysis_failure(monkeypatch, tmp_path):
    reads = []
    analysis_error = RecursionError("analysis failed")

    def read(arguments):
        reads.append(arguments)
        return VULNERABLE_SOURCE

    def fail_analysis(*_args, **_kwargs):
        raise analysis_error

    monkeypatch.setattr("cipherloop.executor.validator.read_file", SimpleNamespace(invoke=read))
    monkeypatch.setattr("cipherloop.executor.validator._find_taint_trace_with_reason", fail_analysis)
    recorder = _production_recorder(tmp_path)
    state = _production_state(recorder, "[ERROR] app.py:6 - Command injection")

    with pytest.raises(RecursionError) as raised:
        validator_node(state, {"configurable": {"__trajectory_recorder__": recorder}})

    assert raised.value is analysis_error
    assert reads == [{"filepath": "app.py", "start_line": 1, "end_line": 1_000_000}]
    rows = _rows(recorder)
    assert rows[-2]["step_type"] == "validation.candidate"
    assert rows[-1]["step_type"] == "source.read"
    assert rows[-1]["payload"] == {
        "candidate_ref": rows[-2]["seq"],
        "arguments": reads[0],
        "status": "returned",
        "text": VULNERABLE_SOURCE,
        "text_sha256": hashlib.sha256(VULNERABLE_SOURCE.encode("utf-8")).hexdigest(),
        "error": None,
    }
    assert not any(row["step_type"] in {"validation.decision", "validation"} for row in rows)
    assert state["messages"] == []
