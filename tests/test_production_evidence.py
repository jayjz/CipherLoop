import asyncio
import hashlib
import json
import sys
import types

import pytest
from langchain_core.messages import AIMessage, ToolMessage
from langgraph.graph import END, START, StateGraph

from cipherloop import main
from cipherloop.core.state import AuditState
from cipherloop.core.trajectory import PRODUCTION_CONTRACT_VERSION, TrajectoryRecorder
from cipherloop.executor.compressor import compressor_node
from cipherloop.executor.validator import validator_node


class _SuccessfulGraph:
    async def astream(self, initial_state, **_kwargs):
        yield initial_state


class _FailingGraph:
    async def astream(self, _initial_state, **_kwargs):
        raise RuntimeError("graph failed")
        yield  # pragma: no cover - marks this as an async generator.


class _InterruptedGraph:
    async def astream(self, _initial_state, **_kwargs):
        raise KeyboardInterrupt()
        yield  # pragma: no cover - marks this as an async generator.


def _install_graph(monkeypatch, graph_or_error):
    module = types.ModuleType("cipherloop.orchestrator.graph")
    if isinstance(graph_or_error, BaseException):
        def build_graph():
            raise graph_or_error
    else:
        def build_graph():
            return graph_or_error
    module.build_graph = build_graph
    monkeypatch.setitem(sys.modules, "cipherloop.orchestrator.graph", module)


def _run_audit(monkeypatch, tmp_path, graph_or_error):
    recorders = []

    def recorder_factory(*args, **kwargs):
        recorder = TrajectoryRecorder(*args, output_dir=str(tmp_path), **kwargs)
        recorders.append(recorder)
        return recorder

    monkeypatch.setattr(main, "TrajectoryRecorder", recorder_factory)
    monkeypatch.setattr(main, "check_prerequisites", lambda _target: None)
    monkeypatch.setattr(main, "ensure_sandbox_running", lambda _target: None)
    _install_graph(monkeypatch, graph_or_error)
    return recorders


def _artifacts(recorder):
    rows = [json.loads(line) for line in recorder.trajectory_file.read_text(encoding="utf-8").splitlines()]
    metadata = json.loads(recorder.metadata_file.read_text(encoding="utf-8"))
    return rows, metadata


def test_audit_records_completed_lifecycle(monkeypatch, tmp_path):
    recorders = _run_audit(monkeypatch, tmp_path, _SuccessfulGraph())

    main.audit(target=str(tmp_path), plan="original plan")

    rows, metadata = _artifacts(recorders[0])
    assert rows[0]["payload"] == {
        "task": {"description": "original plan"},
        "target_directory": str(tmp_path.resolve()),
        "tool_capture_boundary": "compressor_observed",
        "models": None,
    }
    assert rows[-1]["payload"] == {"execution_status": "completed", "error": None}
    assert metadata["execution_status"] == "completed"


def test_audit_records_graph_failure_and_reraises(monkeypatch, tmp_path):
    recorders = _run_audit(monkeypatch, tmp_path, _FailingGraph())

    with pytest.raises(RuntimeError, match="graph failed"):
        main.audit(target=str(tmp_path), plan="original plan")

    rows, metadata = _artifacts(recorders[0])
    assert rows[-1]["payload"] == {
        "execution_status": "failed",
        "error": {"stage": "graph_execution", "type": "RuntimeError", "message": "graph failed"},
    }
    assert metadata["execution_status"] == "failed"


def test_audit_records_preflight_exit_and_reraises(monkeypatch, tmp_path):
    recorders = []

    def recorder_factory(*args, **kwargs):
        recorder = TrajectoryRecorder(*args, output_dir=str(tmp_path), **kwargs)
        recorders.append(recorder)
        return recorder

    monkeypatch.setattr(main, "TrajectoryRecorder", recorder_factory)
    monkeypatch.setattr(main, "check_prerequisites", lambda _target: (_ for _ in ()).throw(SystemExit(1)))

    with pytest.raises(SystemExit) as raised:
        main.audit(target=str(tmp_path), plan="original plan")

    rows, metadata = _artifacts(recorders[0])
    assert raised.value.code == 1
    assert rows[-1]["payload"] == {
        "execution_status": "failed",
        "error": {"stage": "preflight", "type": "SystemExit", "message": "1"},
    }
    assert metadata["execution_status"] == "failed"


def test_audit_records_keyboard_interrupt_and_reraises(monkeypatch, tmp_path):
    recorders = _run_audit(monkeypatch, tmp_path, _InterruptedGraph())

    with pytest.raises(KeyboardInterrupt):
        main.audit(target=str(tmp_path), plan="original plan")

    rows, metadata = _artifacts(recorders[0])
    assert rows[-1]["payload"] == {
        "execution_status": "interrupted",
        "error": {
            "stage": "graph_execution",
            "type": "KeyboardInterrupt",
            "message": "KeyboardInterrupt",
        },
    }
    assert metadata["execution_status"] == "interrupted"


def test_ledger_without_valid_metadata_is_incomplete_contract_artifact(tmp_path):
    recorder = TrajectoryRecorder(
        run_id="00000000-0000-4000-8000-000000000001",
        output_dir=str(tmp_path),
        contract_version=PRODUCTION_CONTRACT_VERSION,
    )
    recorder.start_run("task", "/target")
    recorder.finish_run("completed", None)

    assert recorder.trajectory_file.exists()
    assert not recorder.metadata_file.exists()


@pytest.mark.parametrize("outcome", ["verified", "no_candidates", "rejected", "analysis_failure"])
def test_production_graph_retains_evidence_through_cli_lifecycle(
    monkeypatch, tmp_path, capsys, outcome
):
    source = "import os\nx = input()\nos.system(x)\n"
    if outcome == "rejected":
        source = "import os\nx = 'safe'\nos.system(x)\n"
    results = [] if outcome == "no_candidates" else [
        {
            "path": "app.py", "start": {"line": 3},
            "extra": {"severity": "ERROR", "message": "Command injection"},
        }
    ]
    read_arguments = []

    def read(arguments):
        read_arguments.append(arguments)
        return source

    monkeypatch.setattr(
        "cipherloop.executor.validator.read_file", types.SimpleNamespace(invoke=read)
    )
    analysis_error = RecursionError("analysis failed")
    if outcome == "analysis_failure":
        def fail_analysis(*_args, **_kwargs):
            raise analysis_error
        monkeypatch.setattr(
            "cipherloop.executor.validator._find_taint_trace_with_reason", fail_analysis
        )

    def observe(_state):
        return {"messages": [
            AIMessage(content="", tool_calls=[
                {"id": "scan", "name": "run_semgrep", "args": {"target_path": "app.py"}}
            ]),
            ToolMessage(content=json.dumps({"results": results}), name="run_semgrep",
                        tool_call_id="scan"),
        ]}

    def validate(state, config):
        # Exercise the real RemoveMessage reducer before source capture.
        assert state["messages"] == []
        return validator_node(state, config)

    graph = StateGraph(AuditState)
    graph.add_node("observe", observe)
    graph.add_node("compressor", compressor_node)
    graph.add_node("validator", validate)
    graph.add_edge(START, "observe")
    graph.add_edge("observe", "compressor")
    graph.add_edge("compressor", "validator")
    graph.add_edge("validator", END)
    recorders = _run_audit(monkeypatch, tmp_path, graph.compile())

    if outcome == "analysis_failure":
        with pytest.raises(RecursionError) as raised:
            main.audit(target=str(tmp_path), plan="audit")
        assert raised.value is analysis_error
    else:
        main.audit(target=str(tmp_path), plan="audit")

    rows, metadata = _artifacts(recorders[0])
    status = "failed" if outcome == "analysis_failure" else "completed"
    assert rows[-1]["payload"]["execution_status"] == metadata["execution_status"] == status
    assert [row["seq"] for row in rows] == list(range(1, len(rows) + 1))
    assert metadata["event_count"] == len(rows)
    assert metadata["ledger_sha256"] == hashlib.sha256(
        recorders[0].trajectory_file.read_bytes()
    ).hexdigest()
    assert metadata["compressed_findings_count"] == 1  # Last yielded state survives failure.
    assert metadata["evidence_status"] == "complete"
    assert metadata["report_ref"] is None
    assert len(metadata["final_finding_refs"]) == int(outcome == "verified")
    for ref in metadata["final_finding_refs"]:
        decision = rows[ref - 1]
        assert decision["step_type"] == "validation.decision"
        assert decision["payload"]["disposition"] == "verified"

    reads = [row for row in rows if row["step_type"] == "source.read"]
    decisions = [row for row in rows if row["step_type"] == "validation.decision"]
    aggregates = [row for row in rows if row["step_type"] == "validation"]
    if outcome == "no_candidates":
        assert reads == decisions == read_arguments == []
        assert aggregates[0]["payload"]["total_candidates"] == 0
    else:
        assert read_arguments == [{"filepath": "app.py", "start_line": 1, "end_line": 1_000_000}]
        assert len(reads) == 1
        assert reads[0]["payload"]["text"] == source
        assert reads[0]["payload"]["text_sha256"] == hashlib.sha256(source.encode()).hexdigest()
        if outcome == "analysis_failure":
            assert decisions == aggregates == []
            assert "Audit complete." not in capsys.readouterr().out
        else:
            assert decisions[0]["payload"]["disposition"] == outcome
            assert decisions[0]["payload"]["source_read_ref"] == reads[0]["seq"]
            assert aggregates[0]["payload"]["verified_count"] == int(outcome == "verified")


def test_audit_preserves_original_error_when_failure_capture_fails(monkeypatch, tmp_path, capsys):
    recorders = _run_audit(monkeypatch, tmp_path, _FailingGraph())

    def fail_finish(*_args):
        raise OSError("terminal append failed")

    monkeypatch.setattr(TrajectoryRecorder, "finish_run", fail_finish)
    with pytest.raises(RuntimeError, match="graph failed"):
        main.audit(target=str(tmp_path), plan="audit")

    output = capsys.readouterr()
    assert "terminal append failed" in output.err
    assert "Audit complete." not in output.out
    assert not recorders[0].metadata_file.exists()


@pytest.mark.parametrize(("error", "status"), [
    (RuntimeError("graph build failed"), "failed"),
    (asyncio.CancelledError("cancelled"), "interrupted"),
])
def test_audit_captures_graph_build_failure_or_cancellation(monkeypatch, tmp_path, error, status):
    recorders = _run_audit(monkeypatch, tmp_path, error)
    with pytest.raises(type(error)) as raised:
        main.audit(target=str(tmp_path), plan="audit")
    assert raised.value is error
    rows, metadata = _artifacts(recorders[0])
    assert metadata["execution_status"] == status
    assert rows[-1]["payload"]["error"]["stage"] == "graph_build"
    assert metadata["final_finding_refs"] == metadata["final_compression_refs"] == []


def test_audit_never_announces_completion_after_finalization_failure(monkeypatch, tmp_path, capsys):
    recorders = _run_audit(monkeypatch, tmp_path, _SuccessfulGraph())

    def fail_finalize(*_args):
        raise OSError("metadata unavailable")

    monkeypatch.setattr(TrajectoryRecorder, "finalize", fail_finalize)
    with pytest.raises(OSError, match="metadata unavailable"):
        main.audit(target=str(tmp_path), plan="audit")
    assert "Audit complete." not in capsys.readouterr().out
    assert not recorders[0].metadata_file.exists()
