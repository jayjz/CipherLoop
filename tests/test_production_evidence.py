import json
import sys
import types

import pytest

from cipherloop import main
from cipherloop.core.trajectory import TrajectoryRecorder


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
        contract_version="cipherloop-production-v1",
    )
    recorder.start_run("task", "/target")
    recorder.finish_run("completed", None)

    assert recorder.trajectory_file.exists()
    assert not recorder.metadata_file.exists()
