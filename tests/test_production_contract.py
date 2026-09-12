"""Adversarial closure checks for the producer's versioned final-state commitment."""

import json
import uuid
from types import SimpleNamespace

import pytest
from langchain_core.messages import AIMessage, ToolMessage

from cipherloop.core.trajectory import PRODUCTION_CONTRACT_VERSION, TrajectoryRecorder
from cipherloop.executor.compressor import compressor_node
from cipherloop.executor.validator import validator_node

SOURCE = "import os\nx = input()\nos.system(x)\n"


def capture(tmp_path, monkeypatch):
    recorder = TrajectoryRecorder(
        str(uuid.uuid4()), str(tmp_path), contract_version=PRODUCTION_CONTRACT_VERSION
    )
    recorder.start_run("audit", "/target")
    monkeypatch.setattr(
        "cipherloop.executor.validator.read_file", SimpleNamespace(invoke=lambda _: SOURCE)
    )
    state = {"messages": [
        AIMessage(content="", tool_calls=[{"id": "scan", "name": "run_semgrep", "args": {}}]),
        ToolMessage(content=json.dumps({"results": [{
            "path": "app.py", "start": {"line": 3},
            "extra": {"severity": "ERROR", "message": "Command injection"},
        }]}), name="run_semgrep", tool_call_id="scan"),
    ], "compressed_findings": [], "verified_findings": []}
    config = {"configurable": {"__trajectory_recorder__": recorder}}
    state["compressed_findings"] = compressor_node(state, config)["compressed_findings"]
    state["messages"] = []
    return recorder, state, config


def metadata(recorder):
    return json.loads(recorder.metadata_file.read_text())


def rows(recorder):
    return [json.loads(line) for line in recorder.trajectory_file.read_bytes().splitlines()]


@pytest.mark.parametrize("version", ["cipherloop-production-v1", "cipherloop-production-v99"])
def test_unclosed_and_unknown_versions_cannot_be_produced(tmp_path, version):
    with pytest.raises(ValueError, match="Unsupported"):
        TrajectoryRecorder(str(uuid.uuid4()), str(tmp_path), contract_version=version)


def test_final_references_preserve_duplicate_finding_occurrences(tmp_path, monkeypatch):
    recorder, state, config = capture(tmp_path, monkeypatch)
    for _ in range(2):
        state["verified_findings"].extend(validator_node(state, config)["verified_findings"])
    recorder.finish_run("completed", None)
    recorder.finalize(state)
    decisions = [row for row in rows(recorder) if row["step_type"] == "validation.decision"]
    assert len(decisions) == 2
    assert decisions[0]["payload"]["finding"] == decisions[1]["payload"]["finding"]
    assert metadata(recorder)["final_finding_refs"] == [row["seq"] for row in decisions]


@pytest.mark.parametrize("aggregate_returned", [False, True])
def test_failed_node_observations_are_not_promoted_to_final_state(
    tmp_path, monkeypatch, aggregate_returned
):
    recorder, state, config = capture(tmp_path, monkeypatch)
    original_record = recorder.record_step

    def record(kind, payload):
        if kind == "validation" and not aggregate_returned:
            raise RuntimeError("aggregate unavailable")
        return original_record(kind, payload)

    with monkeypatch.context() as fault:
        fault.setattr(recorder, "record_step", record)
        if aggregate_returned:
            validator_node(state, config)  # Node output lost before state reduction.
        else:
            with pytest.raises(RuntimeError, match="aggregate unavailable"):
                validator_node(state, config)
    recorder.finish_run("failed", {"stage": "graph_execution", "type": "Error", "message": "lost"})
    recorder.finalize(state)
    assert any(row["step_type"] == "validation.decision" for row in rows(recorder))
    assert metadata(recorder)["execution_status"] == "failed"
    assert metadata(recorder)["final_finding_refs"] == []


@pytest.mark.parametrize("mutation", ["missing", "changed", "duplicate", "compressed"])
def test_inconsistent_final_state_cannot_publish_completion(tmp_path, monkeypatch, mutation):
    recorder, state, config = capture(tmp_path, monkeypatch)
    state.update(validator_node(state, config))
    if mutation == "missing":
        state["verified_findings"] = []
    elif mutation == "changed":
        state["verified_findings"][0]["confidence"] = 0.5
    elif mutation == "duplicate":
        state["verified_findings"] *= 2
    else:
        state["compressed_findings"][0]["raw_char_count"] += 1
    recorder.finish_run("completed", None)
    with pytest.raises(RuntimeError, match="state|unreconciled"):
        recorder.finalize(state)
    assert not recorder.metadata_file.exists()


def test_aborted_empty_validation_cycle_is_visible_and_cannot_complete(tmp_path, monkeypatch):
    recorder, state, config = capture(tmp_path, monkeypatch)
    state["compressed_findings"][0]["top_findings"] = []
    original_record = recorder.record_step

    def record(kind, payload):
        if kind == "validation":
            raise RuntimeError("aborted empty cycle")
        return original_record(kind, payload)

    monkeypatch.setattr(recorder, "record_step", record)
    with pytest.raises(RuntimeError, match="aborted empty"):
        validator_node(state, config)
    assert rows(recorder)[-1]["step_type"] == "validation.started"
    recorder.finish_run("completed", None)
    with pytest.raises(RuntimeError):
        recorder.finalize(state)
    assert not recorder.metadata_file.exists()


@pytest.mark.parametrize("tamper", ["same_line_count", "torn_tail", "extra_row"])
def test_ledger_mutation_before_finalization_is_never_committed(tmp_path, monkeypatch, tamper):
    recorder, state, _ = capture(tmp_path, monkeypatch)
    recorder.finish_run("completed", None)
    data = recorder.trajectory_file.read_bytes()
    if tamper == "same_line_count":
        data = data.replace(b'"audit"', b'"other"')
    elif tamper == "torn_tail":
        data = data[:-5]
    else:
        data += b'{}\n'
    recorder.trajectory_file.write_bytes(data)
    with pytest.raises(RuntimeError, match="ledger"):
        recorder.finalize(state)
    assert not recorder.metadata_file.exists()


def test_directory_sync_failure_revokes_new_metadata(tmp_path, monkeypatch):
    recorder, state, config = capture(tmp_path, monkeypatch)
    state.update(validator_node(state, config))
    recorder.finish_run("completed", None)

    def fail_sync():
        assert recorder.metadata_file.exists()
        raise OSError("directory sync failed")

    monkeypatch.setattr(recorder, "_sync_output_directory", fail_sync)
    with pytest.raises(OSError, match="directory sync"):
        recorder.finalize(state)
    assert not recorder.metadata_file.exists()
    assert not list(tmp_path.glob("*.tmp"))


def test_compressed_candidates_without_validation_cannot_finalize_completed(tmp_path, monkeypatch):
    recorder, state, _ = capture(tmp_path, monkeypatch)
    recorder.finish_run("completed", None)
    with pytest.raises(RuntimeError, match="unreconciled"):
        recorder.finalize(state)
    assert not recorder.metadata_file.exists()


def test_no_observations_before_run_start(tmp_path):
    recorder = TrajectoryRecorder(
        str(uuid.uuid4()), str(tmp_path), contract_version=PRODUCTION_CONTRACT_VERSION
    )
    with pytest.raises(RuntimeError, match="must begin"):
        recorder.record_step("message", {})
    assert recorder.trajectory_file.read_bytes() == b""


@pytest.mark.parametrize("failure", ["serialization", "metadata_fsync"])
def test_metadata_failure_cannot_leave_a_complete_commit(tmp_path, monkeypatch, failure):
    recorder = TrajectoryRecorder(
        str(uuid.uuid4()), str(tmp_path), contract_version=PRODUCTION_CONTRACT_VERSION
    )
    recorder.start_run("audit", "/target")
    recorder.finish_run("completed", None)
    state = {"compressed_findings": [], "verified_findings": []}
    if failure == "serialization":
        state["current_plan"] = object()
    else:
        def fail_sync(_descriptor):
            raise OSError("metadata fsync failed")
        monkeypatch.setattr("cipherloop.core.trajectory.os.fsync", fail_sync)
    with pytest.raises((TypeError, OSError)):
        recorder.finalize(state)
    assert not recorder.metadata_file.exists()
    assert not list(tmp_path.glob("*.tmp"))
