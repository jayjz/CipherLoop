import hashlib
import json
import math
import uuid
from pathlib import Path

import pytest

import cipherloop.core.trajectory as trajectory_module
from cipherloop.core.trajectory import PRODUCTION_CONTRACT_VERSION, TrajectoryRecorder


def test_finalize_aggregates_tool_compression_metrics(tmp_path):
    recorder = TrajectoryRecorder(run_id="metrics", output_dir=str(tmp_path))
    recorder.finalize(
        {
            "target_directory": "/workspace/target_repo",
            "current_plan": "AUDIT_COMPLETE",
            "retries": 2,
            "compressed_findings": [
                {"raw_char_count": 120, "compressed_char_count": 30},
                {"raw_char_count": 80, "compressed_char_count": 20},
            ],
        }
    )

    metadata = json.loads((tmp_path / "metadata_metrics.json").read_text(encoding="utf-8"))

    assert metadata["total_raw_char_count"] == 200
    assert metadata["total_compressed_char_count"] == 50
    assert metadata["compression_ratio"] == 4.0


def test_legacy_recorder_keeps_unversioned_shape_and_default_stringification(tmp_path):
    recorder = TrajectoryRecorder(run_id="legacy", output_dir=str(tmp_path))
    recorder.record_step("legacy.event", {"unsupported": object()})

    row = json.loads((tmp_path / "trajectory_legacy.jsonl").read_text(encoding="utf-8"))

    assert set(row) == {"timestamp", "run_id", "step_type", "payload"}
    assert row["run_id"] == "legacy"
    assert isinstance(row["payload"]["unsupported"], str)


def test_production_recorder_writes_versioned_contiguous_lifecycle_and_metadata(tmp_path):
    run_id = str(uuid.uuid4())
    recorder = TrajectoryRecorder(
        run_id=run_id,
        output_dir=str(tmp_path),
        contract_version=PRODUCTION_CONTRACT_VERSION,
    )

    assert recorder.start_run("audit task", "/target") == 1
    assert recorder.record_step("observation", {"value": 1}) == 2
    assert recorder.finish_run("completed", None) == 3
    recorder.finalize({"target_directory": "/target", "compressed_findings": []})

    ledger_bytes = (tmp_path / f"trajectory_{run_id}.jsonl").read_bytes()
    rows = [json.loads(line) for line in ledger_bytes.splitlines()]
    metadata = json.loads((tmp_path / f"metadata_{run_id}.json").read_text(encoding="utf-8"))

    assert [row["seq"] for row in rows] == [1, 2, 3]
    assert all(row["contract_version"] == PRODUCTION_CONTRACT_VERSION for row in rows)
    assert rows[0]["step_type"] == "run.started"
    assert rows[-1]["payload"] == {"execution_status": "completed", "error": None}
    assert metadata["contract_version"] == PRODUCTION_CONTRACT_VERSION
    assert metadata["start_ref"] == 1
    assert metadata["finish_ref"] == 3
    assert metadata["execution_status"] == "completed"
    assert metadata["event_count"] == len(rows) == 3
    assert metadata["ledger_sha256"] == hashlib.sha256(ledger_bytes).hexdigest()


def test_production_recorder_requires_canonical_full_uuid_and_fresh_paths(tmp_path):
    with pytest.raises(ValueError, match="full UUID"):
        TrajectoryRecorder(
            run_id="short-id",
            output_dir=str(tmp_path),
            contract_version=PRODUCTION_CONTRACT_VERSION,
        )

    run_id = str(uuid.uuid4())
    TrajectoryRecorder(
        run_id=run_id,
        output_dir=str(tmp_path),
        contract_version=PRODUCTION_CONTRACT_VERSION,
    )
    with pytest.raises(FileExistsError):
        TrajectoryRecorder(
            run_id=run_id,
            output_dir=str(tmp_path),
            contract_version=PRODUCTION_CONTRACT_VERSION,
        )


def test_production_recorder_rejects_stale_metadata_without_creating_a_ledger(tmp_path):
    run_id = str(uuid.uuid4())
    metadata_file = tmp_path / f"metadata_{run_id}.json"
    metadata_file.write_text("stale", encoding="utf-8")

    with pytest.raises(FileExistsError, match="metadata path already exists"):
        TrajectoryRecorder(
            run_id=run_id,
            output_dir=str(tmp_path),
            contract_version=PRODUCTION_CONTRACT_VERSION,
        )

    assert metadata_file.read_text(encoding="utf-8") == "stale"
    assert not (tmp_path / f"trajectory_{run_id}.jsonl").exists()


@pytest.mark.parametrize("payload", [{"value": math.nan}, {"value": object()}])
def test_production_recorder_rejects_non_strict_json_without_advancing_sequence(tmp_path, payload):
    recorder = TrajectoryRecorder(
        run_id=str(uuid.uuid4()),
        output_dir=str(tmp_path),
        contract_version=PRODUCTION_CONTRACT_VERSION,
    )
    recorder.start_run("task", "/target")

    with pytest.raises((TypeError, ValueError)):
        recorder.record_step("invalid", payload)

    assert recorder.last_seq == 1
    assert recorder.trajectory_file.read_text(encoding="utf-8").count("\n") == 1

    recorder.finish_run(
        "failed", {"stage": "graph_execution", "type": "ValueError", "message": "invalid JSON"}
    )
    recorder.finalize({"compressed_findings": []})
    metadata = json.loads(recorder.metadata_file.read_text(encoding="utf-8"))
    assert metadata["execution_status"] == "failed"
    assert metadata["event_count"] == 2


def test_production_finalization_failure_does_not_publish_valid_metadata(tmp_path, monkeypatch):
    recorder = TrajectoryRecorder(
        run_id=str(uuid.uuid4()),
        output_dir=str(tmp_path),
        contract_version=PRODUCTION_CONTRACT_VERSION,
    )
    recorder.start_run("task", "/target")
    recorder.finish_run("completed", None)
    monkeypatch.setattr(trajectory_module.os, "replace", lambda *_: (_ for _ in ()).throw(OSError("replace failed")))

    with pytest.raises(OSError, match="replace failed"):
        recorder.finalize({"target_directory": "/target", "compressed_findings": []})

    assert not recorder.metadata_file.exists()
    assert not list(tmp_path.glob("*.tmp"))


@pytest.mark.parametrize("failure_stage", ["write", "flush", "fsync"])
def test_production_append_failure_leaves_an_uncommitted_prefix(
    tmp_path, monkeypatch, failure_stage
):
    recorder = TrajectoryRecorder(
        run_id=str(uuid.uuid4()),
        output_dir=str(tmp_path),
        contract_version=PRODUCTION_CONTRACT_VERSION,
    )
    recorder.start_run("task", "/target")
    append_error = OSError(f"{failure_stage} failed")
    original_open = Path.open

    class FailingAppend:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.stream.close()

        def write(self, text):
            if failure_stage == "write":
                self.stream.write(text[:20])
                raise append_error
            return self.stream.write(text)

        def flush(self):
            self.stream.flush()
            if failure_stage == "flush":
                raise append_error

        def fileno(self):
            return self.stream.fileno()

    def faulty_open(path, mode="r", *args, **kwargs):
        stream = original_open(path, mode, *args, **kwargs)
        if path == recorder.trajectory_file and mode == "a":
            return FailingAppend(stream)
        return stream

    def fail_fsync(_fd):
        raise append_error

    with monkeypatch.context() as fault:
        fault.setattr(Path, "open", faulty_open)
        if failure_stage == "fsync":
            fault.setattr(trajectory_module.os, "fsync", fail_fsync)
        with pytest.raises(OSError) as raised:
            recorder.record_step("observation", {"value": 1})

    assert raised.value is append_error
    prefix = recorder.trajectory_file.read_bytes()
    assert recorder.last_seq == 1
    if failure_stage == "write":
        assert not prefix.endswith(b"\n")

    with pytest.raises(RuntimeError, match="unusable"):
        recorder.finish_run(
            "failed", {"stage": "graph_execution", "type": "OSError", "message": str(append_error)}
        )
    with pytest.raises(RuntimeError, match="unusable"):
        recorder.finalize({"compressed_findings": []})

    assert recorder.trajectory_file.read_bytes() == prefix
    assert not recorder.metadata_file.exists()
