import json

from cipherloop.core.trajectory import TrajectoryRecorder


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
