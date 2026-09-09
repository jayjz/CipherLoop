import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Literal

from langchain_core.messages import AIMessage, BaseMessage, ToolMessage

PRODUCTION_CONTRACT_VERSION = "cipherloop-production-v1"
_EXECUTION_STATUSES = {"completed", "failed", "interrupted"}


class TrajectoryRecorder:
    """Append-only flight recorder for agent execution."""

    def __init__(
        self,
        run_id: str,
        output_dir: str = "./traces",
        *,
        contract_version: str | None = None,
    ):
        if contract_version not in (None, PRODUCTION_CONTRACT_VERSION):
            raise ValueError(f"Unsupported trajectory contract version: {contract_version}")

        self.run_id = run_id
        self.contract_version = contract_version
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.trajectory_file = self.output_dir / f"trajectory_{run_id}.jsonl"
        self.metadata_file = self.output_dir / f"metadata_{run_id}.json"
        self._seq = 0
        self._start_ref: int | None = None
        self._finish_ref: int | None = None
        self._execution_status: Literal["completed", "failed", "interrupted"] | None = None

        if self.is_production:
            self._validate_production_run_id()
            self._reserve_production_paths()

    @property
    def is_production(self) -> bool:
        return self.contract_version == PRODUCTION_CONTRACT_VERSION

    @property
    def last_seq(self) -> int:
        return self._seq

    def _validate_production_run_id(self) -> None:
        try:
            parsed = uuid.UUID(self.run_id)
        except (AttributeError, ValueError) as exc:
            raise ValueError("Production run_id must be a full UUID") from exc
        if str(parsed) != self.run_id:
            raise ValueError("Production run_id must use canonical full UUID form")

    def _reserve_production_paths(self) -> None:
        """Reserve only the ledger; metadata is the finalization commitment."""
        if os.path.lexists(self.metadata_file):
            raise FileExistsError(f"Production metadata path already exists: {self.metadata_file}")
        self.trajectory_file.open("x", encoding="utf-8").close()

    def record_step(self, step_type: str, data: dict[str, Any]) -> int | None:
        """Append a single step to the JSONL ledger."""
        if self.is_production:
            return self._record_production_step(step_type, data)

        record = {
            "timestamp": time.time(),
            "run_id": self.run_id,
            "step_type": step_type,
            "payload": data,
        }
        with open(self.trajectory_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")
        return None

    def _record_production_step(self, step_type: str, data: dict[str, Any]) -> int:
        if self._finish_ref is not None:
            raise RuntimeError("Cannot record events after run.finished")
        if not isinstance(step_type, str) or not step_type:
            raise ValueError("Production step_type must be a non-empty string")
        if not isinstance(data, dict):
            raise TypeError("Production event payload must be a JSON object")

        next_seq = self._seq + 1
        record = {
            "contract_version": PRODUCTION_CONTRACT_VERSION,
            "run_id": self.run_id,
            "seq": next_seq,
            "timestamp": time.time(),
            "step_type": step_type,
            "payload": data,
        }
        serialized = json.dumps(record, allow_nan=False, separators=(",", ":"))
        with self.trajectory_file.open("a", encoding="utf-8", newline="\n") as f:
            f.write(serialized + "\n")
            f.flush()
            os.fsync(f.fileno())
        self._seq = next_seq
        return next_seq

    def start_run(self, task_description: str, target_directory: str) -> int:
        """Record the production lifecycle start after artifact reservation."""
        if not self.is_production:
            raise RuntimeError("run.started is available only in production mode")
        if self._start_ref is not None:
            raise RuntimeError("run.started has already been recorded")
        if not isinstance(task_description, str) or not isinstance(target_directory, str):
            raise TypeError("Production run.started fields must be strings")

        self._start_ref = self.record_step(
            "run.started",
            {
                "task": {"description": task_description},
                "target_directory": target_directory,
            },
        )
        return self._start_ref

    def finish_run(
        self,
        execution_status: Literal["completed", "failed", "interrupted"],
        error: dict[str, str] | None,
    ) -> int:
        """Record exactly one observed production terminal lifecycle event."""
        if not self.is_production:
            raise RuntimeError("run.finished is available only in production mode")
        if self._start_ref is None:
            raise RuntimeError("run.finished requires run.started")
        if self._finish_ref is not None:
            raise RuntimeError("run.finished has already been recorded")
        if execution_status not in _EXECUTION_STATUSES:
            raise ValueError(f"Invalid execution status: {execution_status}")
        if execution_status == "completed":
            if error is not None:
                raise ValueError("Completed runs must not carry an error")
        else:
            if not isinstance(error, dict) or set(error) != {"stage", "type", "message"}:
                raise ValueError("Failed/interrupted runs require a structured error")
            if not all(isinstance(error[key], str) for key in error):
                raise TypeError("Production error fields must be strings")

        self._finish_ref = self.record_step(
            "run.finished",
            {"execution_status": execution_status, "error": error},
        )
        self._execution_status = execution_status
        return self._finish_ref

    def record_message(self, msg: BaseMessage, role: str):
        """Serialize LangChain messages for the trajectory ledger."""
        payload = {
            "type": type(msg).__name__,
            "role": role,
            "content": msg.content if hasattr(msg, "content") else str(msg),
        }
        if isinstance(msg, AIMessage) and hasattr(msg, "tool_calls") and msg.tool_calls:
            payload["tool_calls"] = msg.tool_calls

        if isinstance(msg, ToolMessage):
            payload["tool_name"] = getattr(msg, "name", "unknown")
            payload["tool_call_id"] = getattr(msg, "tool_call_id", "unknown")

        self.record_step("message", payload)

    def finalize(self, final_state: dict[str, Any]):
        """Write final metadata and summary for trajectory evaluation."""
        findings = final_state.get("compressed_findings", [])
        total_raw_char_count = sum(
            finding.get("raw_char_count", 0)
            for finding in findings
            if isinstance(finding.get("raw_char_count", 0), int)
        )
        total_compressed_char_count = sum(
            finding.get("compressed_char_count", 0)
            for finding in findings
            if isinstance(finding.get("compressed_char_count", 0), int)
        )
        summary = {
            "run_id": self.run_id,
            "target_directory": final_state.get("target_directory"),
            "final_plan": final_state.get("current_plan"),
            "total_retries": final_state.get("retries", 0),
            "compressed_findings_count": len(final_state.get("compressed_findings", [])),
            "trajectory_file": str(self.trajectory_file),
            "total_raw_char_count": total_raw_char_count,
            "total_compressed_char_count": total_compressed_char_count,
            "compression_ratio": (
                total_raw_char_count / total_compressed_char_count
                if total_compressed_char_count
                else None
            ),
        }
        if not self.is_production:
            with open(self.metadata_file, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2, default=str)
            return

        self._finalize_production(summary)

    def _finalize_production(self, summary: dict[str, Any]) -> None:
        if self._start_ref is None or self._finish_ref is None or self._execution_status is None:
            raise RuntimeError("Production metadata requires run.started and run.finished")
        if self._finish_ref != self._seq:
            raise RuntimeError("Production terminal event must be the final ledger event")

        ledger = self.trajectory_file.read_bytes()
        if not ledger.endswith(b"\n") or ledger.count(b"\n") != self._seq:
            raise RuntimeError("Production ledger is not a contiguous finalized event stream")

        production_summary = {
            **summary,
            "contract_version": PRODUCTION_CONTRACT_VERSION,
            "start_ref": self._start_ref,
            "finish_ref": self._finish_ref,
            "execution_status": self._execution_status,
            "ledger_sha256": hashlib.sha256(ledger).hexdigest(),
            "event_count": self._seq,
        }
        serialized = json.dumps(production_summary, indent=2, allow_nan=False) + "\n"
        temporary_file = self.output_dir / f".{self.metadata_file.name}.{uuid.uuid4().hex}.tmp"
        try:
            with temporary_file.open("x", encoding="utf-8", newline="\n") as f:
                f.write(serialized)
                f.flush()
                os.fsync(f.fileno())
            if os.path.lexists(self.metadata_file):
                raise FileExistsError(f"Production metadata path already exists: {self.metadata_file}")
            os.replace(temporary_file, self.metadata_file)
        finally:
            if temporary_file.exists():
                temporary_file.unlink()
