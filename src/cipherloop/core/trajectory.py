import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Literal

from langchain_core.messages import AIMessage, BaseMessage, ToolMessage

PRODUCTION_CONTRACT_VERSION = "cipherloop-production-v2"
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
        self._compression_refs: dict[int, int] = {}
        self._validation_cycle = 0
        self._append_failed = False
        self._ledger_hash = hashlib.sha256()

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
        if self._append_failed:
            raise RuntimeError("Production ledger is unusable after an append failure")
        if self._finish_ref is not None:
            raise RuntimeError("Cannot record events after run.finished")
        if not isinstance(step_type, str) or not step_type:
            raise ValueError("Production step_type must be a non-empty string")
        if not isinstance(data, dict):
            raise TypeError("Production event payload must be a JSON object")
        if self._start_ref is None and (step_type != "run.started" or self._seq != 0):
            raise RuntimeError("Production ledger must begin with run.started")
        if self._start_ref is not None and step_type == "run.started":
            raise RuntimeError("run.started has already been recorded")

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
        try:
            with self.trajectory_file.open("a", encoding="utf-8", newline="\n") as f:
                f.write(serialized + "\n")
                f.flush()
                os.fsync(f.fileno())
        except BaseException:
            # The append may have left partial or unsynchronized bytes. Never reuse it.
            self._append_failed = True
            raise
        self._seq = next_seq
        self._ledger_hash.update((serialized + "\n").encode("utf-8"))
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
                "tool_capture_boundary": "compressor_observed",
                "models": None,
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

    def record_message(self, msg: BaseMessage, role: str) -> int | None:
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

        return self.record_step("message", payload)

    def record_compression(
        self, raw_result_ref: int, state_index: int, finding: dict[str, Any]
    ) -> int:
        """Persist one production compression and retain its state-index reference."""
        if not self.is_production:
            raise RuntimeError("Compression evidence is available only in production mode")
        if state_index < 0:
            raise ValueError("Compression state_index must be non-negative")
        if state_index in self._compression_refs:
            raise RuntimeError(f"Compression evidence already exists for state index {state_index}")

        compression_ref = self.record_step(
            "compression",
            {
                "raw_result_ref": raw_result_ref,
                "state_index": state_index,
                "finding": finding,
            },
        )
        self._compression_refs[state_index] = compression_ref
        return compression_ref

    def compression_ref_for_state_index(self, state_index: int) -> int | None:
        """Return immutable production compression provenance for a state position."""
        if not self.is_production:
            return None
        return self._compression_refs.get(state_index)

    def next_validation_cycle(self) -> int:
        """Allocate the next recorder-local production validation cycle identity."""
        if not self.is_production:
            raise RuntimeError("Validation cycles are available only in production mode")
        self._validation_cycle += 1
        return self._validation_cycle

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

        self._finalize_production(summary, final_state)

    def _finalize_production(
        self, summary: dict[str, Any], final_state: dict[str, Any]
    ) -> None:
        if self._append_failed:
            raise RuntimeError("Production ledger is unusable after an append failure")
        if self._start_ref is None or self._finish_ref is None or self._execution_status is None:
            raise RuntimeError("Production metadata requires run.started and run.finished")
        if self._finish_ref != self._seq:
            raise RuntimeError("Production terminal event must be the final ledger event")

        ledger = self.trajectory_file.read_bytes()
        if not ledger.endswith(b"\n") or ledger.count(b"\n") != self._seq:
            raise RuntimeError("Production ledger is not a contiguous finalized event stream")
        if hashlib.sha256(ledger).digest() != self._ledger_hash.digest():
            raise RuntimeError("Production ledger changed after recording")
        rows = [json.loads(line) for line in ledger.splitlines()]
        references = self._reconcile_final_state(rows, final_state)

        production_summary = {
            **summary,
            **references,
            "contract_version": PRODUCTION_CONTRACT_VERSION,
            "start_ref": self._start_ref,
            "finish_ref": self._finish_ref,
            "execution_status": self._execution_status,
            "ledger_sha256": hashlib.sha256(ledger).hexdigest(),
            "event_count": self._seq,
            "evidence_status": "complete",
            "report_ref": None,
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
            try:
                self._sync_output_directory()
            except BaseException:
                # Publication has not succeeded. Revoke only this run's new commitment.
                self.metadata_file.unlink()
                raise
        finally:
            if temporary_file.exists():
                temporary_file.unlink()

    def _sync_output_directory(self) -> None:
        """Persist publication on POSIX; Windows has no directory-fsync API here."""
        if os.name == "posix":
            descriptor = os.open(self.output_dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    def _reconcile_final_state(
        self, rows: list[dict[str, Any]], final_state: dict[str, Any]
    ) -> dict[str, Any]:
        """Bind the last yielded reducer state to persisted occurrences, never finding IDs.

        This checks producer bookkeeping, not vulnerability truth or run reliability.
        A failed node can have durable observations absent from the last yielded state.
        """
        compressions = [row for row in rows if row["step_type"] == "compression"]
        compressed = final_state.get("compressed_findings", [])
        for index, row in enumerate(compressions):
            if row["payload"]["state_index"] != index:
                raise RuntimeError("Noncontiguous production compression state indices")
        def same_json(left, right):
            return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(
                right, sort_keys=True, allow_nan=False
            )

        if not same_json(compressed, [row["payload"]["finding"]
                                     for row in compressions[:len(compressed)]]):
            raise RuntimeError("Final compressed state does not match recorded evidence")

        verified = []
        retained_boundaries = {0}
        active_cycle = None
        validated_compression_count = 0
        pending = []
        for row in rows:
            kind, payload = row["step_type"], row["payload"]
            if kind == "validation.started":
                if active_cycle is not None:
                    raise RuntimeError("Overlapping validation cycles")
                active_cycle = row["seq"]
                validated_compression_count = payload["compressed_findings_count"]
                pending = []
            elif kind == "validation.decision" and payload["disposition"] == "verified":
                if active_cycle is None:
                    raise RuntimeError("Verified decision outside a validation cycle")
                pending.append(row)
            elif kind == "validation":
                if active_cycle is None or payload["cycle_ref"] != active_cycle:
                    raise RuntimeError("Validation aggregate has no matching start")
                verified.extend(pending)
                retained_boundaries.add(len(verified))
                active_cycle = None

        findings = final_state.get("verified_findings", [])
        if len(findings) not in retained_boundaries or not same_json(
            findings, [row["payload"]["finding"] for row in verified[:len(findings)]]
        ):
            raise RuntimeError("Final verified state does not match completed validation evidence")
        if self._execution_status == "completed" and (
            active_cycle is not None
            or len(findings) != len(verified)
            or len(compressed) != len(compressions)
            or validated_compression_count != len(compressions)
        ):
            raise RuntimeError("Completed run has unreconciled evidence")
        return {
            "final_compression_refs": [row["seq"] for row in compressions[:len(compressed)]],
            "final_finding_refs": [row["seq"] for row in verified[:len(findings)]],
        }
