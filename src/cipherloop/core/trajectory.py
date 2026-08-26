import json
import time
from pathlib import Path
from typing import Any, Dict
from langchain_core.messages import BaseMessage, ToolMessage, AIMessage

class TrajectoryRecorder:
    """
    Append-only flight recorder for agent execution.
    Decouples full historical logging from the active, compressed LangGraph state.
    """
    def __init__(self, run_id: str, output_dir: str = "./traces"):
        self.run_id = run_id
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.trajectory_file = self.output_dir / f"trajectory_{run_id}.jsonl"
        self.metadata_file = self.output_dir / f"metadata_{run_id}.json"

    def record_step(self, step_type: str, data: Dict[str, Any]):
        """Appends a single step to the JSONL ledger."""
        record = {
            "timestamp": time.time(),
            "run_id": self.run_id,
            "step_type": step_type,
            "payload": data
        }
        with open(self.trajectory_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")

    def record_message(self, msg: BaseMessage, role: str):
        """Serializes LangChain messages for the trajectory ledger."""
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

    def finalize(self, final_state: Dict[str, Any]):
        """Writes the final metadata and summary for TraceForge evaluation."""
        summary = {
            "run_id": self.run_id,
            "target_directory": final_state.get("target_directory"),
            "final_plan": final_state.get("current_plan"),
            "total_retries": final_state.get("retries", 0),
            "compressed_findings_count": len(final_state.get("compressed_findings", [])),
            "trajectory_file": str(self.trajectory_file)
        }
        with open(self.metadata_file, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, default=str)
