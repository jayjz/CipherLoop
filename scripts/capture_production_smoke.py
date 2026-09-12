"""Offline production-contract smoke captures with explicitly scripted observations.

Runs the real CLI lifecycle, LangGraph reducers, compressor, validator and recorder.
No scanner, target application, Docker daemon, or model is executed. This demonstrates
the artifact boundary, not live audit behavior or detection accuracy.
"""

import argparse
import contextlib
import io
import json
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

from langchain_core.messages import AIMessage, ToolMessage
from langgraph.graph import END, START, StateGraph

from cipherloop import main
from cipherloop.core.state import AuditState
from cipherloop.core.trajectory import TrajectoryRecorder
from cipherloop.executor.compressor import compressor_node
from cipherloop.executor.validator import validator_node


def capture(output: Path, scenario: str) -> dict:
    """Create a fresh two-file run bundle through the production CLI boundary."""
    output.mkdir(parents=True, exist_ok=False)
    source = "import os\nx = input()\nos.system(x)\n"
    if scenario == "rejected":
        source = "import os\nx = 'constant'\nos.system(x)\n"
    results = [] if scenario == "zero" else [{
        "path": "app.py", "start": {"line": 3},
        "extra": {"severity": "ERROR", "message": "Command injection"},
    }]

    def observe(_state):
        return {"messages": [
            AIMessage(content="", tool_calls=[
                {"id": "smoke-scan", "name": "run_semgrep", "args": {"target_path": "app.py"}}
            ]),
            ToolMessage(content=json.dumps({"results": results}), name="run_semgrep",
                        tool_call_id="smoke-scan"),
        ]}

    def read(_arguments):
        if scenario == "read_failure":
            raise OSError("scripted unavailable source")
        return source

    def validate(state, config):
        if state["messages"]:
            raise AssertionError("Raw observations survived the message reducer")
        result = validator_node(state, config)
        if scenario == "failed":
            raise RuntimeError("scripted failure before validator state reduction")
        if scenario == "interrupted":
            raise KeyboardInterrupt("scripted interruption before validator state reduction")
        return result

    graph = StateGraph(AuditState)
    graph.add_node("observe", observe)
    graph.add_node("compressor", compressor_node)
    graph.add_node("validator", validate)
    graph.add_edge(START, "observe")
    graph.add_edge("observe", "compressor")
    graph.add_edge("compressor", "validator")
    graph.add_edge("validator", END)
    module = ModuleType("cipherloop.orchestrator.graph")
    module.build_graph = graph.compile
    recorders = []

    def recorder_factory(*args, **kwargs):
        recorder = TrajectoryRecorder(*args, output_dir=str(output), **kwargs)
        recorders.append(recorder)
        return recorder

    with (
        patch.object(main, "TrajectoryRecorder", recorder_factory),
        patch.object(main, "check_prerequisites"),
        patch.object(main, "ensure_sandbox_running"),
        patch.dict("sys.modules", {"cipherloop.orchestrator.graph": module}),
        patch("cipherloop.executor.validator.read_file", SimpleNamespace(invoke=read)),
        contextlib.redirect_stdout(io.StringIO()),
    ):
        try:
            main.audit(target="/offline-scripted-target", plan=f"Offline contract smoke: {scenario}; scripted tool result and source read")
        except (RuntimeError, KeyboardInterrupt):
            if scenario not in {"failed", "interrupted"}:
                raise
    recorder = recorders[0]
    metadata = json.loads(recorder.metadata_file.read_bytes())
    expected = scenario if scenario in {"failed", "interrupted"} else "completed"
    if metadata["execution_status"] != expected:
        raise AssertionError("Unexpected smoke execution outcome")
    if scenario in {"failed", "interrupted"}:
        finish = json.loads(recorder.trajectory_file.read_bytes().splitlines()[-1])["payload"]
        word = "failure" if scenario == "failed" else "interruption"
        if finish["error"]["message"] != f"scripted {word} before validator state reduction":
            raise AssertionError("Unexpected failure was not the scripted scenario")
    return {"scenario": scenario, "run_id": recorder.run_id, "directory": str(output),
            "execution_status": metadata["execution_status"]}


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    captures = [capture(args.output / scenario, scenario)
                for scenario in ("verified", "zero", "rejected", "read_failure", "failed", "interrupted")]
    print(json.dumps({"input_mode": "scripted observations; no tactical execution", "captures": captures}, indent=2))


if __name__ == "__main__":
    run()
