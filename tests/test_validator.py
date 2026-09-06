from types import SimpleNamespace

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
