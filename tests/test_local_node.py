import json
import subprocess

from cipherloop.executor import local_node


def test_semgrep_success_does_not_trigger_fallback(monkeypatch):
    success = '{"results": [], "errors": []}'
    monkeypatch.setattr(local_node, "_run_semgrep", lambda path: success)
    monkeypatch.setattr(
        local_node,
        "_run_fallback_tool",
        lambda path, error: (_ for _ in ()).throw(AssertionError()),
    )

    assert local_node.run_semgrep_with_fallback.invoke({"target_path": "."}) == success


def test_semgrep_crash_triggers_fallback(monkeypatch):
    monkeypatch.setattr(
        local_node,
        "_run_semgrep",
        lambda path: (_ for _ in ()).throw(subprocess.CalledProcessError(2, "semgrep")),
    )
    monkeypatch.setattr(
        local_node,
        "_run_fallback_tool",
        lambda path, error: json.dumps(
            {"results": [], "fallback_used": True, "original_error": error}
        ),
    )

    result = json.loads(local_node.run_semgrep_with_fallback.invoke({"target_path": "src"}))
    assert result["fallback_used"] is True
    assert "returned non-zero exit status 2" in result["original_error"]


def test_semgrep_timeout_triggers_fallback(monkeypatch):
    monkeypatch.setattr(
        local_node,
        "_run_semgrep",
        lambda path: (_ for _ in ()).throw(subprocess.TimeoutExpired("semgrep", 30)),
    )
    monkeypatch.setattr(
        local_node,
        "_run_fallback_tool",
        lambda path, error: json.dumps({"results": [], "fallback_used": True}),
    )

    assert (
        json.loads(local_node.run_semgrep_with_fallback.invoke({"target_path": "."}))[
            "fallback_used"
        ]
        is True
    )


def test_both_tools_fail_gracefully(monkeypatch):
    monkeypatch.setattr(
        local_node, "_run_semgrep", lambda path: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    monkeypatch.setattr(
        local_node,
        "_run_fallback_tool",
        lambda path, error: (_ for _ in ()).throw(RuntimeError("fallback boom")),
    )

    result = json.loads(local_node.run_semgrep_with_fallback.invoke({"target_path": "."}))
    assert result["results"] == []
    assert result["fallback_used"] is True
    assert "fallback boom" in result["errors"][0]["message"]
