import json

from cipherloop.tools import fallback_tool

LIVE_FIXTURE_MATCH = (
    "app.py:8:    return subprocess.run(cmd, shell=True, "
    "capture_output=True, text=True).stdout"
)


def test_fallback_scanner_detects_live_subprocess_fixture(monkeypatch):
    commands = []
    monkeypatch.setattr(
        fallback_tool,
        "execute_in_sandbox",
        lambda command: commands.append(command) or LIVE_FIXTURE_MATCH,
    )

    result = fallback_tool.run_fallback_scanner(
        "app.py", original_error="Tool Execution Timeout: Sandbox command exceeded 30 seconds."
    )

    assert commands == [
        ["rg", "-n", "--no-heading", "-e", fallback_tool.FALLBACK_PATTERN, "app.py"]
    ]
    assert result["fallback_used"] is True
    assert result["original_error"].startswith("Tool Execution Timeout:")
    assert result["errors"] == []
    assert result["results"] == [
        {
            "check_id": "cipherloop.fallback-regex",
            "path": "app.py",
            "start": {"line": 8},
            "extra": {
                "severity": "WARNING",
                "message": "Fallback regex scanner matched a potentially risky pattern.",
                "metadata": {
                    "fallback_used": True,
                    "snippet": "    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout",
                },
            },
        }
    ]


def test_fallback_scanner_treats_ripgrep_exit_one_as_safe_zero_match(monkeypatch):
    monkeypatch.setattr(
        fallback_tool,
        "execute_in_sandbox",
        lambda _command: "Tool Execution Error (Code 1):\n",
    )

    result = fallback_tool.run_fallback_scanner("safe.py", original_error="semgrep failed")

    assert result == {
        "results": [],
        "errors": [],
        "fallback_used": True,
        "original_error": "semgrep failed",
    }


def test_fallback_result_json_is_structured_and_retains_provenance(monkeypatch):
    monkeypatch.setattr(fallback_tool, "execute_in_sandbox", lambda _command: LIVE_FIXTURE_MATCH)

    result = json.loads(fallback_tool.fallback_result_json("app.py", original_error="primary failed"))

    assert result["fallback_used"] is True
    assert result["original_error"] == "primary failed"
    assert result["results"][0]["extra"]["metadata"]["fallback_used"] is True
