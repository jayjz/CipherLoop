"""Sandboxed fallback scanner used when Semgrep is unavailable."""

from __future__ import annotations

import json
from typing import Any

from cipherloop.tools.filesystem import _validate_path, execute_in_sandbox

# These deliberately broad patterns provide a small, offline signal when the
# primary rules engine cannot run.  They are not a replacement for Semgrep.
FALLBACK_PATTERN = r"(os\.system\(|subprocess\.(run|call|Popen)\(|eval\(|exec\(|password\s*=|secret\s*=|api[_-]?key\s*=)"


def run_fallback_scanner(target_path: str, *, original_error: str) -> dict[str, Any]:
    """Run ripgrep in the sandbox and return a Semgrep-shaped result document."""
    safe_path = _validate_path(target_path)
    output = execute_in_sandbox(["rg", "-n", "--no-heading", "-e", FALLBACK_PATTERN, safe_path])

    # ripgrep uses exit status 1 to communicate a successful scan with no
    # matches.  The shared executor represents every non-zero code as text.
    if output.startswith("Tool Execution Error (Code 1):"):
        output = ""
    elif output.startswith(("System Error:", "Tool Execution Error")):
        raise RuntimeError(output)

    findings: list[dict[str, Any]] = []
    if output and output != "Command executed successfully with no output.":
        for match in output.splitlines():
            # rg -n's conventional output is path:line:matched text.  Splitting
            # only twice also preserves colons inside source code.
            parts = match.split(":", 2)
            if len(parts) != 3 or not parts[1].isdigit():
                continue
            path, line, snippet = parts
            findings.append(
                {
                    "check_id": "cipherloop.fallback-regex",
                    "path": path,
                    "start": {"line": int(line)},
                    "extra": {
                        "message": "Fallback regex scanner matched a potentially risky pattern.",
                        "metadata": {"fallback_used": True, "snippet": snippet},
                    },
                }
            )

    return {
        "results": findings,
        "errors": [],
        "fallback_used": True,
        "original_error": original_error,
    }


def fallback_result_json(target_path: str, *, original_error: str) -> str:
    """Serialize fallback findings for the existing Semgrep tool contract."""
    return json.dumps(run_fallback_scanner(target_path, original_error=original_error))
