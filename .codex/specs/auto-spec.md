# Specification: Refactor `local_node` to Support Fallback Tool on Semgrep Crash

## 1. Goal Overview
The objective is to refactor `local_node` (specifically the Semgrep execution/analysis handler) so that if Semgrep crashes (raises an unhandled exception, encounters a process error, exits with a crash code, or times out), the execution gracefully catches the failure, logs a warning, and executes a fallback tool or scanner instead of failing the entire node pipeline.

---

## 2. Target Files
- `src/nodes/local_node.py` (or the primary module executing tool scans in `local_node`)
- `src/tools/fallback_tool.py` (if a standalone fallback runner exists or needs creation)
- `tests/test_local_node.py`

---

## 3. Technical Requirements

### 3.1 Exception & Crash Catching
- Wrap the primary Semgrep tool execution call in a try/except block catching:
  - `subprocess.CalledProcessError` (non-zero exit codes indicating process crash)
  - `subprocess.TimeoutExpired` (tool hangs)
  - `Exception` (general unexpected execution errors/crashes)
- Also check the returned process status or result structure for crash indicators (e.g., status code != 0 or explicit error flags).

### 3.2 Fallback Tool Invocation
- Introduce a fallback execution path when Semgrep fails.
- The fallback mechanism should:
  1. Log a warning event: `[WARN] Semgrep execution failed/crashed. Invoking fallback tool...` along with error details.
  2. Invoke the designated fallback tool (e.g., regex/ripgrep scanner or secondary analysis function).
  3. Mark execution metadata in the returned result structure (e.g., `fallback_used: True`, `original_error: <error_message>`).
  4. Format the output to match the expected schema/contract of `local_node` so downstream consumers receive valid data structure.

### 3.3 Configuration
- Allow the fallback tool or fallback strategy to be configurable or defaulted cleanly (e.g., via parameter or configuration object passed into `LocalNode` or `execute_tool`).

---

## 4. Implementation Steps

### Step 1: Update `local_node.py`
1. Locate the method responsible for running Semgrep (e.g., `run_semgrep` or `execute_analysis`).
2. Add a helper function or method `_run_fallback_tool(context, error)` to handle calling the fallback analyzer.
3. Modify Semgrep execution:
```python
try:
    results = self._run_semgrep(target_path, config)
    # Validate result isn't indicating a crash
    if results.get("status") == "crash" or results.get("returncode", 0) not in (0, 1):
        raise RuntimeError(f"Semgrep process crashed with return code {results.get('returncode')}")
except Exception as exc:
    logger.warning(f"Semgrep crashed: {exc}. Switching to fallback tool.")
    results = self._run_fallback_tool(target_path, config, error=str(exc))
```
4. Ensure the output dictionary/object contains:
   - `findings`: List of findings (from fallback)
   - `fallback_used`: `True`
   - `error`: Summary of Semgrep failure

### Step 2: Implement / Verify Fallback Execution Logic
1. Ensure the fallback tool is safely invoked with the target path.
2. If the fallback tool itself fails, catch the exception, log the error, and return a clean error result with `findings: []` rather than crashing the process.

### Step 3: Add Unit & Integration Tests
Add comprehensive test cases in `tests/test_local_node.py`:
1. **`test_semgrep_success_does_not_trigger_fallback`**: Verify standard execution uses Semgrep without activating fallback.
2. **`test_semgrep_crash_triggers_fallback`**: Mock Semgrep execution to raise `CalledProcessError` or `Exception`, verify fallback tool is called and returns expected schema with `fallback_used=True`.
3. **`test_semgrep_timeout_triggers_fallback`**: Mock Semgrep execution to raise `TimeoutExpired`, verify fallback tool is called.
4. **`test_both_tools_fail_gracefully`**: Mock both Semgrep and fallback tool to raise exceptions, verify node handles it gracefully without crashing the whole application.

---

## 5. Verification Commands

Run pytest to verify implementation:
```bash
pytest tests/test_local_node.py -v
```