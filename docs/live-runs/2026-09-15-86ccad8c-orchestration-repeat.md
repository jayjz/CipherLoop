# Live failure evidence: orchestration repetition

This artifact records failure evidence from a controlled live run. It is **not** successful-run evidence and must not be interpreted as a completed audit, a successful primary Semgrep scan, an AST `VERIFIED` decision, a TraceForge handoff, target safety, scanner accuracy, task success, or end-to-end agent reliability. The recorded bundle is a finalized interrupted-run bundle, not a successful or completed-audit bundle.

## Run identity and environment

- Run ID: `86ccad8c-ad2c-4e79-846a-720b08f2faeb`
- Date: 2026-09-15
- Environment: live Windows execution using the existing Docker sandbox; primary Semgrep execution was air-gapped in the sandbox.
- Controlled target: `C:\Users\jcoul\Desktop\Projects\cipherloop-live-fixture`
- Logical sandbox target: `/workspace/target_repo`
- Audit objective: Audit this Python app for command injection and remote code execution. Preserve evidence.

The observed controlled fixture accepted `request.args.get("cmd")` and passed the resulting value to `subprocess.run` with `shell=True`. The live search result located that sink at `app.py:8`.

## Exact observed sequence

1. CipherLoop initialized successfully.
2. Preflight found the target.
3. The existing Docker sandbox was accepted.
4. Cloud orchestration requested `list_directory`.
5. Local execution ran `list_directory /workspace/target_repo` and observed `app.py`.
6. `read_file` returned the vulnerable `app.py` source.
7. `search_code` found the `subprocess.run(..., shell=True, capture_output=True, text=True)` return at `./app.py:8`.
8. `run_semgrep` was attempted.
9. Primary Semgrep did not complete in the air-gapped sandbox and reached the deterministic 30-second sandbox command timeout.
10. CipherLoop invoked the fallback scanner.
11. The fallback scanner returned a structured candidate for `app.py:8` with `check_id` `cipherloop.fallback-regex`.
12. The planner requested `run_semgrep` again.
13. The second Semgrep invocation again timed out after 30 seconds.
14. The fallback again returned the same candidate.
15. The planner requested `run_semgrep` a third time.
16. The run was manually interrupted before that identical primary scan completed, because it added no new evidence and would consume additional model/API/runtime resources.

## Demonstrated by this run

- Cloud planner execution and local Ollama execution.
- Local text-tool-call compatibility normalization and ToolNode/tool execution.
- Docker `list_directory`, `read_file`, and `search_code` execution.
- Bounded in-container command timeout and Semgrep timeout classification.
- Semgrep-to-fallback transition, fallback regex execution, detection of `subprocess.run`, and explicit fallback provenance.

## Failure classification

The observed blocker is orchestration/non-progress behavior after useful fallback evidence was produced:

```text
Semgrep timeout
  fallback candidate
  planner requests Semgrep
  Semgrep timeout
  same fallback candidate
  planner requests Semgrep again
```

This does not establish that the planner is the sole root cause. Source inspection shows that `planner_node` summarizes state primarily by compressed-finding batch count and verified-sink count and includes a normalized-plan repeat guard. The run was interrupted before audit completion; no completed-audit outcome, final AST finding count, or TraceForge result is asserted here.

## Remaining hypotheses — not root-cause findings

- The planner may lack sufficient progress or tool-history information.
- Graph transition or compressor timing may prevent useful fallback evidence from being visible when planning occurs.
- Non-progress detection may operate at the wrong semantic level.

These are hypotheses only. The next investigation must trace the graph and state lifecycle to determine why the fallback evidence did not progress to validation/completion before another `run_semgrep` request.

## Artifact status and next bounded investigation

Read-only inspection found the following run artifacts:

- `traces/trajectory_86ccad8c-ad2c-4e79-846a-720b08f2faeb.jsonl` contains two events: `run.started` and `run.finished`.
- The `run.finished` event records `execution_status: "interrupted"` and `graph_execution/KeyboardInterrupt`.
- `traces/metadata_86ccad8c-ad2c-4e79-846a-720b08f2faeb.json` records `event_count: 2`, `execution_status: "interrupted"`, `evidence_status: "complete"`, and no final compression or finding references.
- The metadata's ledger SHA-256 is `9ce7b0757e2b3306ba888be2b3ebc0987dbbf448f21a46e8be83ae10b1c3b45c`; read-only hashing of the ledger matched it.

The contract's capture boundary is compressor observation. Accordingly, these two lifecycle events do not independently reproduce the observed tool sequence above; they establish an interrupted finalized bundle, not a completed audit. The first completed live production capture remains outstanding.

Next bounded investigation: trace planner, local execution, ToolNode, compressor, validator, and graph-transition state visibility for this run pattern; establish the actual non-progress mechanism before changing orchestration behavior.
