# Production evidence contract — v2

This is the current artifact contract. It supersedes the proposed v1 format in
`production-evidence-capture-plan.md`. Implementation and tests remain authoritative.
The production CLI uses `cipherloop-production-v2`; unversioned recorder defaults
retain their historical behavior. Checkpoint v1 captures lack the closure fields
and are **unsupported**, never upgraded, repaired, or routed through legacy ingestion.

CipherLoop records observations and reconciles its own state. TraceForge independently
checks artifacts. Neither a producer `completed` outcome nor a TraceForge integrity
`PASS` means the target is safe, an audit succeeded, or a vulnerability is exploitable.

## Files and event envelope

A bundle consists of `trajectory_<UUID>.jsonl` and `metadata_<UUID>.json`. UUIDs use
canonical full form. The producer reserves a fresh ledger exclusively; resume,
concurrent writers, and overwriting prior runs are unsupported. Readers require a
quiescent copied bundle. The original target and metadata's `trajectory_file` are
provenance strings, never paths for the evaluator to open.

Every row has exactly `contract_version`, `run_id`, `seq`, `timestamp`, `step_type`,
and `payload`. `seq` is a contiguous integer starting at 1; references are positive
integer sequence numbers of earlier events in the same ledger. Booleans are not
integers. Recording timestamps are finite epoch seconds, not durations. JSONL must
end in a newline. Duplicate JSON keys, nonfinite numbers, mixed versions, unknown
events, invalid types, and inconsistent references are rejected by the reader.

## Observations

| Event | Required payload and meaning |
| --- | --- |
| `run.started` | `task:{description}`, `target_directory`, `tool_capture_boundary:"compressor_observed"`, `models:null`. First event, before preflight. Task is the original CLI plan. |
| `message` | Existing AI tool-call or ToolMessage payload. AI has `type`, `role`, `content`, `tool_calls`; tool result has `type`, `role`, `content`, `tool_name`, `tool_call_id`. Captured at compressor observation, not tool dispatch. |
| `compression` | `raw_result_ref`, zero-based global `state_index`, exact `finding` dictionary including character counts. Persisted before returning the reducer update. |
| `validation.started` | `cycle` (contiguous from 1), `compressed_findings_count`, `verified_findings_count` from the validator's input state. Appended on entry, including empty or subsequently aborted cycles. Its sequence is `cycle_ref`. |
| `validation.candidate` | Existing integer `cycle`, plus `cycle_ref`, `compression_ref`, zero-based `summary_index`, exact `summary`. One event per selected summary occurrence before parsing. This name intentionally preserves the checkpoint naming. |
| `source.read` | `candidate_ref`, exact `arguments:{filepath,start_line,end_line}`, `status`, `text`, `text_sha256`, `error`. Read range remains 1–1,000,000. On return: status `returned`, text and SHA-256 of UTF-8 text, null error. On caught exception: status `error`, null text/hash, `{stage:"validation_read",type,message}`. Persisted before AST analysis. |
| `validation.decision` | `candidate_ref`, `disposition`, `reason`, `source_read_ref`, `finding`, `source_slice`. See below. |
| `validation` | Existing `total_candidates`, `verified_count`, `rejected_count`, `candidate_to_verified_ratio`, integer `cycle`, plus `cycle_ref`. Marks a fully observed cycle. Parsed candidates = verified + rejected; skipped summaries are excluded. Ratio is candidates/verified or null. |
| `run.finished` | `execution_status: completed/failed/interrupted`, `error`. Last event. Completed requires null error; failure/interruption requires `{stage,type,message}`. This observes execution end, not publication or task success. |

Verified decisions contain the exact existing upstream finding and null reason.
The finding's ID, description, severity, source, sink, taint path, evidence description,
literal confidence `0.9`, and status `VERIFIED` retain existing meanings. Confidence
is not calibrated. A verified slice is `{source_read_ref,start_line,end_line}` and
covers the minimum/maximum lines of the full accepted path, inclusively.

Rejected decisions have null finding and one of `read_exception`, `read_error_marker`,
`syntax_error`, `no_taint_trace`. Syntax/no-trace rejections reference the full analyzed
text span if nonempty, otherwise null; read failures have null slices. Skipped
decisions use `malformed_summary`, with null read, finding, and slice. These record
the producer's branch; a no-trace rejection is not an independent safety verdict.

Source evidence remains local, separate from `AuditState.messages`. Hashes cover
the exact returned string analyzed by the validator. The filesystem tool currently
decodes with replacement and strips output; line numbers refer to analyzed text,
which may differ from physical-file line numbers. No repository coverage or original
byte snapshot is claimed. Source acquisition still uses the existing POSIX sandbox
tool boundary; no host-target fallback or cloud source upload is introduced.

## Final commitment and failure semantics

Metadata preserves the existing fields: `run_id`, `target_directory`, `final_plan`,
`total_retries`, `compressed_findings_count`, `trajectory_file`,
`total_raw_char_count`, `total_compressed_char_count`, `compression_ratio`.
Counts describe retained tool-output dictionaries and characters, not vulnerabilities,
tokens, cost, or recovery. The compressed size is sorted, Unicode-preserving JSON
of the dictionary before adding its two size fields.

V2 additionally requires:

- `contract_version`, `start_ref`, `finish_ref`, `execution_status`, `event_count`;
- `ledger_sha256`: SHA-256 of exact finalized JSONL bytes;
- `evidence_status:"complete"`: commitment to the observed capture scope, including
  captures of failed execution; this is not a producer reliability grade;
- `final_compression_refs`: ordered compression occurrences retained by the last
  yielded state, preserving its prefix and exact dictionaries;
- `final_finding_refs`: ordered verified decision occurrences from completed
  validation cycles retained by the last yielded state. Multiplicity is preserved;
  repeated finding IDs never select or deduplicate evidence;
- `report_ref:null`: the current recorder does not capture the synthesizer report.
  `models:null` likewise denotes unavailable provenance, not inferred defaults.

Completed execution requires all observed compressions to have reached validation,
no unfinished cycle, and full reconciliation of compressed/verified state. Failed
or interrupted execution may retain a shorter state prefix: a node can durably
record decisions before its reducer update is lost. Such observations remain in
the ledger and are not promoted into final references. A prefix cannot end midway
through a validator's returned finding batch.

Each append is flushed and fsynced. An append I/O failure permanently poisons that
recorder; later appending or finalization is refused. A running digest of successful
writes prevents same-line-count edits from being committed. Serialization errors
before an append can still be followed by a recorded failed lifecycle.

The producer fsyncs a metadata temporary file, atomically publishes it in the same
directory, then fsyncs that directory on POSIX. A directory-sync exception attempts
to revoke the newly published metadata and propagates. Windows has no directory
fsync through this implementation. Publication requires filesystem cooperation;
power-loss survival and revocation when the filesystem denies cleanup are not
guaranteed. Readers must reject missing or damaged artifacts; checksums do not
authenticate a producer able to rewrite all files.

| Observed files/outcome | Interpretation |
| --- | --- |
| Valid commitment + completed | Completed observed execution; evaluate artifact integrity separately. Zero findings is not a safety claim. |
| Valid commitment + failed/interrupted | Durable execution-failure evidence, never a successful negative. |
| Missing commitment, even with completed finish event | Incomplete, possibly still running; no guessed termination cause. |
| Torn, altered, inconsistent, or unsupported evidence | Refuse normal ingestion. Never silently omit malformed rows or downgrade versions. |
| Reservation/start/storage fails before durable recording | No promise of a terminal event; caller sees the error. Uncatchable termination may leave only a prefix. |

## Independent handoff and demonstrated scope

TraceForge's separate `adapters/cipherloop_production.py` accepts the two artifacts
without importing CipherLoop. It validates versions, lifecycle, sequence/ref types,
call/result relationships, compression selection/counts, candidate/read/decision
relationships, cycle arithmetic, source hashes/slices, final prefixes, and finding
symbols at their stated AST locations. It does not rerun the producer's taint
analysis or introduce a detection oracle.

Its separate `traceforge-cipherloop-production-v1` result reports integrity/source
location `PASS`, or `ERROR` for unavailable source validation and observed execution
failure. Malformed/incomplete/incompatible artifacts raise an explicit categorized
input error. There is no `outcome.success` or generic score. The existing frozen
TraceForge two-case baseline and its PASS/FAIL/ERROR oracle remain unchanged.

`scripts/capture_production_smoke.py --output <fresh-directory>` produces six
self-contained bundles through the real CLI, LangGraph reducers, compressor,
validator, and recorder, using explicitly scripted tool results and source reads.
Verified, zero-candidate, rejected, read-failure, failed, and interrupted cases are
reproducible offline. No tactical execution or live model audit is represented.
See TraceForge `docs/cipherloop-production.md` for copying and ingestion commands.

Contract checks live in `tests/test_production_contract.py`,
`tests/test_production_evidence.py`, and the existing recorder/validator/compressor
tests. TraceForge's independent adversarial checks live in
`tests/test_cipherloop_production.py`. The next milestone is a bounded live sandbox
capture passed unchanged to this reader, preserving these offline regression gates.

## Closure verification — 2026-09-12

Initial state matched the requested SHAs: CipherLoop `37fcbe4` on
`feat/production-evidence-capture`, clean, tracking the same origin commit;
TraceForge `25668c4` on `main`, tracking origin/main, with the pre-existing deletion
of `tatus --short --branch`. No additional AGENTS.md was found in TraceForge or in
closer source/test scopes. The complete CipherLoop feature delta and checkpoint
were reviewed against source/tests. Valid checkpoint protections were retained.

Final checks (Python 3.12, existing venv plus isolated declared-dependency overlay):

```sh
# CipherLoop root: final focused and full suites.
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=venv/lib/python3.12/site-packages:/tmp/cipherloop-closure-deps:src timeout 60s venv/bin/python -m pytest -q tests/test_trajectory.py tests/test_compressor.py tests/test_validator.py tests/test_production_evidence.py tests/test_production_contract.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=venv/lib/python3.12/site-packages:/tmp/cipherloop-closure-deps:src timeout 60s venv/bin/python -m pytest -q
venv/bin/ruff check src/cipherloop/core/trajectory.py src/cipherloop/executor/validator.py tests/test_trajectory.py tests/test_validator.py tests/test_production_evidence.py tests/test_production_contract.py scripts/capture_production_smoke.py
PYTHONPATH=venv/lib/python3.12/site-packages:/tmp/cipherloop-closure-deps venv/bin/python -m pip check

# Actual TraceForge feature worktree: independent production checks.
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=src:/home/abundance333/Desktop/Projects/CipherLoop/venv/lib/python3.12/site-packages:/tmp/cipherloop-closure-deps /home/abundance333/Desktop/Projects/CipherLoop/venv/bin/python -m pytest -q -p no:cacheprovider tests/test_cipherloop_production.py
/home/abundance333/Desktop/Projects/CipherLoop/venv/bin/ruff check --no-cache scripts/generate_cipherloop_baseline.py src/traceforge tests/conftest.py tests/test_cipherloop_adapter.py tests/test_cipherloop_baseline.py tests/test_baseline_operations.py tests/test_cipherloop_production.py

# Isolated /tmp/traceforge-production-check/TraceForge layout, with unchanged
# baseline files, byte-identical new adapter/tests, and a clean sibling CipherLoop
# clone of main at the baseline's required f03a1e1. No active branch was repinned.
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 LANGSMITH_TRACING=false PYTHONPATH=/tmp/traceforge-production-check/TraceForge/src:/home/abundance333/Desktop/Projects/CipherLoop/venv/lib/python3.12/site-packages:/tmp/cipherloop-closure-deps /home/abundance333/Desktop/Projects/CipherLoop/venv/bin/python -m pytest -q -p no:cacheprovider
```

Results: **60 focused / 73 full CipherLoop tests passed**; **57 production / 119
combined TraceForge tests passed**, including all **62 frozen-baseline regressions**.
Both scoped lint commands and dependency consistency passed. Final actual reader
and tests were byte-compared with the isolated copy used for the combined suite.

The final smoke command was:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=venv/lib/python3.12/site-packages:/tmp/cipherloop-closure-deps:src timeout 60s venv/bin/python scripts/capture_production_smoke.py --output /tmp/cipherloop-production-smoke
```

The six bundles were copied to `/tmp/cipherloop-copied-bundles` and ingested twice
using `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -S` from TraceForge. Every
scenario matched the expected PASS/ERROR and final-finding count; repeated results
were identical, both input files stayed byte-identical, and no CipherLoop module
was imported. Detailed results are in `/tmp/cipherloop-production-evaluation.json`.
Those `/tmp` artifacts are session outputs; the retained smoke script and documented
commands are the durable reproduction path.

Setup limitations were separate from product failures: the initial environment
lacked `typer`, `langchain-openai`, and `jsonschema`; declared dependencies were
installed into `/tmp/cipherloop-closure-deps`, prioritizing existing venv packages
to preserve their compatible resolution. `pip check` then passed. Async graph tests
stalled in the command sandbox and passed outside it with runtime services mocked.
An initial local clone hit a cross-device hardlink error; `--no-hardlinks` fixed it.
Two new test assertions were corrected: one matched the substring in the explicit
`task_success`-unavailable label, and another incorrectly assumed the legacy harness
had not already imported CipherLoop. A separate Python `-S` subprocess now tests
runtime independence directly.

Inherited debt: `venv/bin/ruff check .` reports the same **31 CipherLoop diagnostics**
as the untouched checkpoint, with zero added file/rule/message diagnostics. A broader
TraceForge lint experiment including its immutable fixture source files reports two
existing import-order diagnostics; its authoritative CI lint scope above passes.
No fixture, unrelated code, or existing environment was rewritten to silence debt.

Final changes are local and uncommitted. CipherLoop remains on its original feature
branch at `37fcbe4`; TraceForge uses `feat/cipherloop-production-ingestion` at
`25668c4`, without an upstream. The pre-existing TraceForge deletion remains intact.
No push, merge, rebase, reset, clean, hosted CI, live scanner/model audit, or cloud
deployment was performed. Windows directory durability and storage-denied cleanup
remain unverified limits. There are no unresolved field ambiguities for this v2
slice; live runtime ordering and physical-file fidelity remain bounded follow-ups.
