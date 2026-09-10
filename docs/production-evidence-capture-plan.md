# CipherLoop production evidence capture plan

Original reconnaissance dated 2026-09-09. CipherLoop branch: `main`; HEAD:
`f03a1e186e491cf24aa0f0e0671cac766c1fa8ab`. Initial working tree was clean.
Sections 1–11 preserve that design and historical inventory; they are not a claim
that every proposed field or consumer has been implemented.

## P0.1 implementation and closure status — 2026-09-09

Reviewed `feat/production-evidence-capture` at
`7f9eddb2b3310ee0de8b01dda4e1559e914b4568`, with a clean initial worktree:

- **P0.1A**, `26e966839d337a4e74a7069a8e2e9c4880f89211`: explicit production mode,
  full UUID reservation, original task/start before preflight, observed
  completed/failed/interrupted outcomes, synchronized ledger writes, and atomic
  metadata publication with sequence count and ledger hash. Legacy mode remains.
- **P0.1B**, `7f9eddb2b3310ee0de8b01dda4e1559e914b4568`: exact compression records,
  `validation.candidate` attempts with integer `cycle`, source-read text/hash,
  verified/rejected/skipped decisions and reasons, verified source slices, and
  per-cycle aggregate counts. Source evidence stays outside active messages.
- **Closure fixes under review:** stop appending/finalizing after a possibly torn
  write; retain source reads before AST analysis can raise. Regression tests cover
  these failures without changing detection or the tested event format.

**Release contract unresolved.** The tested format differs from the design below:
there is no `validation.started`/`cycle_ref` (including on an aborted empty cycle),
and the event is `validation.candidate`, not `candidate`. Start events omit
`tool_capture_boundary` and `models`. Metadata omits `evidence_status`,
`final_finding_refs`, and `report_ref`; recorded verified decisions are not
reconciled with the last yielded state's verified findings. Rejection slices are
null even for nonempty syntax/no-trace inputs. Directory synchronization after
metadata publication is also absent. These are open closure items, not silently
waived requirements or instructions to migrate the tested format.

A committed failed run remains failure evidence. Missing metadata remains
incomplete; storage failure or uncatchable termination cannot guarantee a terminal
event. Completed execution and zero candidates do not prove scanner success, target
safety, or task success. TraceForge P0.2 ingestion and independent production
evaluation are separate work and have not been performed in this closure review.

### Offline closure verification

`README.md` documents `venv` and `pip install -e ".[dev]"`; `pyproject.toml`
declares pytest/Ruff and supplies the lint settings. The existing Python 3.12.3
environment lacked `typer` and `langchain-openai`. Declared dependencies were
installed into `/tmp/cipherloop-p01-deps` and `/tmp/cipherloop-p01-openai-deps`,
with `langchain-core==1.6.0` retained. The full-suite command below prioritizes
existing venv packages; `pip check` with that path reports no broken requirements.
The repository environment and dependency declarations were not changed.

Exact verification commands from the repository root:

```sh
PYTHONPATH=/tmp/cipherloop-p01-deps:src timeout 30s venv/bin/python -m pytest -q tests/test_trajectory.py tests/test_compressor.py tests/test_validator.py tests/test_production_evidence.py
PYTHONPATH=venv/lib/python3.12/site-packages:/tmp/cipherloop-p01-deps:/tmp/cipherloop-p01-openai-deps:src timeout 60s venv/bin/python -m pytest -q
venv/bin/ruff check .
venv/bin/ruff check src/cipherloop/core/trajectory.py src/cipherloop/executor/validator.py tests/test_trajectory.py tests/test_validator.py tests/test_production_evidence.py
git diff --check
git rev-parse HEAD main
git status --short --branch
```

Results: **39 focused tests passed; 52 full-suite tests passed**, including nine
added regression/integration cases. The four new append/analysis regression cases
first failed on the original implementation. Initial collection and configuration
failures were missing-package setup failures; the real async graph tests stalled
in the command sandbox and passed outside it with runtime services mocked. No
Docker or live model service was used. The full suite was rerun only after setup
failures were resolved.

Ruff 0.16.4 passes on all five Python files changed during closure. Repository-wide
Ruff still fails with **31 pre-existing diagnostics**: the same executable reports
52 on an isolated copy of `main`'s Python files/config, with no new diagnostics
by file/rule/message in the current tree. Unrelated lint cleanup was not performed.
`git diff --check` passes. P0.1 release closure remains blocked by that lint gate
and the unresolved release contract above.

## 1. Scope, instructions, and evidence inventory

Inspected `AGENTS.md`, `core/trajectory.py`, `executor/validator.py`, `main.py`,
`core/state.py`, focused trajectory/validator/compressor tests, the sibling
TraceForge baseline document, adapter, adapter tests, and normalized trajectory
schema. Source paths below are relative to `src/cipherloop/` unless qualified.
The one additional implementation file was `executor/compressor.py`: necessary
to establish actual recorder call sites, capture timing, and candidate selection.
No planner, graph, filesystem-tool implementation, scanner, or baseline generator
was inspected. Claims about their internal behavior are deliberately excluded.
No nested `AGENTS.md` was found in the inspected project paths; ancestor instruction
checks found no additional files. The local `specs` directory was absent.

`AGENTS.md` requires “ensure `pytest` passes before concluding a thread.” The
explicit reconnaissance request takes precedence: no implementation, dependency
installation, Docker, models, scanners, or runtime test execution. Source reads
are development reconnaissance, not tactical audit execution. Future target reads
must still use the sandbox and POSIX paths; evidence must never be appended to
`AuditState.messages` or sent as raw source to the cloud orchestrator.

### Current persisted artifacts (source facts)

Locations are relative to the CLI process working directory, not the audited
repository. No automatic cleanup appears in the inspected recorder.
“Survives” below means a successfully closed local write normally remains; there
is no `fsync`, transactional guarantee, or guarantee against power/storage failure.

| Artifact/event/fields | Actual producer and timing | Completed-run retention | Interrupted/failed-run retention | Current TraceForge consumption and ambiguity |
|---|---|---|---|---|
| `./traces/trajectory_<run_id>.jsonl` | `TrajectoryRecorder.record_step`, trajectory.py:19–28; append/open/close per row, file created on first event | Written rows remain; an eventless run need not create this file | Earlier rows normally remain; current row may be missing/torn | Baseline reads this name only inside its fixture bundle; ledger alone is insufficient |
| Every row: `timestamp`, `run_id`, `step_type`, `payload` | Recorder; `time.time()` at logging, run ID supplied by caller | Persisted verbatim, arbitrary values serialized with `default=str` | Same as ledger | Timestamp is recording time, not execution start/end; no version, sequence, terminal marker, unique event ID, or integrity commitment |
| `message`: `type`, `role`, `content`; AI `tool_calls` if nonempty (existing dictionaries include IDs/names/arguments) | `compressor_node`, compressor.py:68–79, records AI messages with calls from the current state | Raw message contents remain outside compressed state | Lost if failure precedes compressor observation | Adapter expands assistant AI calls; not all model messages are recorded; recording order is state-list order |
| `message`: ToolMessage `tool_name`, `tool_call_id`, plus common message fields | Same compressor loop, before compression | Raw tool result retained even when active state is sheared | A write may survive a subsequent compression error; execution failing before this boundary may leave no evidence | Adapter matches IDs and names, requires textual result; no exit code or explicit tool-success field; missing name may be null rather than fallback string |
| `validation`: `total_candidates`, `verified_count`, `rejected_count`, `candidate_to_verified_ratio` | `validator_node`, validator.py:226–238, after processing the whole compressed list | Aggregate per invocation retained | No event if invocation fails before its last record call | Adapter requires exactly one cycle after all results; candidate means parseable retained summary, not all scanner findings; ratio is candidates/verified, null at zero verified |
| `./traces/metadata_<run_id>.json`: `run_id`, `target_directory`, `final_plan`, `total_retries`, `compressed_findings_count`, `trajectory_file` | `finalize`, trajectory.py:46–75; CLI calls only after `asyncio.run` returns, main.py:159–160 | Written directly using mode `w` | Usually absent if execution fails; can be truncated if finalization fails; ID collision may leave stale metadata | Adapter requires sidecar/index and fixture-specific values; target is CLI-resolved host path; final plan is last plan, not original task/report; retries is a state counter, not recovery |
| Same metadata: `total_raw_char_count`, `total_compressed_char_count`, `compression_ratio` | Sum integer counts in final compressed dictionaries; ratio raw/compressed or null | Retained aggregates only | Same as metadata | Character counts, not bytes/tokens; compressed size is sorted JSON of dictionary before adding size fields; count of compressed dictionaries is count of processed tool outputs, not vulnerabilities |

### Relevant evidence that is not persisted

* CLI generates an eight-character UUID prefix after prerequisites and sandbox setup
  (main.py:116–124). Original `plan`, initial empty findings/messages and resolved
  target enter `AuditState`; the original task is not separately saved. Preflight
  failures occur before recorder creation. Constructor only creates the directory.
* `compressor_node` returns exact compressed dictionaries and `RemoveMessage` objects,
  but records neither. Semgrep processing retains at most five WARNING/ERROR
  summaries per output, ordered ERROR first. Other candidates and INFO findings
  can exist in raw JSON without ever reaching validation. Generic tools produce
  snippets, not `top_findings`. Messages without IDs cannot be removed by this loop.
* Validator silently skips malformed summaries. Parseable summaries become candidates;
  `verify_finding_evidence` calls sandbox `read_file` with lines 1–1,000,000. Exceptions,
  two error-text markers, syntax errors, and no matching AST trace all collapse to
  `None`. No read request/result, source snapshot, individual rejection, or reason
  is recorded. Read completeness and filesystem-tool decoding were not inspected.
* A successful candidate produces `VerifiedFinding`: `id`, `vulnerability_class`,
  `severity`, `source`/`sink` (file, line, symbol), `taint_path`, `evidence_snippet`,
  `confidence`, `status`. `status` is `VERIFIED`; confidence is the literal `0.9`;
  severity defaults to MEDIUM for unrecognized values (including ERROR/WARNING).
  `evidence_snippet` is an AST-path description, **not source code**. State declares
  optional `rejection_reason` but this producer never supplies it. These objects
  remain in memory only; finalization does not serialize them.
* `AuditState` adds compressed and verified lists through reducers. Validator iterates
  the entire compressed list on each invocation. Revalidation can repeat findings;
  IDs based on path/line are not unique decision IDs. This design must not deduplicate
  or alter that existing behavior. Graph cycle frequency was not inspected.
* CLI prints message previews (100 characters), verified counts, progress and a
  completion message. It does not save stdout, a final report, model provenance,
  start/end markers, errors, or interruption state in the inspected persistence path.
  No claim is made about uninspected external logging facilities.

### Current finalization reliability

There is no `try/finally` around graph import/build, streaming, or finalization.
Graph construction errors, stream/model/tool exceptions reaching the CLI,
`KeyboardInterrupt`, and process termination bypass `finalize`. Its direct JSON
write can fail halfway. The last yielded state can lag the node currently failing.
A metadata file is not an explicit successful-execution certificate, and absence
of findings is not evidence of a completed negative result.

## 2. Missing evidence matrix

“Required” means required for the narrow first production integration below, not
full evaluation of every aspect of an agent. Every requirement addresses a concrete
loss above or a check made by the existing adapter.

| Information | Current gap / baseline dependency | Classification and minimum response |
|---|---|---|
| Task/run identity | Last plan only; baseline substitutes fixture task and toy/safe IDs | **Required:** preserve original CLI plan, target and unique run identity; use run ID as task-instance identity; external task ID deferrable |
| Start/end, explicit state | Logging timestamps only; synthetic sidecar asserts completed | **Required:** start event, observed execution end, committed summary; missing commit stays incomplete |
| Tool calls/results | Captured only at compressor; adapter needs ID/name/args/raw result | **Required:** retain existing rows and references, declare observation boundary; complete dispatch tracing **deferrable** and not currently measurable |
| Candidate findings | Raw output persists but selected summaries do not; baseline reconstructs exact compression | **Required:** exact compressed record linked to raw result, candidate occurrence/index per validation attempt; do not equate all scanner hits with validated candidates |
| Verified findings | Only in state; baseline sidecar provides objects | **Required:** persist each exact upstream finding with decision and source references |
| Rejections/reasons | Only counts; baseline source and oracle establish safe case | **Required:** branch-specific rejected/skipped decisions; no-trace means no recognized trace, not safe code |
| Validation events | Aggregate only; baseline assumes one | **Required:** cycle identity, start/end, candidate decisions and existing aggregate counts |
| Source reads | Hidden validator call; sidecar supplies read arguments/status | **Required:** exact arguments, result/error observation and immutable text analyzed, linked to decision |
| Source-code slices | AST-path prose only; sidecar supplies source.py and slice | **Required:** retained analyzed text plus line-span references covering path endpoints/intermediates; no dependency on live target |
| Final report | No report emitted in inspected path; baseline says unavailable | **Unsupported currently:** explicit null report reference; structured findings serve evidence, not a fabricated report |
| Model/provider provenance | Dropped by recorder; baseline says unavailable | **Useful but deferrable:** optional observed role/provider/model entries; no inferred model from environment/defaults |
| Errors/interruption | Not persisted; missing metadata ambiguous | **Required:** outer lifecycle failure stage/type/message when caught; fatal unobserved termination stays incomplete/unknown |
| Exact exception-origin node/tool | Not exposed at inspected CLI boundary | **Unsupported currently:** use graph_execution stage unless origin is directly known; later dispatch hooks optional |
| Shearing/recovery/safety | RemoveMessage requests visible in code, application result not recorded | **Deferrable:** reducer-level shearing proof needs separate instrumentation; no recovery or safety scores |
| Tokens/cost/rubric/detection accuracy | No production measurement or independent oracle | **Unsupported:** omit; no zero defaults, no confidence calibration or generic task-success score |

## 3. Proposed versioned contract

### Storage and compatibility boundary

Add an explicit recorder mode `contract_version="cipherloop-production-v1"`, used
by the production CLI. Unversioned recorder construction retains existing output
for historical harnesses. This is an explicit evidence-format migration, not a
change to planner, tool, compression, reducer or validation decisions.

Use existing `trajectory_<run_id>.jsonl` and `metadata_<run_id>.json`. Keep the old
row fields and metadata keys. In production mode add envelope fields and events
below. Keep raw tool messages where they already are; do not copy them to state.
Use full UUID run IDs and exclusively reserve a fresh ledger filename. Refuse
reuse; no append-to-old-run, resume, overwrite, or stale-summary fallback in v1.
Legacy mode preserves old ID/append behavior for compatibility.

Store source text **inline in a source-read event**, once per read observation.
This avoids another file/manifest transaction and retains precisely what the
validator analyzed even when target files disappear or change between reads.
Hash UTF-8 encoding of returned text, not alleged original file bytes. Source
line slices reference this immutable event; do not duplicate source text in each
finding. The 1,000,000-line request is not proof of complete physical-file capture.
V1 supports independent checking of the analyzed input, not repository-wide
coverage or authenticating the producer.

### Envelope and reusable types

All fields are required unless marked `O` (optional). `null` is allowed only where
explicitly stated. Strict JSON: reject duplicate keys, nonfinite numbers, unsupported
version/type, and bad reference types. Do not silently stringify contract evidence.
Existing legacy `message.content` retains its JSON-compatible string/list shape.

| Field/type | Producer/timing; example | Relationship, mapping, failure rule |
|---|---|---|
| `contract_version: string` | Recorder on every row and summary; `cipherloop-production-v1` | Required discriminator; unknown version is incompatible, never legacy fallback |
| `run_id: string` | CLI before preflight; full UUID | Existing identity retained; maps to trajectory_id; all references same run |
| `seq: integer >=1` | Recorder on successful append; 1, 2, … | New ordered event identity; gaps/duplicates invalidate complete evidence |
| `timestamp: finite number` | Recorder clock at append; `1788955200.25` | Existing seconds since epoch; normalized UTC; never tool execution duration |
| `step_type: string`, `payload: object` | Existing recorder envelope | Required payload schema by event; examples below |
| `EventRef = integer >=1` | Producer references earlier `seq` | Stable within run; adapter retains file/row/seq references; dangling refs are insufficient evidence |
| `Error = {stage: string, type: string, message: string}` | Catching boundary; e.g. graph_execution/RuntimeError/model request failed | Observed diagnosis only; no traceback/environment dump; type may be ErrorText for existing error-marker branch |
| `Location = {file: string, line: integer >=1, symbol: string}` | Existing AST result | Preserve current strings; target-path operations use posixpath, never resolve source references on host |
| `Slice = {source_read_ref: EventRef, start_line: integer >=1, end_line: integer}` | Validator after trace; inclusive, end >= start | Slice text is exact `splitlines(keepends=True)` range of stored text; adapter checks range and all path locations |

### Required events and fields

| Event | Payload (required unless O) | Producer / lifecycle | Existing data, TraceForge mapping, failure semantics |
|---|---|---|---|
| `run.started` | `task: {description: string}`, `target_directory: string`, `tool_capture_boundary: "compressor_observed"`, `models: array|null`; O `task_id: string`; models entries `{role:string, provider:string, model:string}` | CLI immediately after recorder reservation, before prerequisites; description is original plan, target is resolved CLI path; models null in first milestone | Original task maps to task.description; target namespaced; makes preflight failures visible; failure to create recorder emits stderr/nonzero with no alleged capture |
| `message` | Existing payload unchanged | Compressor as today | Raw evidence; map calls/results to normalized steps, seq plus call index for multi-call rows; not a dispatch event or proof of success |
| `compression` | `raw_result_ref: EventRef`, `state_index: integer >=0`, `finding: object` | Compressor immediately after deriving each output, before returning reducer update | Exact existing dictionary including counts/summaries; state_index is global append position of compressed dictionary; refs allow independent count/selection checks without reimplementing selection as an oracle |
| `validation.started` | `cycle: integer >=1` | Validator on entry, before summary loop | Distinguishes a zero-candidate cycle from a missing/aborted cycle; event seq is cycle_ref |
| `candidate` | `cycle_ref: EventRef`, `compression_ref: EventRef`, `summary_index: integer >=0`, `summary: string` | Validator for **every** top_findings entry before parsing | Candidate event seq is attempt identity; exact summary must equal referenced dictionary entry; malformed entries remain visible, excluded from legacy total_candidates |
| `source.read` | `candidate_ref: EventRef`, `arguments: {filepath:string,start_line:integer,end_line:integer}`, `status: "returned"|"error"`, `text: string|null`, `text_sha256: string|null`, `error: Error|null` | Validator wrapper around existing read, immediately on return/caught exception, before AST parsing | On return retain exact text/hash, including error-marker text; on thrown exception null text/hash and populated error. `returned` does not assert tool success or complete file; replaces sidecar read + source.py |
| `validation.decision` | `candidate_ref: EventRef`, `disposition: "verified"|"rejected"|"skipped"`, `reason: null|"malformed_summary"|"read_exception"|"read_error_marker"|"syntax_error"|"no_taint_trace"`, `source_read_ref: EventRef|null`, `finding: object|null`, `source_slice: Slice|null` | Validator immediately at existing branch outcome | Exact VerifiedFinding for verified, null reason; rejected finding null, reason required; skipped only malformed summary with null read/slice. Verified requires stored text and slice; syntax/no-trace rejection references read and full analyzed-input span when nonempty; empty source has null slice |
| `validation` | Existing four aggregate fields **unchanged**, plus `cycle_ref: EventRef` | Validator after decisions, as today | End-of-cycle marker; parsed candidates = verified + rejected; skipped excluded; compare arithmetic, never sum cycles as unique vulnerabilities |
| `run.finished` | `execution_status: "completed"|"failed"|"interrupted"`, `error: Error|null` | CLI on normal graph return or caught termination before summary publication | Observed execution end, not evidence publication success. Completed requires null error; failure/interruption requires error. No finding count implies outcome here |

A successful parse with no trace remains rejected. To distinguish syntax failure
from no trace, expose the existing parse branch through an internal diagnostic
helper while preserving `find_taint_trace` and `verify_finding_evidence` public
return contracts. Do not add a second sandbox read or change AST matching.
Read error markers retain their current semantics even if found in valid source;
record the branch, do not silently fix detection logic in this task.

Compression references live in recorder bookkeeping keyed by append position,
not extra fields in `AuditState` or compressed dictionaries. Validator enumerates
the same append-only state list. Candidate identity is per **attempt**, so repeated
cycles and duplicate summaries retain distinct evidence even when upstream finding
IDs repeat. If a production caller supplies prepopulated state without matching
compression records, capture is insufficient; do not manufacture raw provenance.

### Final summary (metadata extension)

Keep every current metadata field with its current meaning. Add the following
required fields in production mode; recorder publishes using a same-directory
temporary file and atomic replace **only after** the last ledger row is closed
and synchronized. No new success message until publication succeeds.

| Field/type | Producer/timing and example | Mapping / failure semantics |
|---|---|---|
| `contract_version: string` | Recorder; production version above | Select schema and prevent legacy fallback |
| `start_ref: EventRef`, `finish_ref: EventRef` | Recorder; first/last events | Start/end timestamps derive from references, no duplicated clocks |
| `execution_status: completed|failed|interrupted` | Copy run.finished | Must agree; a diagnostic summary may be committed for failure |
| `evidence_status: "complete"` | Recorder only when all required writes succeeded | Complete means captured observed scope, not all dispatched tools; no commit means incomplete |
| `ledger_sha256: string` | Recorder hashes exact final JSONL bytes | Commitment to all source/messages; mismatches invalidate summary; hashes are integrity checks, not authentication |
| `event_count: integer >=2` | Recorder final sequence | Requires contiguous seq, finish is last row, no trailing extra rows |
| `final_finding_refs: EventRef[]` | CLI/recorder maps final state's verified list to decision events | Preserve order/multiplicity, not unique upstream IDs; require exact object correspondence; do not treat decisions in an unreturned node as committed final state |
| `report_ref: null` | Recorder, first milestone | Explicitly unavailable; future non-null report requires contract extension and retained artifact |

For failed/interrupted runs, final_finding_refs reflect the last yielded state
only; decision events may contain further observations. They remain inspectable
but are not a completed audit result. Failure to reconcile final state references
prevents a complete summary. No new ratios/scores are emitted. Existing aggregate
metrics stay for compatibility; TraceForge recomputes/reconciles them where supported.

## 4. Event and payload examples

Illustrative payloads, not captures. Each occupies a row with the common envelope.
Symbols `H` and `L` below stand for actual 64-hex SHA-256 values in a real capture.
IDs/references show one call, one compression, one validation attempt.

```json
{"contract_version":"cipherloop-production-v1","run_id":"6bd23376-c947-45e4-a0f5-6d6a5660ec46","seq":1,"timestamp":1788955200.0,"step_type":"run.started","payload":{"task":{"description":"Find command injection"},"target_directory":"/example/target","tool_capture_boundary":"compressor_observed","models":null}}
```

Subsequent `step_type` / `payload` examples (envelope omitted):

```json
[
  {"seq":2,"step_type":"message","payload":{"type":"AIMessage","role":"assistant","content":"","tool_calls":[{"id":"call-1","name":"run_semgrep","args":{"target_path":"app.py"}}]}},
  {"seq":3,"step_type":"message","payload":{"type":"ToolMessage","role":"tool","content":"{\"results\":[]}","tool_name":"run_semgrep","tool_call_id":"call-1"}},
  {"seq":4,"step_type":"compression","payload":{"raw_result_ref":3,"state_index":0,"finding":{"tool":"run_semgrep","total_findings":0,"critical_findings_count":0,"top_findings":[],"summary_note":"","raw_char_count":14,"compressed_char_count":114}}},
  {"seq":5,"step_type":"validation.started","payload":{"cycle":1}},
  {"seq":6,"step_type":"validation","payload":{"cycle_ref":5,"total_candidates":0,"verified_count":0,"rejected_count":0,"candidate_to_verified_ratio":null}},
  {"seq":7,"step_type":"run.finished","payload":{"execution_status":"completed","error":null}}
]
```

For a different compression record containing `[ERROR] app.py:3 - Command injection`,
a validation cycle instead includes these payloads. The slice references the full
analyzed text, making an independent line/path check possible without the target.

```json
[
  {"seq":6,"step_type":"candidate","payload":{"cycle_ref":5,"compression_ref":4,"summary_index":0,"summary":"[ERROR] app.py:3 - Command injection"}},
  {"seq":7,"step_type":"source.read","payload":{"candidate_ref":6,"arguments":{"filepath":"app.py","start_line":1,"end_line":1000000},"status":"returned","text":"import os\nx = input()\nos.system(x)\n","text_sha256":"H","error":null}},
  {"seq":8,"step_type":"validation.decision","payload":{"candidate_ref":6,"disposition":"verified","reason":null,"source_read_ref":7,"finding":{"id":"VULN-app.py-3","vulnerability_class":"Command injection","severity":"MEDIUM","source":{"file":"app.py","line":2,"symbol":"input"},"sink":{"file":"app.py","line":3,"symbol":"os.system"},"taint_path":["app.py:2:input","app.py:2:x","app.py:3:os.system"],"evidence_snippet":"AST-verified taint path: app.py:2:input -> app.py:2:x -> app.py:3:os.system","confidence":0.9,"status":"VERIFIED"},"source_slice":{"source_read_ref":7,"start_line":2,"end_line":3}}}
]
```

Rejected/no-trace decision: same references, `disposition:"rejected"`,
`reason:"no_taint_trace"`, `finding:null`, and source_slice spanning the nonempty
analyzed input. Malformed summary: `disposition:"skipped"`,
`reason:"malformed_summary"`, null source_read_ref/finding/source_slice.
Read exception example:

```json
{"candidate_ref":6,"arguments":{"filepath":"app.py","start_line":1,"end_line":1000000},"status":"error","text":null,"text_sha256":null,"error":{"stage":"validation_read","type":"RuntimeError","message":"read failed"}}
```

Its decision is rejected/read_exception with a reference to this read event and
null finding/slice. End-of-run failure example:

```json
{"execution_status":"failed","error":{"stage":"graph_execution","type":"RuntimeError","message":"model request failed"}}
```

Summary extension for the zero-candidate example (existing metadata keys omitted):

```json
{"contract_version":"cipherloop-production-v1","start_ref":1,"finish_ref":7,"execution_status":"completed","evidence_status":"complete","ledger_sha256":"L","event_count":7,"final_finding_refs":[],"report_ref":null}
```

## 5. Lifecycle and failure semantics

1. Reserve new identity/ledger and append run.started before preflight. Wrap
   prerequisites, graph import/build and streaming. Preserve exits/exceptions;
   capture diagnostics without turning failures into ordinary returns. Known
   stages: `preflight`, `sandbox_setup`, `graph_build`, `graph_execution`,
   `validation_read`, `finalization`. Do not infer planner/tool origin from prose.
2. Append events synchronously at the indicated boundaries. Completed individual
   writes survive ordinary exceptions; process-kill/power-loss may leave a prefix.
   Use one writer per run. Preserve raw state and current reducer behavior.
3. On normal stream exhaustion append completed run.finished. On caught exception
   append failed; on KeyboardInterrupt/cancellation append interrupted, best effort,
   then preserve the original propagation/exit semantics. SIGKILL and unhandled
   termination cannot emit reliable end events. V1 does not promise signal recovery.
4. Finalize both ordinary and caught-failure paths from the last available state.
   Publish summary last. A finish event alone proves only an observed end, not a
   complete evidence bundle. A summary committing a failed run is valid evidence
   of failure, never success. Protect original exceptions from finalizer exceptions.
5. If append, serialization, synchronization, hashing or atomic summary publication
   fails, propagate/report a capture error, emit no completion claim, and do not
   publish a valid complete summary. If possible append failed diagnostics before
   committing a failed execution; after a torn append, stop writing that ledger.
   No attempt to repair, truncate, or reuse the run. Existing recorder already
   propagates I/O errors; new terminal handling must not silently swallow them.
6. Reader accepts only newline-terminated, parseable contiguous rows. A torn final
   row may be excluded from **diagnostic prefix viewing** with an explicit truncated
   flag, never from successful ingestion. Malformation in the middle is corruption.
   Missing summary = incomplete/possibly still running, termination cause unknown;
   do not label it interrupted without observation or use a timeout as proof.
7. Atomic replacement prevents partially published JSON, not all power-loss cases.
   Synchronize ledger before summary, synchronize summary temp before replacement,
   and directory after publication where supported. Any missing/damaged artifact
   on re-read is insufficient evidence regardless of prior runtime output.

| Scenario | Execution observation | Evaluation eligibility |
|---|---|---|
| Normal run with source-backed findings | completed + committed, reconciled summary | Eligible for evidence checks; upstream VERIFIED is not a TraceForge verdict |
| Normal run, no retained candidates or no verified decisions | completed + summary, completed validation cycle(s) | Completed negative observation; not proof target is safe or task met |
| Validator rejection | Per-attempt reason; run can still complete | Rejection is an ordinary result, not run failure; read/syntax failures cannot be interpreted as safe negatives |
| Tool result containing error text | Raw result retained if compressor reached; validator read markers recorded explicitly | No general tool-success inference; structured dispatch status deferred |
| Tool or planner/model exception reaches CLI | failed/graph_execution unless origin known | Failure diagnostics; may lack call/result from failed node |
| Handled interruption | interrupted + best-effort summary | Never successful empty audit |
| Exception before recorder creation / storage unavailable | stderr/nonzero; no bundle possible | No evidence available, not a zero-finding result |
| Crash after run.finished but before summary | Finish observed, commit absent | Incomplete evidence even if finish says completed |
| Finalization error or partially written data | No valid commitment | Operational evidence error; no normalized success |

## 6. TraceForge mapping and evaluation boundary

The inspected `adapters/cipherloop.py` is a strict **two-case capture adapter**.
`_load_case` requires parent index with exactly toy/safe; fixture source and canonical
hashes; capture.json with `synthetic_scanner:true`; fixed unavailable list;
exact call arguments/ID; three rows/two steps; exact compression and metadata;
read, slice and shearing records. `match_messages` rejects unknown events, messages
after validation, missing pairs, and multiple validation cycles. Production v1
cannot be passed through this loader unchanged.

Add a separate `adapters/cipherloop_production.py` entry point, taking the run
ledger/metadata paths, never importing CipherLoop. It must consume a copied bundle
with no original target, fixture manifest, index.json, capture.json or source.py.
Contract version selects this path explicitly; legacy baseline selection stays
explicit too. No weakening of baseline provenance or oracle checks.

| Evidence layer | Production data | Proposed TraceForge representation |
|---|---|---|
| Raw observations | message contents/calls/results, original task, source.read text/error, compressed dictionaries, exact upstream findings | Retained evidence references; normalized tool_call/tool_result steps and namespaced `cipherloop_evidence` |
| Normalized metadata | Run identity/version, UTC recording timestamps, references, lifecycle, null provenance | trajectory_id/task.description; namespaced lifecycle and models only when observed |
| Derived checks/metrics | Call-result reconciliation, source hash/slice/line checks, per-cycle arithmetic, observed tool-call count | TraceForge-owned diagnostics; preserve exact upstream counts and confidence alongside recomputation; no token/cost/recovery/safety substitutions |
| Final observed outcome | Execution status, final_finding_refs, report_ref null | Namespaced execution outcome; no synthesized report or task-success verdict |

Validate paired tool IDs/names by references across the observed rows, allowing
result order variation and multiple calls/cycles. Sequence is evidence order, not
proof of causal dispatch ordering. Index calls within a multi-call row. Refuse
ambiguous duplicate IDs rather than silently deduplicating; on partial runs retain
unmatched observations as diagnostics. Repeated finding IDs across attempts are
legal; repeat final-state entries remain repeated references. An otherwise finished
run with inconsistent references is insufficient for production normalization.

The current normalized schema requires `outcome.success: boolean`. Production
completion is **not** task success: the baseline's true value depends on its fixture
oracle, which production lacks. First milestone returns a separate versioned
production-ingestion document with task, observed steps, namespaced evidence,
execution status, integrity diagnostics and **no outcome.success**. It is not claimed
to conform to `trajectory.schema.json`. Evidence can be evaluated for integrity,
source backing and arithmetic offline; detection accuracy/task success remains
unavailable. A later explicit normalized-schema migration can represent unknown
success or an external oracle can supply a verdict. Do not change that schema or
stuff `false`/`true` into success merely to satisfy it in this milestone.

## 7. Compatibility and migration

* Existing raw messages, metadata keys/counts, and aggregate validation meaning
  remain valid. Existing source-less ledgers remain insufficient for independent
  source verification; do not retrospectively fill evidence from a changed target.
* JSONL is structurally extensible, but **not backward-compatible with this strict
  adapter** when new events appear. Explicit production mode plus a separate
  consumer avoids pretending otherwise. Do not change legacy recorder defaults.
* A version is required in each production event and summary. No version means
  legacy, not an implicit v1. Missing summary on a versioned ledger is partial v1.
  Mixed/unknown versions are errors. Do not route rejected v1 through legacy code.
* Freeze the two-case synthetic baseline, source snapshots, original reference,
  canonical hashes and oracle semantics. Its documentation says captures pin this
  exact CipherLoop SHA; updating CipherLoop will not satisfy that harness's pin.
  Use its preserved clean pinned checkout for baseline reproduction later; do not
  repin or regenerate goldens as part of production integration. Legacy recorder
  tests plus frozen adapter fixtures provide compatibility checks offline.
* Add new production tests/fixtures, not edits to old evidence. Existing recorder,
  validator and compressor behavior assertions should continue passing. Preserve
  public validator helper returns and exact finding/compression dictionaries.
* Full UUID CLI IDs are an intentional evidence identity change. Callers parsing
  eight-character filenames need migration; old artifacts remain readable.
* Snapshot text may include secrets and increases trace size. Store locally with
  the existing trusted evidence owner; no cloud upload is introduced. Redacting
  analyzed text would invalidate source verification and needs a separate policy.

## 8. Exact likely implementation files

Required source changes for the bounded milestone:

| File | Responsibility |
|---|---|
| `src/cipherloop/core/trajectory.py` | Explicit production mode; envelope/sequence and reference bookkeeping; fresh-run reservation; retained source events; commit hash and atomic summary; keep legacy mode unchanged |
| `src/cipherloop/main.py` | Full run identity/start before preflight; production mode; outer lifecycle handling; capture failure reporting and last-state finalization, preserving graph and exit behavior |
| `src/cipherloop/executor/compressor.py` | Record exact compression dictionary and raw-result reference at existing observation boundary; no change to selection, counts or RemoveMessage return |
| `src/cipherloop/executor/validator.py` | Cycle/candidate/read/decision events; expose existing rejection branches internally; retain analyzed source and slice references; preserve public return types and finding decisions |
| `../TraceForge/src/traceforge/adapters/cipherloop_production.py` (new) | Strict production-v1 ingestion and evidence diagnostics; no fixture or CipherLoop imports; separate result from legacy normalized schema |

Required focused test files:

* `tests/test_trajectory.py`: legacy output and production append/commit failures.
* `tests/test_compressor.py`: exact data/ref capture without reducer changes.
* `tests/test_validator.py`: source-backed decisions, rejection/skip branches, repeats.
* `tests/test_production_evidence.py` (new): fake CLI graph/preflight lifecycle and
  offline end-to-end producer bundle generation.
* `../TraceForge/tests/test_cipherloop_production.py` (new): standalone copied-bundle
  ingestion and malformed/version/lifecycle cases. Fixtures can be inline or temp
  files; no new committed capture corpus is necessary for this milestone.

No required changes to `core/state.py`, the old TraceForge adapter, normalized
schema, planner, graph, scanner or filesystem tools. The contract can initially be
validated in the new adapter; a standalone
`../TraceForge/schemas/cipherloop-production-v1.schema.json` is optional follow-up
if publishing a machine-readable schema is needed. Provenance/dispatch hooks and
normalized-outcome schema migration are explicitly separate future tasks, not
implied additions to this diff. No additional services or architecture refactors.

## 9. Minimal verification plan for implementation

These are planned checks, not tests executed during reconnaissance.

### Unit tests (offline)

* Recorder: legacy serialization/metrics unchanged; strict v1 fields, contiguous
  sequence, exclusive run identity, same-run references, atomic complete/failure
  summary and exact ledger hash. Inject append/serialize/fsync/rename failure,
  including failure during handling another exception; never mask original error
  or leave a valid success commitment. Test torn tail and stale-summary mismatch.
* Compressor: recorder captures exact dictionary before state return; raw-result
  reference and append index match; no added state fields or raw-source messages;
  existing top-five ordering, generic truncation and RemoveMessage behavior stay.
* Validator: mock read_file, run real AST logic on vulnerable/safe source; assert
  exact existing findings unchanged, matching source/sink/slice/hash; source text
  remains available after mocked target removal/change. Cover malformed summary,
  read exception, both error markers, syntax error, no trace, empty text, repeated
  cycles and duplicate upstream finding IDs. Existing counts exclude skipped entries.
* Consumer: version/mixed version/duplicate key/NaN/reference/hash failures;
  multi-call result ordering; multi-cycle decisions; malformed slices; missing
  source and unverifiable VERIFIED claim cannot pass evidence checks. Confidence
  remains upstream 0.9, not calibrated. No fabricated metrics or success field.

### Integration tests (offline first milestone)

* Stub prerequisite/sandbox functions and graph construction; fake async graph
  invokes real compressor/validator/recorder with mocked source reads. Exercise CLI
  start/end/finalization, retaining real reducers where needed to check final refs.
* Produce (a) verified finding, (b) zero candidates, (c) rejected safe candidate;
  assert completed execution distinct from evidence judgement and unknown task
  success. Read failure is not a safe rejection verdict.
* Inject preflight exit, graph-build failure, graph-stream exception after an
  emitted snapshot, KeyboardInterrupt/cancellation, and finalization failure.
  Also truncate a copied ledger to model uncatchable termination. Every incomplete
  path must differ from completed zero findings; no undocumented shutdown guarantee.
* Copy only ledger + metadata to a fresh temp directory; ingest with new TraceForge
  adapter without synthetic sidecar/index/manifest/source.py or target access.
  Reconcile selected candidates, final references, source slices and legacy counts.
* Run focused existing CipherLoop tests and existing TraceForge adapter fixture
  tests in already available offline environments. Preserve historical references;
  do not run the pinned generator against a modified source checkout or claim the
  two-case baseline was reproduced without its pinned environment/source.

### Docker/models

None required for milestone acceptance. A later separately authorized live audit
can confirm actual graph message/cycle ordering and source-read representation.
It must use the network-isolated sandbox and appropriate POSIX target paths.
No scanner-quality, model-quality, latency or cost claims follow from offline tests.

## 10. Open questions and risks

* Actual planner/graph dispatch ordering and error attribution were out of scope.
  Production v1 intentionally observes compressor messages; a model/tool failure
  before that point lacks dispatch evidence. Do not advertise a full execution trace.
* Source-read return formatting/decoding and truncation need a future targeted check
  before calling snapshots physical-file copies. V1 hashes exact analyzed text and
  labels it accordingly; no host-target reads may be added to fill the gap.
* AST heuristics are conservative intra-procedural implementation behavior, not
  general proof of exploitability. Persist upstream VERIFIED but distinguish it
  from independent source-backing checks and external vulnerability adjudication.
* No independent production task oracle exists in inspected evidence. Deciding
  normalized unknown-success semantics is a separate TraceForge schema decision.
* Full source snapshots can be large/sensitive; future retention/export policy must
  preserve evidence or explicitly make affected evaluations unavailable.
* Event recording can fail between a decision and state reduction; final reference
  reconciliation must use the actual last yielded state, not every observed decision.
* Existing message IDs can be absent or duplicated; v1 should diagnose insufficient
  correlation instead of inventing successful calls. Resume/concurrent writers are
  not supported. Wall-clock adjustments prohibit inferring precise durations.
* Checksums detect inconsistent bytes, not a producer rewriting all evidence.
  No signing/remote attestation system is proposed.

## 11. Recommended first implementation milestone and acceptance

One bounded session: add **production-v1 capture at the four existing CipherLoop
boundaries plus one standalone TraceForge ingestion function**, with the focused
offline tests above. Preserve legacy recorder mode and baseline artifacts. Do not
add full dispatch tracing, provenance discovery, reports, metric expansion, signal
recovery, a CLI evaluation command, or normalized-schema migration.

Acceptance: production-mode CLI wiring under mocked runtime emits a self-contained
ledger and committed summary; the new consumer reads them after the target is gone;
source-backed verified, safe/no-candidate, rejected and incomplete runs remain
separate; every required reference/count/hash is checked; failures cannot publish
normal success; existing finding/reducer/legacy artifacts remain compatible; the
consumer requires no synthetic sidecar and reports no unsupported task verdict.
A live run remains a separate smoke test, not an excuse to expand this milestone.

## Reconnaissance checks

Read-only checks established branch/HEAD and initial clean status. Source and focused
tests were inspected, not executed. The only file created is this document. Final
checks use `git diff --check --no-index /dev/null docs/production-evidence-capture-plan.md`
so the untracked document is actually checked, plus `git diff --check` and
`git status --short`. No implementation, commits, network operations, dependencies,
Docker, scanners or models were changed/run.
