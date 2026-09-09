# CipherLoop Operating Protocol

CipherLoop is an evidence-producing security agent and systems-engineering flagship project.

Source code and tests are authoritative for current behavior.

For product strategy, evidence principles, project boundaries, and roadmap, read:

- `docs/PROJECT_STRATEGY_AND_ENGINEERING_ROADMAP.md`

For the current production evidence milestone, read:

- `docs/production-evidence-capture-plan.md`

Do not treat README prose, old specs, or planning documents as stronger evidence than current implementation and tests.

## Core Invariants

### Sandbox boundary

- All tactical tool execution MUST occur inside the `cipherloop-sandbox` Docker container.
- Tactical execution must preserve `network_mode: none`.
- Never expose audited target files directly to the cloud orchestrator.
- Do not introduce host-filesystem shortcuts that bypass the sandbox abstraction.

### Path discipline

- Paths sent to sandbox execution MUST use POSIX semantics.
- Use `posixpath` for container workloads.
- Do not introduce `os.path` behavior for paths interpreted inside the Linux sandbox.

### Deterministic memory

- Never append raw tool stdout directly to `AuditState.messages`.
- Raw tool results must pass through the existing compression boundary.
- Preserve LangGraph message shearing with `RemoveMessage`.
- Do not weaken bounded active-context behavior without an explicit, tested design change.

### Evidence threshold

- A vulnerability MUST NOT be labeled `VERIFIED` without reproducible source, sink, and evidence sufficient to reconstruct the accepted path.
- Failed, interrupted, incomplete, or partially finalized runs MUST NOT be represented as successful zero-finding runs.
- Do not fabricate missing evidence, metrics, provenance, or success states.

### Producer / evaluator separation

- CipherLoop produces execution evidence.
- TrajectoryLab / upstream `jayjz/TraceForge` independently evaluates evidence.
- Do not move evaluator verdicts into CipherLoop merely for convenience.
- Preserve the frozen synthetic TrajectoryLab baseline unless a task explicitly targets it.

## Engineering Behavior

### Think before editing

Before changing code:

1. inspect the current branch and working tree,
2. read the relevant source and focused tests,
3. identify material assumptions,
4. verify behavior from implementation instead of guessing from docs.

If a consequential ambiguity cannot be resolved from repository evidence, surface it before making a risky change.

### Prefer the smallest correct solution

- Solve the requested outcome, not adjacent hypothetical problems.
- Avoid speculative abstractions, new services, queues, databases, frameworks, or dependencies unless the task requires them.
- Prefer extending existing boundaries over introducing parallel architecture.
- Keep interfaces narrow and versioned where they become durable contracts.

### Make surgical changes

- Modify only files necessary for the current milestone.
- Preserve user-owned and unrelated working-tree changes.
- Do not stash, reset, clean, reformat, rename, or rewrite unrelated work.
- Do not broaden a bounded task into architecture cleanup.

### Goal-driven execution

For implementation tasks, continue through:

`inspect -> implement -> focused verification -> diff review -> final report`

Do not stop after producing a plan unless the task explicitly requests planning only or a material blocker requires user input.

## Development Workflow

### Source hierarchy

Use this precedence when sources disagree:

1. explicit current user instruction,
2. current implementation and tests,
3. `AGENTS.md` invariants,
4. current milestone/design document,
5. strategy roadmap,
6. README and older specs.

Call out contradictions instead of silently choosing whichever source is convenient.

### Specs and plans

- Read only the specs relevant to the active task.
- Do not assume everything under `.codex/specs/` is current.
- Historical specs may describe superseded architecture.
- Reconcile any plan against source before implementation.

### Verification

Choose verification proportional to the change.

Use:

1. focused tests for changed behavior,
2. relevant static checks,
3. broader regression tests when justified by the risk or requested acceptance criteria.

Do not repeatedly run the full suite after every tiny edit.

If a test cannot run because of an environmental limitation, report that limitation precisely and distinguish it from a product failure.

### Failure handling

Treat failure paths as first-class behavior.

When relevant, test:

- tool/scanner failure,
- fallback failure,
- malformed results,
- source-read failure,
- validator rejection,
- graph exception,
- interruption,
- finalization failure,
- incompatible evidence versions.

### Completion standard

Before claiming completion:

- inspect `git diff`,
- run the required checks,
- confirm no unrelated files changed,
- report exact verification results,
- identify remaining assumptions or risks.

Do not claim success for behavior that was not directly verified.

## Scope Control

Unless explicitly requested, do NOT add:

- dashboards,
- authentication systems,
- databases,
- distributed queues,
- Kubernetes,
- billing,
- multi-agent hierarchies,
- LLM judges,
- new scanners,
- autonomous remediation,
- unrelated refactors.

The current flagship sequence is:

1. production evidence capture,
2. TrajectoryLab production ingestion,
3. REST API,
4. minimal operator UI,
5. benchmark and provider comparison.

Do not skip ahead without an explicit task.

## Repository Notes

- Local sibling evaluator path on the current Windows setup: `../TrajectoryLab`
- Upstream evaluator repository: `jayjz/TraceForge`
- Local folder names are not authoritative repository identities.

## Final Response Format

For implementation tasks, report:

- what changed,
- why it changed,
- files changed,
- exact tests/checks run,
- pass/fail results,
- skipped checks and why,
- remaining risks/assumptions,
- next bounded milestone.

Keep the final report concise and evidence-based.