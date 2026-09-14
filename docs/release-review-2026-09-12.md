# CipherLoop → TraceForge adversarial release review

The requested committed heads are **NOT READY as-is** because of the reproduced
defects below. With this review's local fixes, **CipherLoop: READY WITH CAVEATS**
and **TraceForge: READY WITH CAVEATS** as the offline foundation for the first live
run. The fixes must accompany the branches before those verdicts apply to a PR.
No successful Docker/Ollama/model audit or hosted CI pass is claimed.

## Repository truth and scope

| Repository | Branch / HEAD | Intended base | Ahead / behind base |
| --- | --- | --- | --- |
| CipherLoop | `feat/production-evidence-capture` / `a5a8bf7bea443b6a35f3af101c4d4b4cbf92f911` | `main`, `f03a1e186e491cf24aa0f0e0671cac766c1fa8ab` | 6 / 0 |
| TraceForge | `feat/cipherloop-production-ingestion` / `d14f7ce3c7fed7929de26e5068a740a597edc82a` | `main`, `25668c4db622a322b87271825ce68fd37390f3ec` | 1 / 0 |

Both track the same-named `origin/feat/...` branch and remain 0 ahead / 0 behind
those locally recorded upstream refs. No fetch was performed. CipherLoop started
clean. TraceForge started with the deleted tracked file `tatus --short --branch`
and untracked file `t CipherLoop production evidence"`; both were preserved.
There are no staged changes, new commits, pushes, merges, or PR operations.

The review covered the complete feature deltas (14 CipherLoop files; three
TraceForge files), current producer/consumer implementation and focused tests,
current contract, relevant roadmap and capture plan, dependencies, and workflows.
The applicable instructions were CipherLoop's AGENTS.md; no additional ancestor,
nested, or TraceForge AGENTS.md was found. Historical v1 proposals were not treated
as current acceptance criteria. No delegated agents were used.

## Reproduced defects and smallest fixes

| Priority | Defect before fix | Change and regression evidence |
| --- | --- | --- |
| P1 | A matching target mount authorized reuse of a networked, writable, or differently named sandbox. This was inherited behavior, not introduced by evidence capture. | Require the exact container name, `HostConfig.NetworkMode == "none"`, and `RW is False` as well as the target identity. Four mocked inspection cases failed before the fix. |
| P1 | Failed-run metadata could retain a verified decision while discarding its compression and reporting zero retained tool-output counts. Both implementations accepted the impossible state. | Producer and independent reader require final state to include the state already witnessed by validation starts. One regression in each repository. |
| P1 | Producer finalization ignored a later validator's stale input count; identical repeated findings could hide a lost reducer update and still publish completed metadata. | Reconcile each validation start against preceding compression occurrences and completed validation output. A two-cycle regression failed before the fix. |
| P1 | `run.started` followed directly by completed `run.finished` could become a committed, evaluator-PASS empty run without any validation. | Both implementations require a finished validation cycle even with no tool observations. One regression in each repository; valid empty-cycle captures remain supported. |
| P2 | Replacing the reserved ledger with a same-byte file or symlink passed digest checks and could be committed. | Check the reserved filesystem identity on append and final read. Four replacement/append/finalization cases failed before the fix. Trusted-directory and filesystem-identity assumptions remain explicit. |
| P1 | Structured failure of both scanners, and generic tool error markers, could ingest as PASS with zero candidates. | TraceForge independently reports `tool_output_unavailable` ERROR diagnostics. Producer observations and scanner selection remain unchanged. Two regressions failed before the fix. |
| P2 | The producer's permissive parsing of embedded scanner JSON disagreed with the reader's strict parsing. Recorded duplicate-key/NaN/overflow observations were rejected as corrupt artifacts. | Recompute the actual compression semantics independently while reporting ambiguous embedded JSON as ERROR. Artifact objects still reject duplicate keys and nonfinite numbers. Three regressions failed before the fix. |
| P2 | The reader accepted ten CR-separated events as JSONL despite only one LF delimiter, a stream the producer would refuse to finalize. | Split artifact rows on LF. The CR-only regression failed before the fix; the CRLF compatibility control passes. |

Added **20 regression/control cases**: 11 in CipherLoop and nine in TraceForge.
Nineteen exposed failures before implementation; the additional CRLF case is a
positive compatibility control. Existing finalization-fault tests now include a
valid empty validation cycle so they still reach the intended storage fault.

The smoke generator adds scanner failure, ambiguous scanner JSON, and no-tool
execution to its six existing scenarios. All use scripted observations and real
CLI lifecycle, LangGraph reducers, compression, validation, and recording.

## Assumptions challenged

- Counts and equality of finding dictionaries do not establish occurrence identity
  or a possible reducer history. References must preserve multiplicity, batch
  boundaries, and prerequisite state. Duplicate finding IDs remain legal.
- Forward/dangling/wrong-kind references, duplicate calls/results/reads/decisions,
  orphan candidates, skipped or unfinished cycles, missing source, altered slices,
  and stale final references must fail closed. Existing adversarial tests exercise
  these; the new tests address gaps rather than duplicating that coverage.
- Hash consistency is not producer authenticity. A producer rewriting all evidence
  can recompute hashes. No signing, attestation, or hostile concurrent-writer claim
  is introduced. Quiescent copied artifacts and a trusted output directory remain
  required; filesystem identity checks assume meaningful stable file identifiers.
  Python documents platform-dependent identifiers in its
  [filesystem API](https://docs.python.org/3.11/library/os.html#os.stat_result).
- A returned source string is the analyzed input, not an original-byte file copy.
  Existing decoding/replacement/stripping can affect physical-file line fidelity.
- Result observation order is not dispatch provenance. Reordered results can be
  valid; missing/duplicate correlation remains insufficient. No full call trace,
  measured model provenance, or captured synthesizer report is invented.
- PASS means the stated capture-integrity/source-location checks passed. It does
  not establish target safety, dataflow truth, exploitability, scanner accuracy,
  task success, agent reliability, or target coverage. AST symbol-location checks
  deliberately do not reproduce CipherLoop's taint evaluator. ERROR includes known
  execution/tool/validation unavailability; malformed, unsupported, incomplete,
  and inconsistent input remains an explicit categorized exception.

Additional byte-level probes accepted UTF-8 text containing accents, emoji, and
U+2028, and rejected BOM-prefixed UTF-8, invalid UTF-8, and UTF-16 ledgers even with
recomputed hashes. Decreasing timestamps remained valid: sequence numbers order
observations; timestamps are not claimed monotonic clocks or durations.

## CI and documentation

CipherLoop previously had no repository workflow. The new
`.github/workflows/production-evidence.yml` installs declared dependencies, runs
the full offline suite, scoped lint, and the scripted smoke. TraceForge's existing
workflow now includes production tests and their lint scope. Its baseline source
pin, dependency constraints, fixtures, schema, oracle, and generation gates are
unchanged. Both workflows use pinned action revisions and read-only permissions.
Their YAML structure and embedded Bash syntax were checked locally.

Setup may fetch dependencies; the contract gates do not require Docker, Ollama,
cloud credentials, GPU, or network model access. Hosted execution is unverified.
CipherLoop's dependency ranges remain unpinned; this review used the existing
declared-dependency environment, not a new package-index resolution. Cross-repo
feature compatibility CI still needs published immutable revisions of these fixes.

README/roadmap corrections distinguish offline P0.1/P0.2 closure, observed real
preflight failure, and unverified live success. CipherLoop's former AST→Semgrep
fallback story and full-DAG/every-run-publication claims were corrected. Its CLI
example now matches the inspected single-command Typer interface. Earlier closure
logs are explicitly historical rather than descriptions of current Git state.

## Exact verification

From CipherLoop, using its existing Python 3.12 venv and dependency overlay:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=venv/lib/python3.12/site-packages:/tmp/cipherloop-closure-deps:src timeout 60s venv/bin/python -m pytest -q tests/test_trajectory.py tests/test_compressor.py tests/test_validator.py tests/test_production_contract.py tests/test_production_evidence.py tests/test_sandbox_identity.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=venv/lib/python3.12/site-packages:/tmp/cipherloop-closure-deps:src timeout 60s venv/bin/python -m pytest -q
venv/bin/ruff check --no-cache src/cipherloop/core/trajectory.py src/cipherloop/main.py src/cipherloop/executor/compressor.py src/cipherloop/executor/validator.py tests/test_trajectory.py tests/test_compressor.py tests/test_validator.py tests/test_production_contract.py tests/test_production_evidence.py tests/test_sandbox_identity.py scripts/capture_production_smoke.py
PYTHONPATH=venv/lib/python3.12/site-packages:/tmp/cipherloop-closure-deps venv/bin/python -m pip check
```

Results: **73 focused passed; 84 full-suite passed; scoped lint passed; no broken
requirements**. The focused graph run first timed out (exit 124) in the command
sandbox, then passed outside that restriction with runtime services still mocked.

From the actual TraceForge worktree:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=src:/home/abundance333/Desktop/Projects/CipherLoop/venv/lib/python3.12/site-packages:/tmp/cipherloop-closure-deps /home/abundance333/Desktop/Projects/CipherLoop/venv/bin/python -m pytest -q -p no:cacheprovider tests/test_cipherloop_production.py
/home/abundance333/Desktop/Projects/CipherLoop/venv/bin/ruff check --no-cache scripts/generate_cipherloop_baseline.py src/traceforge tests/conftest.py tests/test_cipherloop_adapter.py tests/test_cipherloop_baseline.py tests/test_baseline_operations.py tests/test_cipherloop_production.py
```

Results: **66 production tests passed; authoritative scoped lint passed**.
For baseline regression, local `--no-hardlinks` clones were created under
`/tmp/cipherloop-release-review.nSJ2Rf`. The sibling CipherLoop clone is clean at
the frozen required `f03a1e1`; only current production adapter/tests were copied
into the isolated TraceForge checkout and byte-compared. From that TraceForge:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 LANGSMITH_TRACING=false PYTHONPATH=src:/home/abundance333/Desktop/Projects/CipherLoop/venv/lib/python3.12/site-packages:/tmp/cipherloop-closure-deps /home/abundance333/Desktop/Projects/CipherLoop/venv/bin/python -m pytest -q -p no:cacheprovider
```

Final result: **128 passed (66 production + all 62 frozen-baseline regressions)**.
The combined suite was repeated after the final framing defect was discovered;
the unchanged CipherLoop suite was not repeated. No baseline source was repinned.

The cross-repository smoke used:

```sh
# CipherLoop root
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=venv/lib/python3.12/site-packages:/tmp/cipherloop-closure-deps:src timeout 60s venv/bin/python scripts/capture_production_smoke.py --output /tmp/cipherloop-release-review.nSJ2Rf/producer-bundles
cp -R /tmp/cipherloop-release-review.nSJ2Rf/producer-bundles /tmp/cipherloop-release-review.nSJ2Rf/copied-bundles
# TraceForge root; only its source path, with site packages disabled
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -S /tmp/cipherloop-release-review.nSJ2Rf/verify_handoff.py > /tmp/cipherloop-release-review.nSJ2Rf/handoff-results.json
```

All nine scenarios matched expected status/finding counts. Repeated ingestion was
deterministic, both input files stayed byte-identical, and no CipherLoop/LangChain
module was imported. The verifier also reingested the retained real preflight
failure, run `8b1c3f56-dfca-4ac8-9bf7-1d03a9459235`, as ERROR/failed with zero final
findings and `preflight/FileNotFoundError` for missing Docker. Artifact hashes:

- Ledger: `97baff0db3dcb2a05bde469ee6441f50abb2352bff7ae6da1d7a399be0014f6b`
- Metadata: `ffc1c1a21986ced604a23326aca7f4f626a7a9562e36369954a3afeb10ef9821`

The `/tmp` verifier/results are session artifacts. The retained smoke generator
and TraceForge production documentation provide the durable reproduction path.
Both repositories' `git diff --check` passed. Frozen TraceForge code, fixtures,
schema, rubric, constraints, and declarations have no diff from HEAD.

Repository-wide CipherLoop Ruff remains **failing with 28 inherited diagnostics**,
down from 31 because the touched sandbox subprocess calls now explicitly state
`check=False`. Comparing file/rule/message against the prior diagnostic snapshot
found no new diagnostics. Unrelated lint cleanup was not performed. No relevant
offline test was left skipped; live runtime, Windows filesystem behavior, hosted
CI, clean dependency resolution, power-loss recovery, and storage-denied cleanup
were not demonstrated.

## Final changed-file inventory

CipherLoop (all unstaged; two new files):

```text
M README.md
M docs/PROJECT_STRATEGY_AND_ENGINEERING_ROADMAP.md
M docs/production-evidence-capture-plan.md
M docs/production-evidence-contract.md
M scripts/capture_production_smoke.py
M src/cipherloop/core/trajectory.py
M src/cipherloop/main.py
M tests/test_production_contract.py
M tests/test_production_evidence.py
M tests/test_sandbox_identity.py
M tests/test_trajectory.py
? .github/workflows/production-evidence.yml
? docs/release-review-2026-09-12.md
```

TraceForge review changes (all unstaged):

```text
M .github/workflows/cipherloop-baseline.yml
M README.md
M docs/ROADMAP.md
M docs/cipherloop-production.md
M src/traceforge/adapters/cipherloop_production.py
M tests/test_cipherloop_production.py
```

The pre-existing deletion/untracked file listed above remain alongside these six
changes. No scanner, taint algorithm, graph architecture, evaluator oracle, API,
UI, dependency declaration, or frozen baseline artifact was changed.

## Next bounded step and caveats

Yes: carry these fixes to the Windows machine, run the offline gates there, then
capture one bounded successful sandbox/model execution and ingest its unchanged
two-file bundle independently. Preserve `network_mode: none` and a read-only target.
File identity and metadata durability still need Windows validation; offline Linux
fault injection is not a Windows or power-loss test.

Existing scanner limitations matter when interpreting that run: Semgrep is invoked
with registry configurations `p/secrets` and `p/rce`, while the Dockerfile does not
bundle those rules. Rule availability inside the isolated sandbox remains a live
verification issue. The existing fallback omits severity, so its nonempty results
can yield zero selected validation candidates. Changing that selection would alter
scanner capability and was explicitly out of scope. A completed live handoff must
therefore be distinguished from successful primary scanning or a verified positive
finding. These limitations do not block validating the evidence pipeline itself.
