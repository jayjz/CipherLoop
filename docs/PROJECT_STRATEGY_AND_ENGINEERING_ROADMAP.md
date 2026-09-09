# CipherLoop / TrajectoryLab Strategy & Engineering Roadmap

**Status date:** 2026-09-09  
**Role:** durable project source of truth for human contributors and coding agents.  
**Repositories:** `jayjz/CipherLoop` and `jayjz/TraceForge` (local Windows folder: `TrajectoryLab`).

> If this document conflicts with implementation, tests, or a newer explicit user instruction, inspect the repository and resolve the conflict explicitly. Code and tests remain authoritative for current behavior.

---

## 1. Executive strategy

CipherLoop should not compete as another generic “AI security scanner.” That market already contains platform-native and specialist vendors with stronger distribution, language coverage, security intelligence, and integrated remediation.

The stronger position is:

> **Evidence-first evaluation and reliability infrastructure for agentic security work.**

CipherLoop is the reference security agent and evidence producer. TrajectoryLab is the independent evaluation layer that tests whether an agent’s findings and execution claims are reproducible, source-backed, and operationally trustworthy.

Long-term thesis:

```text
tool-using security agent
        ↓
versioned evidence contract
        ↓
durable trajectory + source-backed findings
        ↓
independent evaluation
        ↓
measurable reliability / regression evidence
```

Potential moat:
1. rigorous evidence contracts,
2. reproducible evaluation,
3. benchmark corpora and failure taxonomies,
4. historical trajectory data,
5. agent-agnostic adapters,
6. trustworthy workflow integration.

The moat should not depend on owning one LLM, scanner, or orchestration framework.

---

# 2. Current verified project state

## CipherLoop

At preparation time:

- `main`: `f03a1e186e491cf24aa0f0e0671cac766c1fa8ab`
- `feat/production-evidence-capture`: `84c96e7656ad12c2a662681897093d2a6c5a60b6`
- `docs/production-evidence-capture`: `cc948845d12bbd80af0c6bec1d3021964406f92c`
- `wip/windows-existing-work`: `12b83857161e2ac68a7c31d68e6b9800805a54e3`

`feat/production-evidence-capture` is one commit ahead of `main`, zero behind, and its only committed delta is `docs/production-evidence-capture-plan.md`.

Implemented today:
- configurable cloud planner/synthesizer,
- local Ollama tactical executor,
- LangGraph orchestration,
- sandboxed tools,
- Semgrep primary scanning,
- sandboxed regex/ripgrep fallback when Semgrep fails,
- deterministic tool-output compression,
- bounded active message state,
- append-only JSONL trajectory recording,
- AST-based intra-procedural evidence validation,
- aggregate compression/validation telemetry,
- offline positive and negative controls.

### Documentation discrepancy

The current README describes an `AST Validator → Semgrep fallback` flow. Current implementation instead uses:

```text
Semgrep primary
   ↓ failure/crash
sandboxed regex/ripgrep fallback
   ↓
compressed candidate
   ↓
AST evidence validation
```

Agents must follow implementation/tests over stale README prose.

### Production evidence gap

Current persistence does not yet capture enough for independent production evaluation. Missing or incomplete areas include:
- original task identity,
- explicit run lifecycle,
- exact compressed records,
- individual candidate decisions,
- verified/rejected findings,
- rejection reasons,
- source reads,
- immutable analyzed source,
- source slices,
- interruption/finalization evidence,
- model/provider provenance.

The design exists in `docs/production-evidence-capture-plan.md`; implementation has not begun.

## TrajectoryLab / TraceForge

Local folder: `TrajectoryLab`  
Upstream: `jayjz/TraceForge`  
Current `main`: `25668c4db622a322b87271825ce68fd37390f3ec`

Implemented:
- deterministic two-case offline CipherLoop baseline,
- real CipherLoop compressor/AST-validator/recorder use,
- artifact ingestion,
- schema and provenance checks,
- deterministic independent fixture oracle.

Explicitly not established:
- general detection accuracy,
- scanner coverage,
- production ingestion,
- general trajectory scoring,
- calibrated LLM judging,
- broad agent compatibility.

The synthetic baseline should remain frozen while production ingestion is developed separately.

---

# 3. Porter’s Five Forces

## Rivalry — HIGH

The surrounding market includes GitHub Code Security/CodeQL/Copilot Autofix, OpenAI Codex Security, Snyk Code/DeepCode AI/Agent Fix, Semgrep, and other AppSec platforms.

These competitors possess mature distribution, security intelligence, broad language support, and integrated remediation.

**Implication:** do not sell “smarter AI vulnerability scanning.” Position around evidence quality, reproducibility, trajectory evaluation, and accountability. Existing scanners can become inputs.

## Threat of new entrants — HIGH

LLM orchestration, tool APIs, open-source agent frameworks, and scanners make prototypes easy to assemble.

**Implication:** architecture alone is not defensible. Defensibility must accumulate through benchmarks, schemas, trajectory datasets, interoperability, and reputation for rigorous evaluation.

## Threat of substitutes — HIGH

Substitutes include CodeQL, Semgrep, Snyk, GitHub Advanced Security, Codex Security, manual review, pen testing, CI SAST, and general coding agents.

**Implication:** perform a job substitutes do poorly: prove what the agent observed, how it reached a claim, whether evidence is independently reproducible, and whether behavior regressed.

## Buyer power — HIGH initially

Security teams have many tools and expect evidence on false positives, integration, data handling, security controls, and cost.

**Implication:** do not optimize pricing or enterprise packaging yet. First reduce buyer uncertainty with independent benchmark evidence.

## Supplier power — MEDIUM/HIGH

Suppliers include model vendors, Ollama/model ecosystems, GitHub, Semgrep/CodeQL, LangGraph, registries, and CI.

**Mitigation:** keep core evidence/evaluation artifact-driven, provider-agnostic, scanner-agnostic where possible, versioned, and reproducible offline.

## Conclusion

Generic AI AppSec scanning is structurally unattractive. Evidence/evaluation infrastructure for agents is more defensible but unproven.

**Strategic decision:** pursue **agent evidence, evaluation, and reliability**, with security auditing as the first proving domain.

---

# 4. Jobs to Be Done

## AppSec / security engineer

> When an AI security agent reports a vulnerability, help me determine quickly whether the finding is real, reproducible, and supported by evidence the agent actually observed, so I can trust or reject it without repeating the investigation manually.

Desired outcomes:
- exact evidence,
- reproducible source/sink relationship,
- rejection visibility,
- incomplete-run detection,
- lower triage noise,
- release-to-release comparison.

## AI-agent engineer

> When I change a planner, model, tool, memory strategy, or prompt, help me know whether reliability improved or regressed, so I can ship from measured behavior rather than demos and intuition.

Desired outcomes:
- deterministic regression tests,
- trajectory comparison,
- failure classification,
- benchmark pass/fail,
- tool-use correctness,
- reproducible artifacts.

## Security researcher / evaluator

> When I study autonomous security agents, give me durable artifacts and independent evaluation rules so results can be reproduced and compared across systems.

## Future governance owner

> When autonomous agents operate in my organization, help me prove what they did and whether their decisions satisfied evidence requirements, so I can govern them without reviewing every action manually.

This future job is premature until the technical evidence model is validated.

---

# 5. Product positioning

Avoid:
- “AI-powered SAST”
- “better Semgrep”
- “autonomous pentester”
- “AI auditor that finds what others miss”
- “enterprise governance platform”

Current positioning:

**CipherLoop:** experimental evidence-producing security agent for studying reliable tool-using audits under context/privacy constraints.

**TrajectoryLab:** experimental evaluator for deciding whether tool-using agent outcomes are reproducible, evidence-backed, and regression-safe.

**Combined thesis:** **Build agents that leave enough evidence to be independently evaluated.**

---

# 6. Strategic hypotheses

### H1 — Evidence reduces false confidence
Structured evidence should expose incomplete, unsupported, or contradictory outcomes hidden by final reports.

### H2 — Trajectory evaluation catches regressions final-answer tests miss
Planner/model/tool changes can preserve an answer while degrading process quality.

### H3 — Independent evaluation beats self-grading
Artifact-only evaluation should be more trustworthy than asking the same agent to judge itself.

### H4 — The evaluator can generalize beyond CipherLoop
A second producer should map into the same normalized evidence model without rewriting the core evaluator.

Treat all four as hypotheses until measured.

---

# 7. Kill / pivot criteria

Reassess if:
1. evidence checks rarely change decisions,
2. capture cost/latency/storage is excessive,
3. evaluation cannot generalize beyond CipherLoop,
4. useful regressions cannot be measured,
5. incumbents expose equivalent durable evidence,
6. users value scan speed far more than proof/reproducibility,
7. benchmark results are not better than a simpler scanner + deterministic tests for the target job.

An elegant architecture without a differentiated job is not a product.

---

# 8. Engineering principles

1. **Evidence before claims.** Label claims source-, test-, benchmark-, production-verified, or hypothesis.
2. **Deterministic ground truth before LLM judges.**
3. **Separate producer and evaluator.**
4. **Version every durable contract.**
5. **Incomplete is not negative.**
6. **Use small implementation batches with explicit gates.**
7. **Treat reproducibility as a feature.**
8. **Use NIST SSDF as the secure-development baseline.**
9. **Record provenance explicitly; use SLSA as a conceptual reference.**
10. **Follow SWEBOK fundamentals: requirements, architecture, testing, quality, operations, security, configuration management.**
11. **Keep benchmark dimensions separate:** detection, evidence integrity, process quality, runtime/cost.
12. **Do not build product UI before the measurement layer is trustworthy.**

---

# 9. Codex operating policy

Current OpenAI guidance favors precise, repository-grounded, issue-like tasks and persistent repo context.

## Persistent context
Keep `AGENTS.md` short and true. It should reference this document rather than duplicate strategy.

Recommended line:

```text
For product strategy, evidence principles, project boundaries, and roadmap, read docs/PROJECT_STRATEGY_AND_ENGINEERING_ROADMAP.md. Source and tests remain authoritative for current behavior.
```

## Task prompts
Every substantial Codex prompt should define:
- objective,
- branch,
- relevant files,
- scope,
- forbidden side effects,
- acceptance criteria,
- appropriate tests,
- final report format.

## Follow-through
For implementation tasks require:

```text
inspect → reproduce → implement → test → review diff → summarize
```

unless a material blocker requires a user decision.

## Verification
Calibrate tests to risk:
1. focused tests,
2. required static checks,
3. one broader regression pass when justified.

Do not repeatedly run broad suites for tiny reversible changes.

## Batch size
Do not combine architecture redesign, schema migration, CI, product strategy, docs, and unrelated refactors into one agent task.

## Model choice
Use stronger reasoning for architecture, security boundaries, lifecycle, migration, and cross-repo contracts. Use faster models for mechanical cleanup and narrow repairs. Correctness is gated by evidence/tests, not model branding.

---

# 10. Testing strategy

## Unit
- schema validation,
- event serialization,
- sequence IDs,
- lifecycle transitions,
- error mapping,
- source slicing,
- hashes,
- normalization.

## Integration
- recorder + compressor,
- validator + source capture,
- CLI + finalization,
- production artifact + TrajectoryLab adapter.

## End to end
Maintain controlled positive and negative cases. Default deterministic regression must not require a live cloud model.

## Failure
First-class cases:
- scanner/tool crash,
- fallback crash,
- malformed result,
- source-read failure,
- syntax failure,
- validator rejection,
- graph exception,
- interruption,
- finalization failure,
- partial artifact,
- incompatible contract version.

---

# 11. Metrics hierarchy

## Level 1 — artifact integrity
- schema-valid runs,
- complete lifecycle,
- valid references,
- hash consistency,
- no dangling event refs.

## Level 2 — evidence quality
- candidate→decision coverage,
- verified-source completeness,
- rejection-reason coverage,
- reproducibility rate.

## Level 3 — task quality
Once independent labeled benchmarks exist:
- TP,
- FP,
- FN,
- precision,
- recall,
- class-specific performance.

## Level 4 — process quality
Later:
- unnecessary tool calls,
- retry efficiency,
- recovery behavior,
- evidence-acquisition efficiency,
- context-compression behavior,
- lucky-pass detection.

## Level 5 — product outcomes
Only after users:
- triage time saved,
- review time saved,
- findings accepted,
- regressions caught,
- reproduction time,
- percentage of runs independently auditable.

---

# 12. Roadmap

## Phase 0 — Strategy/truth baseline
**Status: current.**

- add this document,
- keep production evidence plan as immediate technical design,
- make `AGENTS.md` reference this file,
- correct README architecture contradiction separately.

**Exit:** humans/agents have one durable strategy reference.

## Phase 1 — CipherLoop production evidence contract
**Next implementation milestone.**

Implement the smallest useful slice from `docs/production-evidence-capture-plan.md`.

Required:
- contract version,
- full run identity,
- run.started,
- completed/failed/interrupted lifecycle,
- persisted individual validation decisions,
- verified findings,
- rejection reasons,
- source-read evidence,
- immutable analyzed text/hash,
- source slices,
- unambiguous final summary.

Do not change detection, planner, scanner behavior, add LLM judging, dashboards, or frozen TrajectoryLab fixtures.

**Exit:** deterministic offline runs distinguish verified positive, valid negative, rejected candidate, failed run, interrupted/incomplete run.

## Phase 2 — TrajectoryLab production adapter
Build a separate production adapter; preserve fixture baseline.

Required:
- production-v1 ingestion,
- seq/ref integrity,
- lifecycle validation,
- hash/slice validation,
- finding/decision normalization,
- explicit incompatible/incomplete errors.

**Exit:** real production-style CipherLoop artifact ingests without synthetic sidecars.

## Phase 3 — Cross-repo contract CI
- pin compatible revisions,
- offline contract fixtures,
- producer/consumer drift checks.

**Exit:** breaking contract changes fail before merge.

## Phase 4 — Independent benchmark corpus
Start with 10–30 curated cases:
- command injection,
- SQL injection,
- path traversal,
- unsafe deserialization,
- secrets,
- safe near-misses,
- sanitization,
- scanner errors,
- malformed source.

Each case needs an independent oracle.

**Exit:** report TP/FP/FN without using CipherLoop’s verdict as truth.

## Phase 5 — Baseline comparisons
Compare:
1. scanner-only,
2. scanner + deterministic validator,
3. full CipherLoop evidence flow.

Questions:
- false-positive reduction?
- true-positive loss?
- planning coverage value?
- compression evidence loss?
- hidden failure modes?

**Exit:** at least one architectural choice has quantitative justification.

## Phase 6 — Failure taxonomy / trajectory metrics
Stabilize categories before weighted scoring:
- tool-selection error,
- tool failure,
- malformed result,
- evidence loss,
- unsupported claim,
- duplicate/revalidation loop,
- incomplete lifecycle,
- unnecessary retry,
- lucky pass.

**Exit:** known failure fixtures classify deterministically.

## Phase 7 — Second-agent adapter
Add another producer.

**Exit:** two producers map to a shared normalized model.

## Phase 8 — Workflow integration
Only after credible evaluation:
- CLI,
- GitHub Action,
- PR summary,
- SARIF where appropriate,
- machine-readable artifacts.

## Phase 9 — User discovery / pilots
Interview:
- AppSec engineers,
- security-conscious AI teams,
- agent developers,
- researchers.

Measure repeated jobs/pains before productization.

## Phase 10 — Product decision
Possible outcomes:
- security-agent evaluator,
- general agent evidence platform,
- CipherLoop product,
- research/portfolio artifact.

All are acceptable if supported by evidence.

---

# 13. Immediate execution order

```text
1. Add this document to CipherLoop.
2. Add one AGENTS.md reference to it.
3. Run bounded Phase 1 production-evidence implementation.
4. Review/merge only after focused verification.
5. Build TrajectoryLab production adapter.
6. Add cross-repo compatibility CI.
7. Build first independent benchmark corpus.
8. Measure before broad scoring or UI.
```

---

# 14. Decision log

## 2026-09-09 — Product wedge
Pursue evidence/evaluation infrastructure rather than generic AI AppSec positioning.

## 2026-09-09 — Two-repo separation
CipherLoop produces evidence; TrajectoryLab independently evaluates it.

## 2026-09-09 — Production evidence before adaptive rubrics
Do not prioritize weighted rubrics, LLM judges, dashboards, or broad scores until real production artifacts can be independently ingested.

---

# 15. References

## Strategy
- Porter, M. E. (1979). *How Competitive Forces Shape Strategy.* Harvard Business Review. https://hbr.org/1979/03/how-competitive-forces-shape-strategy
- Porter, M. E. (1980). *Competitive Strategy.* Free Press.
- Porter, M. E. (2008). *The Five Competitive Forces That Shape Strategy.* Harvard Business Review.
- Christensen, C. M., Hall, T., Dillon, K., & Duncan, D. S. (2016). *Know Your Customers’ “Jobs to Be Done.”* Harvard Business Review. https://hbr.org/2016/09/know-your-customers-jobs-to-be-done
- Christensen, C. M., Hall, T., Dillon, K., & Duncan, D. S. (2016). *Competing Against Luck.* HarperBusiness.
- Grant, R. M. *Contemporary Strategy Analysis.* Wiley.

## Software engineering / security
- Washizaki, H. (ed.) (2024). *Guide to the Software Engineering Body of Knowledge (SWEBOK Guide), Version 4.0.* IEEE Computer Society. https://www.computer.org/education/bodies-of-knowledge/software-engineering/resources/
- Scarfone, K., Souppaya, M., & Dodson, D. (2022). *NIST SP 800-218: SSDF Version 1.1.* https://doi.org/10.6028/NIST.SP.800-218
- NIST (2025). *SP 800-218 Rev.1 Initial Public Draft: SSDF Version 1.2.* https://csrc.nist.gov/pubs/sp/800/218/r1/ipd
- Forsgren, N., Humble, J., & Kim, G. (2018). *Accelerate.* IT Revolution.
- Google Cloud DORA (2024). *Accelerate State of DevOps Report 2024.* https://dora.dev/research/2024/
- SLSA v1.2 (2026). https://slsa.dev/spec/v1.2/

## Agent / benchmark research
- Liu, X. et al. *AgentBench: Evaluating LLMs as Agents.* ICLR 2024 / arXiv:2308.03688. https://arxiv.org/abs/2308.03688
- Jimenez, C. E. et al. *SWE-bench: Can Language Models Resolve Real-World GitHub Issues?* https://arxiv.org/abs/2310.06770
- Siddiq, M. L. et al. (2025). *Large Language Models for Software Engineering: A Reproducibility Crisis.* https://arxiv.org/abs/2512.00651
- Kulsum, U., Zhu, H., Xu, B., & d’Amorim, M. (2024). *A Case Study of LLM for Automated Vulnerability Repair.* https://arxiv.org/abs/2405.15690

## Current development / market references checked 2026-09-09
- OpenAI model guidance: https://developers.openai.com/api/docs/guides/latest-model
- OpenAI, *How OpenAI uses Codex*: https://openai.com/business/guides-and-resources/how-openai-uses-codex/
- OpenAI Codex Security: https://openai.com/index/codex-security-now-in-research-preview/
- GitHub Code Security: https://github.com/security/advanced-security/code-security
- Snyk DeepCode AI: https://snyk.io/platform/deepcode-ai/
- SLSA provenance: https://slsa.dev/spec/v1.2/provenance

---

# 16. Agent usage

Before substantial work:
1. read `AGENTS.md`,
2. read this file,
3. read the relevant milestone/design document,
4. inspect branch/status,
5. verify assumptions against source/tests.

At completion report:
- changed files,
- verified behavior,
- tests/checks run,
- failed/skipped checks,
- remaining assumptions,
- next bounded milestone.
