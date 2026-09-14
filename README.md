
<div align="center">
  <!-- Optional Hero Image Placeholder: Replace the src with a real banner image if you design one in Figma/ComfyUI -->
  <img src="https://images.unsplash.com/photo-1555949963-ff9fe0c870eb?q=80&w=1200&auto=format&fit=crop" alt="CipherLoop Hero" width="100%" style="border-radius: 10px; opacity: 0.8; margin-bottom: 20px;">

  <h1>🛡️ CipherLoop</h1>
  <p><b>A Context-Compressed, Privacy-Preserving Hybrid Code Auditing Agent</b></p>

  <a href="https://python.org"><img src="https://img.shields.io/badge/Python-3.11+-blue.svg?logo=python&logoColor=white" alt="Python"></a>
  <a href="https://docker.com"><img src="https://img.shields.io/badge/Sandbox-Docker-2496ED.svg?logo=docker&logoColor=white" alt="Docker"></a>
  <a href="https://ollama.com"><img src="https://img.shields.io/badge/Local_Executor-Ollama-orange.svg" alt="Local Model"></a>
  <a href="https://langchain.com"><img src="https://img.shields.io/badge/Orchestrator-Configurable_LLM-D97757.svg" alt="Cloud Model"></a>
</div>

<br>

CipherLoop is an experimental evidence-producing security agent using a hybrid
local/cloud LangGraph architecture. It records tool observations, compressed
signals, and source-backed validation decisions for independent evaluation.

Production evidence v2 (P0.1) and TraceForge's initial production ingestion (P0.2)
are implemented and verified offline. A real preflight failure was captured and
ingested correctly. A successful live Docker/Ollama/model audit has not yet been
demonstrated. See the [contract](docs/production-evidence-contract.md) and
[release review](docs/release-review-2026-09-12.md) for the exact scope.

---

## 🧠 The Architecture (How It Works)

```mermaid
graph TD
    classDef cloud fill:#2d3748,stroke:#4a5568,stroke-width:2px,color:#fff;
    classDef local fill:#2b6cb0,stroke:#2c5282,stroke-width:2px,color:#fff;
    classDef sandbox fill:#c53030,stroke:#9b2c2c,stroke-width:2px,color:#fff;
    classDef memory fill:#276749,stroke:#22543d,stroke-width:2px,color:#fff;

    subgraph Cloud Orchestrator
        P[Planner Node<br>Configured Cloud LLM]:::cloud
        S[Synthesizer Node<br>Final Report]:::cloud
    end

    subgraph Local Edge Executor
        LM[Local Model<br>Configured Ollama Model]:::local
        C[Context Compressor<br>Deterministic Parser]:::local
        V[AST Evidence Validator]:::local
        WAL[(Trajectory Ledger<br>JSONL WAL)]:::memory
    end

    subgraph Air-Gapped Docker Sandbox
        ST[Security Tools<br>semgrep, rg, tree]:::sandbox
    end

    P -->|Tactical Plan| LM
    LM <-->|Micro-Loop| ST
    LM -->|Raw Exec Log| C
    C -->|Observed tool evidence| WAL
    C -->|Shear context + compressed candidates| V
    V -->|Source reads and decisions| WAL
    V -->|Next cycle| P
    V -->|Observed completion| S

```

## ⚠️ The Research Problem: Context Collapse

Modern LLM agents excel at logical reasoning but fail catastrophically during extensive codebase audits. When agents passively ingest massive outputs from static analysis tools (`semgrep`, `ripgrep`, AST parsers), their context windows quickly degrade. This leads to hallucinations, infinite loops, and "Lucky Passes" where the agent guesses a vulnerability without proof.

## 🛡️ The CipherLoop Solution

CipherLoop introduces a strict **Memory Hypervisor** and **Write-Ahead Log (WAL)** to decouple reasoning from tool execution:

1. **The Cloud Orchestrator (Strategic):** A configured Anthropic, OpenAI, or xAI model handles high-level planning, vulnerability triage, and report synthesis. It receives compressed findings rather than raw tool output.
2. **The Tactical Executor (Local):** A configured Ollama model runs high-volume micro-loops over `ripgrep`, `tree`, and `semgrep`. The active message state is swept after compression to keep tactical context bounded.
3. **The Air-Gapped Sandbox:** Tactical tools execute in a Docker container with `network_mode: none` and a read-only target mount. This reduces attack surface; before reuse, CipherLoop verifies the container's resolved target-mount identity and replaces stale bindings to prevent cross-contamination.
4. **The AST Evidence Validator:** `validator_node` uses Python's `ast.NodeVisitor` for intra-procedural taint tracking. An upstream `VERIFIED` finding retains the accepted source, path, sink, and analyzed text. This heuristic is not an independent proof of exploitability.
5. **The Context Compressor & WAL:** Raw `stdout` is retained in the append-only JSONL trajectory ledger, while active graph memory is deterministically summarized and swept with LangGraph's `RemoveMessage` reducer.

---

## Scanner and validator flow

Semgrep runs first. A scanner failure invokes the existing sandboxed regex/ripgrep
fallback. The compressor selects candidate summaries, and the AST validator records
each verification, rejection, or unavailable read. Syntax failure rejects a
candidate; it does not trigger Semgrep. Failure of both scanners is retained as
explicit error evidence. Scanner coverage is not established by these checks.

```text
Semgrep → compressed candidates → AST evidence validation
   └ failure → sandboxed regex fallback → compression
```

---

## 🚀 Quick Start

### Prerequisites

* **Python 3.11+**
* **Docker Engine** (running locally)
* **Ollama** (running locally with the model named by `OLLAMA_MODEL`)
* **Credentials for the configured cloud provider** (`anthropic`, `openai`, or `xai`)

### 1. Installation

Clone the repository and set up your virtual environment:

```bash
git clone https://github.com/jayjz/CipherLoop.git
cd CipherLoop

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install in editable mode with dev dependencies
pip install -e ".[dev]"

```

### 2. Configuration

Copy the environment template and select a cloud provider, cloud model, and local Ollama model:

```bash
cp .env.example .env
# Edit .env: set the selected provider's API key/model and OLLAMA_BASE_URL/OLLAMA_MODEL

```

Ensure Ollama has the execution model pulled:

```bash
ollama pull <your OLLAMA_MODEL value>

```

### 3. Execution

Launch the CLI against a target directory. CipherLoop verifies any existing sandbox's resolved target mount before reuse; a mismatched binding is replaced before the audit begins.

```bash
python -m cipherloop.main ./path/to/target/repo --plan "Hunt for hardcoded credentials and remote code execution."

```

---

## 📚 TraceForge Integration (Evaluation)

CipherLoop attempts to reserve a fresh `trajectory_<UUID>.jsonl` ledger in `./traces/`
before preflight and publishes `metadata_<UUID>.json` only after finalization.
Missing metadata means incomplete evidence, even if a finish event exists. Failed
or interrupted execution is never a successful zero-finding audit.

The `TrajectoryRecorder` records tool-level `raw_char_count` and `compressed_char_count`, then calculates the run-wide compression ratio in metadata. Validation events also record total candidates, verified findings, and the candidate-to-verified ratio. These measurements can be ingested by **[TraceForge](https://github.com/jayjz/TraceForge)** to evaluate compression efficiency and evidence quality empirically.

TraceForge independently checks artifact integrity and source locations, without
importing CipherLoop. Its production `PASS` is not target safety, scanner accuracy,
task success, agent reliability, or exploitability. Hashes check consistency, not
producer authenticity. The offline CI gate runs tests and scripted captures without
Docker, Ollama, credentials, GPU, or model access; a hosted pass remains unverified.

## 🔒 Security Notice

Do **NOT** mount live production credentials or highly sensitive data into the target directory unless you understand the risks. While the sandbox is air-gapped (`network_mode: none`), the local LLM will parse the files it is instructed to read.

---
