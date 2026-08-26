# CipherLoop

**A Context-Compressed Hybrid Code Auditing Agent**

CipherLoop is an experimental cybersecurity agent framework utilizing a hybrid local/cloud LangGraph architecture to conduct long-horizon source code audits.

## ⚠️ The Research Problem
Modern LLM agents excel at logical reasoning but fail catastrophically during extensive codebase audits due to **Context Collapse**. When agents passively ingest massive outputs from static analysis tools (`semgrep`, `ripgrep`, AST parsers), their context windows degrade, leading to hallucinations, infinite loops, and "Lucky Passes."

## 🛡️ The Architecture
CipherLoop solves this by implementing a hierarchical multi-agent topology inspired by recent literature on explicitly managed agent memory and trajectory compression:

1. **The Cloud Orchestrator (Claude 3.5 Sonnet / GPT-4o):**
   - Handles high-level planning, vulnerability triage, and attack-chain synthesis.
   - **Never** executes raw commands.

2. **The Tactical Executor (Local Hermes 8B via Ollama):**
   - Operates entirely within a sandboxed Docker container (`network_mode: none`).
   - Runs high-volume micro-loops executing `ripgrep`, `tree`, and `semgrep`.
   - Context is heavily sheared; it only possesses the immediate tactical horizon.

3. **The Memory Hypervisor (The Context Compressor):**
   - Serves as the state gateway between the local executor and the cloud orchestrator.
   - Summarizes and parses raw `stdout` into structured JSON findings before passing state back up the graph, preventing context bloat.

## 🚀 Quick Start
*Documentation for deployment and execution is pending first stable release.*

## 📚 Trajectory Evaluation
CipherLoop is designed to generate deterministic Directed Acyclic Graph (DAG) traces of its execution, which are explicitly formatted to be ingested and evaluated by **TraceForge**, ensuring the agent's findings are grounded in valid, safe, and recoverable processes.
