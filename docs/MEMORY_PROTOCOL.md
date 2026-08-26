# CipherLoop Memory Management Protocol

## 1. The Context Collapse Problem
In autonomous code auditing, passive appending of raw execution logs (e.g., `stdout` from `grep` or `semgrep`) into the agent's context window inevitably leads to context exhaustion, hallucination, and loop degradation (as demonstrated in recent frameworks like STACKPLANNER and Living-Harness).

## 2. Hierarchical Memory Structure
CipherLoop enforces a strict separation between Working Memory and Episodic Reflection:
- **Working Memory (The Sandbox):** Tactical, short-term logs. Exists only during the active LangGraph execution node.
- **Episodic Memory (The Record):** High-level strategic state. Maintained dynamically in Markdown.

## 3. Agentic Update Rules
When operating within this repository, all AI agents MUST adhere to the following file manipulation rules:

1. **Never dump raw stdout:** Tools like `grep` or `tree` output must be parsed and summarized BEFORE being committed to memory.
2. **Timestamped Reflection (`docs/AGENT_LOG.md`):** After completing a planning cycle or finishing a tool execution chain, the Orchestrator MUST append a concise reflection block to `docs/AGENT_LOG.md`. 
3. **Format Requirement:**
   - Append using `[YYYY-MM-DD HH:MM:SS]`
   - Structure: `State` -> `Action Taken` -> `Outcome/Observation` -> `Strategic Shift`.
4. **State Mutability:** Do not edit past log entries. Memory is an append-only time-series stream to preserve the trajectory for TraceForge evaluation.
