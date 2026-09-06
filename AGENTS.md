# CipherLoop Operating Protocol

## Core Invariants
- **Air-Gap Security:** All tactical tool execution MUST occur inside the `cipherloop-sandbox` Docker container (`network_mode: none`). Never expose raw host filesystem access to the Cloud Orchestrator.
- **Strict POSIX Paths:** All paths sent to sandbox execution must use `posixpath`. Never introduce `os.path` operations for container workloads.
- **Deterministic Memory:** Never append raw `stdout` to `AuditState.messages`. All tool output must pass through `compressor_node` and be sheared with `RemoveMessage`.
- **Evidence Threshold:** No vulnerability may be labeled `VERIFIED` without a reproducible source, sink, and valid code slice.

## Development Workflow
- Follow "Spec-Driven Development": Read feature specs in `/specs`, implement, and ensure `pytest` passes before concluding a thread.
- Use `/compact` frequently to maintain context.