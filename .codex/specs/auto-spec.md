# Spec: Update README.md with AST Validator and Semgrep Fallback Documentation

## Role
Senior Staff Engineer Architect

## Goal
Document the AST Validator and the Semgrep fallback mechanism in `README.md` to reflect recent architecture and reliability updates.

---

## Targeted Files
- `README.md`

---

## Detailed Instructions

### 1. Locate/Add Architecture or Feature Sections in `README.md`
Read `README.md` to understand its existing layout and structure. Identify where features and architecture components are described (e.g., under `## Features`, `## Architecture`, or `## Core Components`).

### 2. Add Section: AST Validator
Insert documentation detailing the **AST Validator** component:
- **Purpose**: Explain that the AST (Abstract Syntax Tree) Validator inspects and validates target source code structure prior to deep analysis or transformation.
- **Key Functionality**:
  - Ensures syntax correctness and safe parsing before downstream execution.
  - Detects malformed, unsupported, or unsafe AST nodes early.
  - Prevents engine crashes or undefined behavior when encountering invalid syntax.

### 3. Add Section: Semgrep Fallback Mechanism
Insert documentation detailing the **Semgrep Fallback Mechanism**:
- **Purpose**: Guarantees resilient scanning and rule execution when full AST parsing or native engine processing cannot be completed (e.g., due to syntax errors, partial code snippets, or unsupported language constructs).
- **Execution Flow**:
  1. **Primary Pass**: Attempt AST parsing and validation via the native AST validator/engine.
  2. **Fallback Trigger**: If AST parsing/validation fails or returns an recoverable syntax error:
     - Log a non-fatal warning describing the fallback trigger.
     - Automatically route execution to the Semgrep engine fallback mode.
  3. **Secondary Pass**: Semgrep pattern matching executes against the source text to maintain scan coverage without failing the pipeline.
- **Benefits**: Ensures high availability and continuous coverage across partial or legacy codebases without blocking CI/CD pipelines.

### 4. Visual Workflow (Optional / ASCII Diagram)
Include a brief ASCII diagram illustrating the validation & fallback pipeline:
```
[ Source Code ]
       │
       ▼
[ AST Validator ] ──── (Valid) ──────► [ Native Engine Analysis ]
       │
   (Invalid /
   Unsupported)
       │
       ▼
[ Semgrep Fallback ] ─────────────────► [ Pattern-based Results ]
```

---

## Verification & Acceptance Criteria

1. **File Updated**: `README.md` contains dedicated, clearly structured headers for both `AST Validator` and `Semgrep Fallback Mechanism`.
2. **Formatting**: Markdown headers, code blocks, lists, and ASCII diagrams render cleanly without formatting errors.
3. **Accuracy**: Content accurately conveys AST validation preceding full analysis, and Semgrep acting as a graceful fallback on parsing failures.