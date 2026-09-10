import ast
import hashlib
from dataclasses import dataclass

from langchain_core.runnables import RunnableConfig

from cipherloop.core.state import AuditState, CodeLocation, VerifiedFinding
from cipherloop.core.trajectory import TrajectoryRecorder
from cipherloop.tools.filesystem import read_file

SOURCE_PREFIXES = (
    "request.args",
    "request.form",
    "request.values",
    "request.json",
    "request.get_json",
    "sys.argv",
    "os.environ",
)
SOURCE_CALLS = {"input"}
DANGEROUS_SINKS = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
    "os.system",
    "os.popen",
    "eval",
    "exec",
}


@dataclass(frozen=True)
class TaintTrace:
    source: CodeLocation
    sink: CodeLocation
    path: list[str]


@dataclass(frozen=True)
class _ValidationEvidence:
    trace: TaintTrace | None
    source_code: str | None
    reason: str | None
    error: Exception | None
    source_read_ref: int | None = None


def _dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else None
    return None


def _reference(location: CodeLocation) -> str:
    return f"{location['file']}:{location['line']}:{location['symbol']}"


class _TaintAnalyzer(ast.NodeVisitor):
    """Conservative, intra-procedural taint tracking for command-execution calls."""

    def __init__(self, target_file: str, expected_sink_line: int | None) -> None:
        self.target_file = target_file
        self.expected_sink_line = expected_sink_line
        self.bindings: dict[str, tuple[CodeLocation, list[str]]] = {}
        self.traces: list[TaintTrace] = []

    def _location(self, node: ast.AST, symbol: str) -> CodeLocation:
        return {"file": self.target_file, "line": node.lineno, "symbol": symbol}

    def _source_trace(self, node: ast.AST) -> tuple[CodeLocation, list[str]] | None:
        symbol: str | None = None
        if isinstance(node, ast.Call):
            dotted = _dotted_name(node.func)
            if dotted in SOURCE_CALLS or dotted and dotted.startswith(SOURCE_PREFIXES):
                symbol = dotted
        else:
            dotted = _dotted_name(node)
            if dotted and dotted.startswith(SOURCE_PREFIXES):
                symbol = dotted

        if symbol is None:
            return None
        location = self._location(node, symbol)
        return location, [_reference(location)]

    def _taint_from_expression(
        self, node: ast.AST
    ) -> tuple[CodeLocation, list[str]] | None:
        source = self._source_trace(node)
        if source:
            return source
        if isinstance(node, ast.Name):
            return self.bindings.get(node.id)

        for child in ast.iter_child_nodes(node):
            taint = self._taint_from_expression(child)
            if taint:
                return taint
        return None

    def _bind_target(
        self, target: ast.AST, taint: tuple[CodeLocation, list[str]] | None
    ) -> None:
        if not isinstance(target, ast.Name):
            return
        if taint is None:
            self.bindings.pop(target.id, None)
            return

        source, path = taint
        variable_location = self._location(target, target.id)
        self.bindings[target.id] = (source, [*path, _reference(variable_location)])

    def visit_Assign(self, node: ast.Assign) -> None:
        taint = self._taint_from_expression(node.value)
        self.visit(node.value)
        for target in node.targets:
            self._bind_target(target, taint)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is None:
            return
        taint = self._taint_from_expression(node.value)
        self.visit(node.value)
        self._bind_target(node.target, taint)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        outer_bindings = self.bindings
        self.bindings = {}
        for statement in node.body:
            self.visit(statement)
        self.bindings = outer_bindings

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node: ast.Call) -> None:
        sink_symbol = _dotted_name(node.func)
        if (
            sink_symbol in DANGEROUS_SINKS
            and (self.expected_sink_line is None or node.lineno == self.expected_sink_line)
        ):
            for argument in [*node.args, *(keyword.value for keyword in node.keywords)]:
                taint = self._taint_from_expression(argument)
                if taint is None:
                    continue
                source, path = taint
                sink = self._location(node, sink_symbol)
                self.traces.append(TaintTrace(source, sink, [*path, _reference(sink)]))
                break
        self.generic_visit(node)


def find_taint_trace(
    source_code: str, target_file: str, expected_sink_line: int | None = None
) -> TaintTrace | None:
    """Return an AST-backed source-to-sink trace, or ``None`` when none exists."""
    trace, _reason = _find_taint_trace_with_reason(
        source_code, target_file, expected_sink_line=expected_sink_line
    )
    return trace


def _find_taint_trace_with_reason(
    source_code: str, target_file: str, expected_sink_line: int | None = None
) -> tuple[TaintTrace | None, str | None]:
    try:
        tree = ast.parse(source_code, filename=target_file)
    except SyntaxError:
        return None, "syntax_error"

    analyzer = _TaintAnalyzer(target_file, expected_sink_line)
    analyzer.visit(tree)
    if analyzer.traces:
        return analyzer.traces[0], None
    return None, "no_taint_trace"


def _inspect_finding_evidence(
    target_file: str,
    line_num: int,
    *,
    recorder: TrajectoryRecorder | None = None,
    candidate_ref: int | None = None,
) -> _ValidationEvidence:
    arguments = {"filepath": target_file, "start_line": 1, "end_line": 1_000_000}
    source_code = None
    read_error = None
    try:
        source_code = read_file.invoke(arguments)
    except Exception as exc:  # noqa: BLE001 - preserve the existing all-read-failure rejection.
        read_error = exc

    source_read_ref = None
    if recorder is not None:
        # Retain the observed read before parsing/walking can fail or be interrupted.
        source_read_ref = recorder.record_step(
            "source.read",
            {
                "candidate_ref": candidate_ref,
                "arguments": arguments,
                "status": "error" if read_error is not None else "returned",
                "text": source_code,
                "text_sha256": (
                    hashlib.sha256(source_code.encode("utf-8")).hexdigest()
                    if read_error is None else None
                ),
                "error": (
                    {
                        "stage": "validation_read",
                        "type": type(read_error).__name__,
                        "message": str(read_error),
                    }
                    if read_error is not None else None
                ),
            },
        )

    if read_error is not None:
        return _ValidationEvidence(None, None, "read_exception", read_error, source_read_ref)

    if "Tool Execution Error" in source_code or "System Error" in source_code:
        return _ValidationEvidence(None, source_code, "read_error_marker", None, source_read_ref)
    trace, reason = _find_taint_trace_with_reason(
        source_code, target_file, expected_sink_line=line_num
    )
    return _ValidationEvidence(trace, source_code, reason, None, source_read_ref)


def verify_finding_evidence(target_file: str, line_num: int) -> TaintTrace | None:
    """Read the sandboxed target and verify the reported sink with an AST trace."""
    return _inspect_finding_evidence(target_file, line_num).trace


def _parse_summary(summary: str) -> tuple[str, str, int, str] | None:
    if not summary.startswith("["):
        return None
    severity, separator, remainder = summary[1:].partition("] ")
    if not separator:
        return None
    location, separator, description = remainder.partition(" - ")
    if not separator:
        return None
    path, separator, line = location.rpartition(":")
    if not separator or not line.isdigit():
        return None
    return severity, path, int(line), description


def _verified_finding(
    path: str, line_num: int, severity: str, description: str, trace: TaintTrace
) -> VerifiedFinding:
    return {
        "id": f"VULN-{path.replace('/', '_')}-{line_num}",
        "vulnerability_class": description,
        "severity": severity
        if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        else "MEDIUM",
        "source": trace.source,
        "sink": trace.sink,
        "taint_path": trace.path,
        "evidence_snippet": "AST-verified taint path: " + " -> ".join(trace.path),
        "confidence": 0.9,
        "status": "VERIFIED",
    }


def _source_slice(trace: TaintTrace, source_read_ref: int) -> dict[str, int]:
    lines = [trace.source["line"], trace.sink["line"]]
    for reference in trace.path:
        _file, line, _symbol = reference.rsplit(":", 2)
        lines.append(int(line))
    return {
        "source_read_ref": source_read_ref,
        "start_line": min(lines),
        "end_line": max(lines),
    }


def validator_node(state: AuditState, config: RunnableConfig | None = None) -> dict:
    """Promote only AST-proven untrusted-source to dangerous-sink data flows."""
    config = config or {}
    verified_findings: list[VerifiedFinding] = []
    compressed = state.get("compressed_findings", [])
    recorder = config.get("configurable", {}).get("__trajectory_recorder__")
    is_production = bool(recorder and recorder.is_production)
    cycle = recorder.next_validation_cycle() if is_production else None
    total_candidates = 0

    for state_index, item in enumerate(compressed):
        for summary_index, summary in enumerate(item.get("top_findings", [])):
            candidate_ref = None
            if is_production:
                compression_ref = recorder.compression_ref_for_state_index(state_index)
                if compression_ref is None:
                    raise RuntimeError(
                        f"Missing production compression evidence for state index {state_index}"
                    )
                candidate_ref = recorder.record_step(
                    "validation.candidate",
                    {
                        "cycle": cycle,
                        "compression_ref": compression_ref,
                        "summary_index": summary_index,
                        "summary": summary,
                    },
                )
            parsed = _parse_summary(summary)
            if parsed is None:
                if is_production:
                    recorder.record_step(
                        "validation.decision",
                        {
                            "candidate_ref": candidate_ref,
                            "disposition": "skipped",
                            "reason": "malformed_summary",
                            "source_read_ref": None,
                            "finding": None,
                            "source_slice": None,
                        },
                    )
                continue
            total_candidates += 1
            severity, path, line_num, description = parsed
            evidence = _inspect_finding_evidence(
                path, line_num, recorder=recorder if is_production else None,
                candidate_ref=candidate_ref,
            )
            source_read_ref = evidence.source_read_ref
            if evidence.trace is None:
                if is_production:
                    recorder.record_step(
                        "validation.decision",
                        {
                            "candidate_ref": candidate_ref,
                            "disposition": "rejected",
                            "reason": evidence.reason,
                            "source_read_ref": source_read_ref,
                            "finding": None,
                            "source_slice": None,
                        },
                    )
                continue

            finding = _verified_finding(path, line_num, severity, description, evidence.trace)
            verified_findings.append(finding)
            if is_production:
                recorder.record_step(
                    "validation.decision",
                    {
                        "candidate_ref": candidate_ref,
                        "disposition": "verified",
                        "reason": None,
                        "source_read_ref": source_read_ref,
                        "finding": finding,
                        "source_slice": _source_slice(evidence.trace, source_read_ref),
                    },
                )

    if recorder:
        verified_count = len(verified_findings)
        payload = {
            "total_candidates": total_candidates,
            "verified_count": verified_count,
            "rejected_count": total_candidates - verified_count,
            "candidate_to_verified_ratio": (
                total_candidates / verified_count if verified_count else None
            ),
        }
        if is_production:
            payload["cycle"] = cycle
        recorder.record_step(
            "validation",
            payload,
        )

    return {"verified_findings": verified_findings}
