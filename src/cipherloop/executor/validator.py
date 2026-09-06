import ast
from dataclasses import dataclass
from typing import Optional

from cipherloop.core.state import AuditState, CodeLocation, VerifiedFinding
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


def _dotted_name(node: ast.AST) -> Optional[str]:
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

    def __init__(self, target_file: str, expected_sink_line: Optional[int]) -> None:
        self.target_file = target_file
        self.expected_sink_line = expected_sink_line
        self.bindings: dict[str, tuple[CodeLocation, list[str]]] = {}
        self.traces: list[TaintTrace] = []

    def _location(self, node: ast.AST, symbol: str) -> CodeLocation:
        return {"file": self.target_file, "line": node.lineno, "symbol": symbol}

    def _source_trace(self, node: ast.AST) -> Optional[tuple[CodeLocation, list[str]]]:
        symbol: Optional[str] = None
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
    ) -> Optional[tuple[CodeLocation, list[str]]]:
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
        self, target: ast.AST, taint: Optional[tuple[CodeLocation, list[str]]]
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
    source_code: str, target_file: str, expected_sink_line: Optional[int] = None
) -> Optional[TaintTrace]:
    """Return an AST-backed source-to-sink trace, or ``None`` when none exists."""
    try:
        tree = ast.parse(source_code, filename=target_file)
    except SyntaxError:
        return None

    analyzer = _TaintAnalyzer(target_file, expected_sink_line)
    analyzer.visit(tree)
    return analyzer.traces[0] if analyzer.traces else None


def verify_finding_evidence(target_file: str, line_num: int) -> Optional[TaintTrace]:
    """Read the sandboxed target and verify the reported sink with an AST trace."""
    try:
        source_code = read_file.invoke(
            {"filepath": target_file, "start_line": 1, "end_line": 1_000_000}
        )
    except Exception:
        return None

    if "Tool Execution Error" in source_code or "System Error" in source_code:
        return None
    return find_taint_trace(source_code, target_file, expected_sink_line=line_num)


def _parse_summary(summary: str) -> Optional[tuple[str, str, int, str]]:
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


def validator_node(state: AuditState, config: dict) -> dict:
    """Promote only AST-proven untrusted-source to dangerous-sink data flows."""
    verified_findings: list[VerifiedFinding] = []
    compressed = state.get("compressed_findings", [])
    recorder = config.get("configurable", {}).get("__trajectory_recorder__")

    for item in compressed:
        for summary in item.get("top_findings", []):
            parsed = _parse_summary(summary)
            if parsed is None:
                continue
            severity, path, line_num, description = parsed
            trace = verify_finding_evidence(path, line_num)
            if trace is None:
                continue

            verified_findings.append(
                {
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
            )

    if recorder:
        recorder.record_step(
            "validation",
            {
                "total_candidates": len(compressed),
                "verified_count": len(verified_findings),
                "rejected_count": len(compressed) - len(verified_findings),
            },
        )

    return {"verified_findings": verified_findings}
