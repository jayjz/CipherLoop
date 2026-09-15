from operator import add
from typing import Annotated, Literal, NotRequired, TypedDict

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages


class CodeLocation(TypedDict):
    file: str
    line: int
    symbol: str

class VerifiedFinding(TypedDict):
    id: str
    vulnerability_class: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    source: CodeLocation
    sink: CodeLocation
    taint_path: list[str]
    evidence_snippet: str
    confidence: float
    status: Literal["VERIFIED"]
    rejection_reason: NotRequired[str]

class AuditState(TypedDict):
    """
    The memory hypervisor payload passing between Cloud and Local nodes.
    Separates raw compressed tool signals from strictly verified findings.
    """
    messages: Annotated[list[BaseMessage], add_messages]
    current_plan: str
    target_directory: str
    # The user objective and host target are distinct from tactical container state.
    requested_plan: NotRequired[str]
    plan_history: Annotated[list[str], add]
    terminal_error: NotRequired[str]
    
    # Raw compressed signals from semgrep/rg
    compressed_findings: Annotated[list[dict], add]
    
    # Strictly validated findings that met the evidence threshold
    verified_findings: Annotated[list[VerifiedFinding], add]
    
    active_tool: str
    retries: int
