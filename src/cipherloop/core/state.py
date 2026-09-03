from typing import Annotated, TypedDict, List, Literal, Optional
from langchain_core.messages import BaseMessage
from operator import add

class CodeLocation(TypedDict, total=False):
    file: str
    line: int
    symbol: str

class VerifiedFinding(TypedDict, total=False):
    id: str
    vulnerability_class: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    source: CodeLocation
    sink: CodeLocation
    taint_path: List[str]
    evidence_snippet: str
    confidence: float
    status: Literal["HYPOTHESIS", "SUSPECTED", "VERIFIED", "REJECTED"]
    rejection_reason: Optional[str]

class AuditState(TypedDict):
    """
    The memory hypervisor payload passing between Cloud and Local nodes.
    Separates raw compressed tool signals from strictly verified findings.
    """
    messages: Annotated[List[BaseMessage], add]
    current_plan: str
    target_directory: str
    
    # Raw compressed signals from semgrep/rg
    compressed_findings: Annotated[List[dict], add]
    
    # Strictly validated findings that met the evidence threshold
    verified_findings: Annotated[List[VerifiedFinding], add]
    
    active_tool: str
    retries: int
