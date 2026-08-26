from typing import Annotated, TypedDict, List
from langchain_core.messages import BaseMessage
from operator import add

class AuditState(TypedDict):
    """
    The memory hypervisor. This payload passes between the Cloud and Local nodes.
    By strictly typing this, we prevent the context window from bloating with raw stdout.
    """
    messages: Annotated[List[BaseMessage], add]
    current_plan: str
    target_directory: str
    
    # The Compressor prevents context collapse by writing to this field
    compressed_findings: Annotated[List[dict], add]
    
    # State tracking for the local loop
    active_tool: str
    retries: int
