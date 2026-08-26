import json
from typing import Dict, Any, List
from langchain_core.messages import ToolMessage, AIMessage, RemoveMessage

from cipherloop.core.state import AuditState

def process_semgrep_output(raw_json: str) -> dict:
    """
    Deterministically parses Semgrep JSON output.
    Extracts the highest severity findings and throws away the JSON noise.
    """
    try:
        data = json.loads(raw_json)
        results = data.get("results", [])
        
        # Filter out purely informational noise
        critical_findings = [
            r for r in results 
            if r.get("extra", {}).get("severity", "").upper() in ["WARNING", "ERROR"]
        ]
        
        # Sort to ensure ERRORs surface before WARNINGs
        critical_findings.sort(
            key=lambda x: 0 if x.get("extra", {}).get("severity", "").upper() == "ERROR" else 1
        )
        
        # Cap to top 5 findings per run to guarantee context protection
        top_findings = critical_findings[:5]
        
        summaries = []
        for f in top_findings:
            path = f.get("path", "Unknown")
            line = f.get("start", {}).get("line", "?")
            msg = f.get("extra", {}).get("message", "No description")
            sev = f.get("extra", {}).get("severity", "UNKNOWN")
            summaries.append(f"[{sev}] {path}:{line} - {msg}")
            
        return {
            "tool": "run_semgrep",
            "total_findings": len(results),
            "critical_findings_count": len(critical_findings),
            "top_findings": summaries
        }
    except json.JSONDecodeError:
        return {
            "tool": "run_semgrep",
            "error": "Failed to parse JSON. Possible timeout or sandbox crash.",
            "snippet": raw_json[:250]
        }

def process_generic_tool(tool_name: str, raw_output: str) -> dict:
    """
    Handles grep, tree, and sed output deterministically.
    Truncates massive stdout blobs into a strict 15-line preview.
    OPTIMIZED: Uses split with maxsplit to prevent OOM on massive outputs.
    """
    # O(1) memory split: only split the first 15 lines, leave the rest as a single string
    lines = raw_output.split("\n", 15)
    preview = "\n".join(lines[:15])
    
    # If there was a 16th element, it means we hit the maxsplit limit and truncated
    if len(lines) > 15:
        preview += "\n... [TRUNCATED: Output exceeded 15 lines. Refine search query.]"
    else:
        # If we didn't hit the limit, the last element is the remainder of the string, 
        # but we already joined all of it. We can estimate total lines by counting newlines in original.
        total_lines = raw_output.count("\n") + 1
        
    return {
        "tool": tool_name,
        "snippet": preview,
        "truncated": len(lines) > 15
    }

def compressor_node(state: AuditState) -> dict:
    """
    The Memory Hypervisor.
    Intercepts raw tool outputs, structures them into JSON findings, 
    and explicitly shears the local working memory to prevent context collapse.
    """
    messages = state.get("messages", [])
    
    new_findings = []
    messages_to_remove = []
    
    for msg in messages:
        msg_id = getattr(msg, "id", None)
        
        if isinstance(msg, ToolMessage):
            tool_name = getattr(msg, "name", "unknown_tool")
            
            # Resilient tool name matching
            if "semgrep" in tool_name.lower():
                finding = process_semgrep_output(msg.content)
            else:
                finding = process_generic_tool(tool_name, msg.content)
            
            new_findings.append(finding)
            
            # Only queue for removal if a valid ID exists
            if msg_id:
                messages_to_remove.append(RemoveMessage(id=msg_id))
                
        elif isinstance(msg, AIMessage) and getattr(msg, "tool_calls", None):
            # Flag the local agent's tool call requests for deletion to keep state clean
            if msg_id:
                messages_to_remove.append(RemoveMessage(id=msg_id))
                
    return {
        "compressed_findings": new_findings,
        "messages": messages_to_remove
    }
