import json
from langchain_core.messages import ToolMessage, AIMessage, RemoveMessage
from cipherloop.core.state import AuditState

def process_semgrep_output(raw_json: str) -> dict:
    try:
        data = json.loads(raw_json)
        results = data.get("results", [])
        critical_findings = [r for r in results if r.get("extra", {}).get("severity", "").upper() in ["WARNING", "ERROR"]]
        critical_findings.sort(key=lambda x: 0 if x.get("extra", {}).get("severity", "").upper() == "ERROR" else 1)
        top_findings = critical_findings[:5]
        
        summaries = [f"[{f.get('extra', {}).get('severity', 'UNKNOWN')}] {f.get('path', 'Unknown')}:{f.get('start', {}).get('line', '?')} - {f.get('extra', {}).get('message', 'No description')}" for f in top_findings]
            
        return {
            "tool": "run_semgrep",
            "total_findings": len(results),
            "critical_findings_count": len(critical_findings),
            "top_findings": summaries,
            "summary_note": f"Found {len(results)} total issues. Showing top 5 critical." if len(results) > 5 else ""
        }
    except json.JSONDecodeError:
        return {"tool": "run_semgrep", "error": "Failed to parse JSON.", "snippet": raw_json[:250]}

def process_generic_tool(tool_name: str, raw_output: str) -> dict:
    # FIX: Hard character limit to prevent minified file context bombs
    if len(raw_output) > 3000:
        preview = raw_output[:3000] + "\n... [TRUNCATED: Output exceeded 3000 characters. Refine search.]"
        return {"tool": tool_name, "snippet": preview, "truncated": True}

    lines = raw_output.split("\n", 15)
    preview = "\n".join(lines[:15])
    if len(lines) > 15:
        preview += "\n... [TRUNCATED: Output exceeded 15 lines. Refine search query.]"
        
    return {"tool": tool_name, "snippet": preview, "truncated": len(lines) > 15}

def compressor_node(state: AuditState, config: dict) -> dict:
    messages = state.get("messages", [])
    recorder = config.get("configurable", {}).get("__trajectory_recorder__")
    
    new_findings = []
    messages_to_remove = []
    
    for msg in messages:
        msg_id = getattr(msg, "id", None)
        
        if isinstance(msg, ToolMessage):
            if recorder: recorder.record_message(msg, role="tool")
                
            tool_name = getattr(msg, "name", "unknown_tool")
            finding = process_semgrep_output(msg.content) if "semgrep" in tool_name.lower() else process_generic_tool(tool_name, msg.content)
            new_findings.append(finding)
            if msg_id: messages_to_remove.append(RemoveMessage(id=msg_id))
                
        elif isinstance(msg, AIMessage) and getattr(msg, "tool_calls", None):
            if recorder: recorder.record_message(msg, role="assistant")
            if msg_id: messages_to_remove.append(RemoveMessage(id=msg_id))
                
    return {"compressed_findings": new_findings, "messages": messages_to_remove}
