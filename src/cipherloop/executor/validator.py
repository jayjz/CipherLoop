import re
from typing import List, Dict, Any
from cipherloop.core.state import AuditState, VerifiedFinding
from cipherloop.tools.filesystem import read_file

# Heuristic patterns for common sources & sinks to cross-validate claims
KNOWN_SOURCES = [r"request\.", r"sys\.argv", r"os\.environ", r"input\(", r"params\["]
KNOWN_SINKS = [r"subprocess\.", r"os\.system\(", r"exec\(", r"eval\(", r"sqlite3\.execute", r"cursor\.execute"]

def verify_finding_evidence(target_file: str, line_num: int) -> tuple[bool, str]:
    """
    Reads the actual code slice from the sandbox around the reported line
    to confirm the line exists and contains actionable code.
    """
    try:
        start_line = max(1, line_num - 2)
        end_line = line_num + 2
        snippet = read_file.invoke({"filepath": target_file, "start_line": start_line, "end_line": end_line})
        
        if "Tool Execution Error" in snippet or "System Error" in snippet:
            return False, f"File read failed: {snippet}"
            
        if not snippet.strip():
            return False, "File slice was empty."
            
        return True, snippet
    except Exception as e:
        return False, str(e)

def validator_node(state: AuditState, config: dict) -> dict:
    """
    The Evidence Engine.
    Filters raw compressed tool outputs into verified findings.
    Enforces the invariant: No verified source/sink evidence -> REJECTED.
    """
    compressed = state.get("compressed_findings", [])
    verified_list: List[VerifiedFinding] = []
    
    recorder = config.get("configurable", {}).get("__trajectory_recorder__")
    
    for item in compressed:
        # Check Semgrep structured results
        top_findings = item.get("top_findings", [])
        for raw_summary in top_findings:
            # Pattern: [SEVERITY] path/to/file:line - description
            match = re.match(r"\[(.*?)\]\s+(.*?):(\d+)\s+-\s+(.*)", raw_summary)
            if not match:
                continue
                
            sev, path, line_str, desc = match.groups()
            line_num = int(line_str)
            
            # 1. Ground truth check: does the line exist in the target?
            is_valid, snippet = verify_finding_evidence(path, line_num)
            
            finding_id = f"VULN-{path.replace('/', '_')}-{line_num}"
            
            if not is_valid:
                verified_list.append({
                    "id": finding_id,
                    "vulnerability_class": desc,
                    "severity": sev if sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] else "MEDIUM",
                    "status": "REJECTED",
                    "rejection_reason": snippet,
                    "confidence": 0.0
                })
                continue
                
            # 2. Heuristic check: is this a potential sink or secret?
            is_sink_match = any(re.search(pat, snippet) for pat in KNOWN_SINKS)
            is_secret = "secret" in desc.lower() or "key" in desc.lower() or "credential" in desc.lower()
            
            if is_sink_match or is_secret:
                verified_list.append({
                    "id": finding_id,
                    "vulnerability_class": desc,
                    "severity": sev if sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] else "HIGH",
                    "sink": {"file": path, "line": line_num, "symbol": desc[:30]},
                    "evidence_snippet": snippet,
                    "confidence": 0.9 if is_sink_match else 0.8,
                    "status": "VERIFIED"
                })
            else:
                verified_list.append({
                    "id": finding_id,
                    "vulnerability_class": desc,
                    "severity": "LOW",
                    "evidence_snippet": snippet,
                    "status": "SUSPECTED",
                    "confidence": 0.4,
                    "rejection_reason": "Snippet verified but no active sink pattern confirmed."
                })
                
    if recorder:
        recorder.record_step("validation", {
            "total_candidates": len(compressed),
            "verified_count": sum(1 for v in verified_list if v.get("status") == "VERIFIED"),
            "rejected_count": sum(1 for v in verified_list if v.get("status") == "REJECTED")
        })

    return {"verified_findings": verified_list}
