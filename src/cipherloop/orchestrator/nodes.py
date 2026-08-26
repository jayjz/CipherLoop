import os
from typing import List
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
from langchain_anthropic import ChatAnthropic
from cipherloop.core.state import AuditState

# Initialize Cloud LLM (Claude 3.5 Sonnet)
API_KEY = os.getenv("ANTHROPIC_API_KEY", "sk-test-key")
cloud_llm = ChatAnthropic(
    model="claude-3-5-sonnet-20241022",
    api_key=API_KEY,
    temperature=0.2
)

def planner_node(state: AuditState) -> dict:
    """
    Reads compressed findings and generates the next highly specific tactical plan.
    """
    findings = state.get("compressed_findings", [])
    target_dir = state.get("target_directory", "/workspace/target_repo")
    
    # Format findings for the LLM
    findings_str = "\n".join([f"- {f}" for f in findings]) if findings else "No findings yet. Start with initial reconnaissance."
    
    system_prompt = SystemMessage(content="""You are the Cloud Orchestrator for a cybersecurity code audit.
Your job is to generate a SINGLE, highly specific, tactical instruction for the local agent.
Do NOT write code. Do NOT summarize. 
Output ONLY the next command or search query the local agent should execute.
Examples:
- "Run run_semgrep on the /src/auth directory"
- "Use search_code to find all instances of 'eval(' in .py files"
- "Use read_file to inspect lines 10-50 of config.py"
Keep it under 50 words.""")

    human_prompt = HumanMessage(content=f"Target: {target_dir}\nRecent Findings:\n{findings_str}\n\nWhat is the next tactical step?")
    
    response = cloud_llm.invoke([system_prompt, human_prompt])
    
    return {
        "current_plan": response.content,
        "messages": [AIMessage(content=f"Orchestrator Plan: {response.content}")],
        "retries": state.get("retries", 0) + 1
    }

def synthesizer_node(state: AuditState) -> dict:
    """
    Aggregates all compressed findings into a final, professional vulnerability report.
    """
    findings = state.get("compressed_findings", [])
    target_dir = state.get("target_directory", "Unknown Target")
    
    findings_str = "\n".join([str(f) for f in findings])
    
    system_prompt = SystemMessage(content="""You are a senior security researcher writing a final bug bounty report.
Synthesize the provided raw findings into a clean, professional Markdown report.
Include:
1. Executive Summary
2. Critical Findings (with file paths and line numbers)
3. Recommended Remediation
Do not hallucinate findings. Only use the provided data.""")

    human_prompt = HumanMessage(content=f"Target: {target_dir}\n\nAll Compressed Findings:\n{findings_str}")
    
    response = cloud_llm.invoke([system_prompt, human_prompt])
    
    return {
        "messages": [AIMessage(content="--- FINAL REPORT ---\n" + response.content)],
        "current_plan": "AUDIT_COMPLETE"
    }
