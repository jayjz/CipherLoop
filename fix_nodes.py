content = '''import os
from typing import List
from pydantic import BaseModel, Field
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from cipherloop.core.state import AuditState

API_KEY = os.getenv("GEMINI_API_KEY", "")

class TacticalPlan(BaseModel):
    instruction: str = Field(description="The exact next command or search query the local agent should execute. No preamble.")

cloud_llm = ChatGoogleGenerativeAI(
    model="gemini-1.5-pro",
    google_api_key=API_KEY,
    temperature=0.1
).with_structured_output(TacticalPlan)

cloud_llm_synth = ChatGoogleGenerativeAI(
    model="gemini-1.5-pro",
    google_api_key=API_KEY,
    temperature=0.2
)

def planner_node(state: AuditState) -> dict:
    findings = state.get("compressed_findings", [])
    target_dir = state.get("target_directory", "/workspace/target_repo")
    
    findings_str = "\\n".join([f"- {f}" for f in findings]) if findings else "No findings yet. Start with initial reconnaissance."
    
    system_prompt = SystemMessage(content=\"\"\"You are the Cloud Orchestrator for a cybersecurity code audit.
Your job is to generate a SINGLE, highly specific, tactical instruction for the local agent.
Output ONLY the next command or search query the local agent should execute.\"\"\")

    human_prompt = HumanMessage(content=f"Target: {target_dir}\\nRecent Findings:\\n{findings_str}\\n\\nWhat is the next tactical step?")
    
    response = cloud_llm.invoke([system_prompt, human_prompt])
    
    plan_text = response.instruction if hasattr(response, 'instruction') else "AUDIT_COMPLETE"
    
    return {
        "current_plan": plan_text,
        "messages": [AIMessage(content=f"Orchestrator Plan: {plan_text}")],
        "retries": state.get("retries", 0) + 1
    }

def synthesizer_node(state: AuditState) -> dict:
    findings = state.get("compressed_findings", [])
    target_dir = state.get("target_directory", "Unknown Target")
    
    findings_str = "\\n".join([str(f) for f in findings])
    
    system_prompt = SystemMessage(content=\"\"\"You are a senior security researcher writing a final bug bounty report.
Synthesize the provided raw findings into a clean, professional Markdown report.
Include:
1. Executive Summary
2. Critical Findings (with file paths and line numbers)
3. Recommended Remediation\"\"\")

    human_prompt = HumanMessage(content=f"Target: {target_dir}\\n\\nAll Compressed Findings:\\n{findings_str}")
    
    response = cloud_llm_synth.invoke([system_prompt, human_prompt])
    
    return {
        "messages": [AIMessage(content="--- FINAL REPORT ---\\n" + response.content)],
        "current_plan": "AUDIT_COMPLETE"
    }
'''

with open('src/cipherloop/orchestrator/nodes.py', 'w', encoding='utf-8') as f:
    f.write(content)
print('nodes.py overwritten successfully.')
