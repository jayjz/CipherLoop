import os
import json
from typing import List
from pydantic import BaseModel, Field
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
from langchain_anthropic import ChatAnthropic
from cipherloop.core.state import AuditState

API_KEY = os.getenv("ANTHROPIC_API_KEY", "sk-test-key")

class TacticalPlan(BaseModel):
    instruction: str = Field(description="The exact next command or search query the local agent should execute. No preamble.")

cloud_llm = ChatAnthropic(
    model="claude-3-5-sonnet-20241022",
    api_key=API_KEY,
    temperature=0.1
).with_structured_output(TacticalPlan)

cloud_llm_synth = ChatAnthropic(
    model="claude-3-5-sonnet-20241022",
    api_key=API_KEY,
    temperature=0.2
)

def planner_node(state: AuditState) -> dict:
    findings = state.get("compressed_findings", [])
    verified = [f for f in state.get("verified_findings", []) if f.get("status") == "VERIFIED"]
    target_dir = state.get("target_directory", "/workspace/target_repo")
    
    findings_str = f"Raw Signals: {len(findings)} batches | Verified Sinks: {len(verified)}"
    if verified:
        findings_str += "\nVerified Findings:\n" + "\n".join([f"- [{v.get('severity')}] {v.get('id')}: {v.get('vulnerability_class')}" for v in verified])

    system_prompt = SystemMessage(content="""You are the Cloud Orchestrator for a cybersecurity code audit.
Your job is to generate a SINGLE, highly specific, tactical instruction for the local agent.
Output ONLY the next command or search query the local agent should execute.""")

    human_prompt = HumanMessage(content=f"Target: {target_dir}\nStatus:\n{findings_str}\n\nWhat is the next tactical step?")
    
    response = cloud_llm.invoke([system_prompt, human_prompt])
    plan_text = response.instruction if hasattr(response, 'instruction') else "AUDIT_COMPLETE"
    
    return {
        "current_plan": plan_text,
        "messages": [AIMessage(content=f"Orchestrator Plan: {plan_text}")],
        "retries": state.get("retries", 0) + 1
    }

def synthesizer_node(state: AuditState) -> dict:
    verified = [f for f in state.get("verified_findings", []) if f.get("status") == "VERIFIED"]
    target_dir = state.get("target_directory", "Unknown Target")
    
    if not verified:
        report = "## Executive Summary\nNo verified high-confidence vulnerabilities were found matching the required evidence threshold."
        return {
            "messages": [AIMessage(content="--- FINAL REPORT ---\n" + report)],
            "current_plan": "AUDIT_COMPLETE"
        }
    
    verified_data = json.dumps(verified, indent=2)
    system_prompt = SystemMessage(content="""You are a senior security researcher writing a verified bug bounty report.
Synthesize ONLY the provided verified findings into a clean Markdown report.
You must reject any hypothesis not present in the verified findings list.
Include:
1. Executive Summary
2. Verified Vulnerabilities (with file paths, exact lines, and code evidence)
3. Remediation Guidance""")

    human_prompt = HumanMessage(content=f"Target: {target_dir}\nVerified Findings:\n{verified_data}")
    response = cloud_llm_synth.invoke([system_prompt, human_prompt])
    
    return {
        "messages": [AIMessage(content="--- FINAL REPORT ---\n" + response.content)],
        "current_plan": "AUDIT_COMPLETE"
    }
