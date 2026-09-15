import json

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from pydantic import BaseModel, Field

from cipherloop.core.llm import get_cloud_llm
from cipherloop.core.state import AuditState
from cipherloop.tools.filesystem import WORKDIR

MAX_IDENTICAL_PLAN_ATTEMPTS = 3


class TacticalPlan(BaseModel):
    instruction: str = Field(description="The exact next command or search query the local agent should execute. No preamble.")


def normalize_plan_instruction(instruction: str) -> str:
    """Normalize planner text solely for deterministic non-progress detection."""
    return " ".join(instruction.strip().casefold().split())

def planner_node(state: AuditState) -> dict:
    findings = state.get("compressed_findings", [])
    verified = [f for f in state.get("verified_findings", []) if f.get("status") == "VERIFIED"]
    requested_plan = state.get("requested_plan", state.get("current_plan", ""))
    host_target = state.get("target_directory", "")
    if host_target:
        requested_plan = requested_plan.replace(host_target, WORKDIR)
    
    findings_str = f"Raw Signals: {len(findings)} batches | Verified Sinks: {len(verified)}"
    if verified:
        findings_str += "\nVerified Findings:\n" + "\n".join([f"- [{v.get('severity')}] {v.get('id')}: {v.get('vulnerability_class')}" for v in verified])

    system_prompt = SystemMessage(content=f"""You are the Cloud Orchestrator for a cybersecurity code audit.
Your job is to generate a SINGLE, highly specific, tactical instruction for the local agent.
Tactical execution occurs inside an isolated Linux container, not on the host.
Use POSIX paths only. The only target root is {WORKDIR}.
Do not emit PowerShell commands, cmd.exe commands, or drive-letter paths.
Prefer the available structured tools (list_directory, read_file, search_code, run_semgrep)
over shell syntax. Output ONLY the next tactical instruction.""")

    human_prompt = HumanMessage(
        content=(
            f"Audit objective: {requested_plan}\n"
            f"Tactical target root: {WORKDIR}\n"
            f"Status:\n{findings_str}\n\nWhat is the next tactical step?"
        )
    )
    
    cloud_llm = get_cloud_llm(temperature=0.1).with_structured_output(TacticalPlan)
    response = cloud_llm.invoke([system_prompt, human_prompt])
    plan_text = response.instruction if hasattr(response, "instruction") else "AUDIT_COMPLETE"
    normalized_plan = normalize_plan_instruction(plan_text)
    prior_attempts = state.get("plan_history", []).count(normalized_plan)
    if normalized_plan and prior_attempts >= MAX_IDENTICAL_PLAN_ATTEMPTS:
        error = (
            "Repeated tactical plan limit reached: "
            f"{MAX_IDENTICAL_PLAN_ATTEMPTS} identical normalized instructions."
        )
        return {
            "current_plan": "AUDIT_COMPLETE",
            "terminal_error": error,
            "messages": [AIMessage(content=f"Orchestrator stopped: {error}")],
            "retries": state.get("retries", 0) + 1,
        }
    
    return {
        "current_plan": plan_text,
        "plan_history": [normalized_plan],
        "messages": [AIMessage(content=f"Orchestrator Plan: {plan_text}")],
        "retries": state.get("retries", 0) + 1
    }

def synthesizer_node(state: AuditState) -> dict:
    verified = [f for f in state.get("verified_findings", []) if f.get("status") == "VERIFIED"]
    target_dir = state.get("target_directory", "Unknown Target")
    
    terminal_error = state.get("terminal_error")
    if terminal_error:
        report = (
            "## Audit Incomplete\n"
            f"Tactical execution stopped before completion: {terminal_error}"
        )
        return {
            "messages": [AIMessage(content="--- FINAL REPORT ---\n" + report)],
            "current_plan": "AUDIT_COMPLETE",
        }

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
    cloud_llm_synth = get_cloud_llm(temperature=0.2)
    response = cloud_llm_synth.invoke([system_prompt, human_prompt])
    
    return {
        "messages": [AIMessage(content="--- FINAL REPORT ---\n" + response.content)],
        "current_plan": "AUDIT_COMPLETE"
    }
