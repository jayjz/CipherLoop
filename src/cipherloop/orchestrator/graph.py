from typing import Literal
from langgraph.graph import StateGraph, END
from cipherloop.core.state import AuditState

from cipherloop.orchestrator.nodes import planner_node, synthesizer_node
from cipherloop.executor.local_node import call_local_model, execute_sandbox_tools, route_local_execution
from cipherloop.executor.compressor import compressor_node
from cipherloop.executor.validator import validator_node

def build_graph():
    workflow = StateGraph(AuditState)

    workflow.add_node("planner", planner_node)
    workflow.add_node("local_model", call_local_model)
    workflow.add_node("sandbox_tools", execute_sandbox_tools)
    workflow.add_node("compressor", compressor_node)
    workflow.add_node("validator", validator_node)
    workflow.add_node("synthesizer", synthesizer_node)

    workflow.set_entry_point("planner")
    workflow.add_edge("planner", "local_model")

    workflow.add_conditional_edges(
        "local_model",
        route_local_execution,
        {
            "execute_sandbox_tools": "sandbox_tools",
            "compressor_node": "compressor"
        }
    )

    workflow.add_edge("sandbox_tools", "local_model")
    workflow.add_edge("compressor", "validator")

    def route_after_validation(state: AuditState) -> Literal["planner", "synthesizer"]:
        if state.get("retries", 0) >= 25:
            return "synthesizer"
        
        plan = state.get("current_plan", "").lower()
        if "complete" in plan or not plan:
            return "synthesizer"
        return "planner"

    workflow.add_conditional_edges(
        "validator",
        route_after_validation,
        {
            "planner": "planner",
            "synthesizer": "synthesizer"
        }
    )

    workflow.add_edge("synthesizer", END)
    return workflow.compile()
