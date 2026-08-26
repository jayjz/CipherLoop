from typing import Literal
from langgraph.graph import StateGraph, END
from cipherloop.core.state import AuditState

# Import nodes
from cipherloop.orchestrator.nodes import planner_node, synthesizer_node
from cipherloop.executor.local_node import call_local_model, execute_sandbox_tools, route_local_execution
from cipherloop.executor.compressor import compressor_node

def build_graph():
    """
    Compiles the CipherLoop LangGraph.
    Topology: Planner -> Local Model <-> Sandbox Tools -> Compressor -> (Planner OR Synthesizer)
    """
    workflow = StateGraph(AuditState)

    # 1. Add Nodes
    workflow.add_node("planner", planner_node)
    workflow.add_node("local_model", call_local_model)
    workflow.add_node("sandbox_tools", execute_sandbox_tools)
    workflow.add_node("compressor", compressor_node)
    workflow.add_node("synthesizer", synthesizer_node)

    # 2. Define Edges
    # Entry point
    workflow.set_entry_point("planner")

    # Planner always goes to local model to execute the first step
    workflow.add_edge("planner", "local_model")

    # Conditional routing for the local tactical loop
    workflow.add_conditional_edges(
        "local_model",
        route_local_execution,
        {
            "execute_sandbox_tools": "sandbox_tools",
            "compressor_node": "compressor"
        }
    )

    # Sandbox tools always return to the local model to decide the next step
    workflow.add_edge("sandbox_tools", "local_model")

    # Conditional routing after compression: Is the plan complete or do we need more tactical loops?
    def route_after_compression(state: AuditState) -> Literal["planner", "synthesizer"]:
        # Simple heuristic: if retries > 3, force synthesis to prevent infinite loops
        if state.get("retries", 0) >= 3:
            return "synthesizer"
        # If the current plan is marked as complete or empty, synthesize
        plan = state.get("current_plan", "").lower()
        if "complete" in plan or not plan:
            return "synthesizer"
        return "planner"

    workflow.add_conditional_edges(
        "compressor",
        route_after_compression,
        {
            "planner": "planner",
            "synthesizer": "synthesizer"
        }
    )

    # Synthesizer is the terminal node
    workflow.add_edge("synthesizer", END)

    return workflow.compile()
