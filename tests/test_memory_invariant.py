from langchain_core.messages import AIMessage, ToolMessage
from langgraph.graph import END, START, StateGraph

from cipherloop.core.state import AuditState
from cipherloop.executor.compressor import compressor_node
from cipherloop.executor.validator import validator_node


TOOL_CALLS = 100


def test_messages_remain_bounded_across_repeated_tool_and_validation_cycles():
    """Compression must remove each cycle's transient model and tool messages."""

    def create_tool_messages(state: AuditState) -> dict:
        iteration = state["retries"] + 1
        tool_call_id = f"call-{iteration}"
        return {
            "messages": [
                AIMessage(
                    content="",
                    id=f"assistant-{iteration}",
                    tool_calls=[
                        {
                            "name": "search_code",
                            "args": {"query": "password"},
                            "id": tool_call_id,
                        }
                    ],
                ),
                ToolMessage(
                    content=f"search result {iteration}",
                    name="search_code",
                    tool_call_id=tool_call_id,
                    id=f"tool-{iteration}",
                ),
            ],
            "retries": iteration,
        }

    def route_after_validation(state: AuditState) -> str:
        return "tool_messages" if state["retries"] < TOOL_CALLS else END

    workflow = StateGraph(AuditState)
    workflow.add_node("tool_messages", create_tool_messages)
    workflow.add_node("compressor", lambda state: compressor_node(state, config={}))
    workflow.add_node("validator", lambda state: validator_node(state, config={}))
    workflow.add_edge(START, "tool_messages")
    workflow.add_edge("tool_messages", "compressor")
    workflow.add_edge("compressor", "validator")
    workflow.add_conditional_edges(
        "validator",
        route_after_validation,
        {"tool_messages": "tool_messages", END: END},
    )

    app = workflow.compile()
    initial_state: AuditState = {
        "messages": [],
        "current_plan": "audit",
        "target_directory": "/workspace/target_repo",
        "compressed_findings": [],
        "verified_findings": [],
        "active_tool": "",
        "retries": 0,
    }

    message_counts = [
        len(state["messages"])
        for state in app.stream(
            initial_state,
            config={"recursion_limit": TOOL_CALLS * 4},
            stream_mode="values",
        )
    ]

    assert max(message_counts) <= 2
    assert message_counts[-1] == 0
