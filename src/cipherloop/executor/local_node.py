from typing import Literal
from langchain_core.messages import SystemMessage
from langgraph.prebuilt import ToolNode

from cipherloop.core.state import AuditState
from cipherloop.tools.filesystem import SANDBOX_TOOLS
from cipherloop.core.llm import get_local_llm

local_llm = get_local_llm(temperature=0.1).bind_tools(SANDBOX_TOOLS)

def call_local_model(state: AuditState) -> dict:
    plan = state.get("current_plan", "No active plan.")
    
    system_prompt = SystemMessage(
        content=(
            "You are a tactical security execution agent operating inside an isolated Linux sandbox.\n"
            "Your ONLY purpose is to execute tools to fulfill the current plan.\n"
            "Do not explain your reasoning. Do not generate reports. Just call the appropriate tools.\n\n"
            f"CURRENT PLAN:\n{plan}"
        )
    )
    
    clean_messages = state.get("messages", [])
    response = local_llm.invoke([system_prompt] + clean_messages)
    
    return {"messages": [response]}

execute_sandbox_tools = ToolNode(SANDBOX_TOOLS)

def route_local_execution(state: AuditState) -> Literal["execute_sandbox_tools", "compressor_node"]:
    last_message = state["messages"][-1]
    if hasattr(last_message, "tool_calls") and last_message.tool_calls:
        return "execute_sandbox_tools"
    return "compressor_node"
