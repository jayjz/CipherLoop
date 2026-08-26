import os
from typing import Literal
from langchain_core.messages import SystemMessage, ToolMessage
from langchain_community.chat_models import ChatOllama
from langgraph.prebuilt import ToolNode

from cipherloop.core.state import AuditState
from cipherloop.tools.filesystem import SANDBOX_TOOLS

# Initialize the local Ollama model
LOCAL_MODEL = os.getenv("LOCAL_MODEL_NAME", "hermes3:8b")
OLLAMA_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

local_llm = ChatOllama(
    model=LOCAL_MODEL,
    base_url=OLLAMA_URL,
    temperature=0.1,
    format="json"
).bind_tools(SANDBOX_TOOLS)


def call_local_model(state: AuditState) -> dict:
    """
    The tactical brain. Reads the orchestrator's plan and decides which tool to fire.
    """
    plan = state.get("current_plan", "No active plan.")
    
    system_prompt = SystemMessage(
        content=(
            "You are a tactical security execution agent operating inside an isolated Linux sandbox.\n"
            "Your ONLY purpose is to execute tools to fulfill the current plan.\n"
            "Do not explain your reasoning. Do not generate reports. Just call the appropriate tools.\n\n"
            f"CURRENT PLAN:\n{plan}"
        )
    )
    
    # FIX: Trust the compressor's RemoveMessage logic. The state is already sheared.
    # Passing the whole clean list prevents accidental truncation of the system prompt or plan.
    clean_messages = state.get("messages", [])
    
    response = local_llm.invoke([system_prompt] + clean_messages)
    
    return {"messages": [response]}


# LangGraph's prebuilt ToolNode handles the exact parsing and execution of the bound tools.
execute_sandbox_tools = ToolNode(SANDBOX_TOOLS)


def route_local_execution(state: AuditState) -> Literal["execute_sandbox_tools", "compressor_node"]:
    """
    The micro-loop routing logic.
    """
    last_message = state["messages"][-1]
    
    # If there are tool calls, keep looping in the sandbox
    if hasattr(last_message, "tool_calls") and last_message.tool_calls:
        return "execute_sandbox_tools"
        
    # If the model thinks it's done, kick it to the context compressor
    return "compressor_node"
