import os
from typing import Literal
from langchain_core.messages import SystemMessage, ToolMessage
from langchain_community.chat_models import ChatOllama
from langgraph.prebuilt import ToolNode

from cipherloop.core.state import AuditState
from cipherloop.tools.filesystem import SANDBOX_TOOLS

# Initialize the local Ollama model
# We use a low temperature to enforce deterministic tool execution.
LOCAL_MODEL = os.getenv("LOCAL_MODEL_NAME", "hermes3:8b")
OLLAMA_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

local_llm = ChatOllama(
    model=LOCAL_MODEL,
    base_url=OLLAMA_URL,
    temperature=0.1,
    format="json"  # Forces structured output if Hermes gets chatty, though native tool calling usually handles this.
).bind_tools(SANDBOX_TOOLS)


def call_local_model(state: AuditState) -> dict:
    """
    The tactical brain. Reads the orchestrator's plan and decides which tool to fire.
    """
    plan = state.get("current_plan", "No active plan.")
    
    # The system prompt acts as a blinder, forcing the local model to stay tactical.
    system_prompt = SystemMessage(
        content=(
            "You are a tactical security execution agent operating inside an isolated Linux sandbox.\n"
            "Your ONLY purpose is to execute tools to fulfill the current plan.\n"
            "Do not explain your reasoning. Do not generate reports. Just call the appropriate tools.\n\n"
            f"CURRENT PLAN:\n{plan}"
        )
    )
    
    # We only pass the most recent messages to prevent the local context window from collapsing
    # A standard 8B model will choke if you pass the entire audit history.
    recent_messages = state["messages"][-5:] 
    
    response = local_llm.invoke([system_prompt] + recent_messages)
    
    return {"messages": [response]}


# LangGraph's prebuilt ToolNode handles the exact parsing and execution of the bound tools.
# We map it to our SANDBOX_TOOLS which safely route through the Docker SDK.
execute_sandbox_tools = ToolNode(SANDBOX_TOOLS)


def route_local_execution(state: AuditState) -> Literal["execute_sandbox_tools", "compressor_node"]:
    """
    The micro-loop routing logic.
    If the local model called a tool, we route to execution.
    If it returned text (finished the task), we route to the compressor to summarize it.
    """
    last_message = state["messages"][-1]
    
    # If there are tool calls, keep looping in the sandbox
    if hasattr(last_message, "tool_calls") and last_message.tool_calls:
        return "execute_sandbox_tools"
        
    # If the model thinks it's done, kick it to the context compressor
    return "compressor_node"
