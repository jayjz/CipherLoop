"""Opt-in diagnostic for the Ollama tool-binding response shape.

Run from the repository root with the configured Ollama service available:
    .\\.venv\\Scripts\\python.exe scripts\\probe_local_tool_calls.py
"""

from langchain_core.messages import HumanMessage, SystemMessage

from cipherloop.core.llm import get_local_llm
from cipherloop.executor.local_node import LOCAL_TOOLS
from cipherloop.tools.filesystem import WORKDIR


def main() -> None:
    response = get_local_llm(temperature=0.1).bind_tools(LOCAL_TOOLS).invoke(
        [
            SystemMessage(
                content=(
                    "You are a tactical security execution agent. "
                    f"Call list_directory for {WORKDIR}. "
                    "Return only a structured tool call."
                )
            ),
            HumanMessage(content="List the target directory."),
        ]
    )
    print(f"type: {type(response)!r}")
    print(f"content: {response.content!r}")
    print(f"tool_calls: {response.tool_calls!r}")
    print(f"additional_kwargs: {response.additional_kwargs!r}")


if __name__ == "__main__":
    main()
