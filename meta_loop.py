import os
import subprocess
import time
import sys
from google import genai

try:
    client = genai.Client()
except Exception as e:
    print(f"Failed to initialize Gemini Client: {e}")
    sys.exit(1)

from pathlib import Path

SPEC_PATH = Path(".codex/specs/auto-spec.md")
SPEC_PATH.parent.mkdir(parents=True, exist_ok=True)

SYSTEM_PROMPT = """You are the Senior Staff Engineer Architect.
Your job is to write highly specific markdown specs for a junior coding agent (Codex).
When given a goal, write a complete spec. If given terminal output from a previous run, 
evaluate if the tests passed. If they failed, write a new spec to fix the failure.
If they passed and the goal is met, output exactly: 'TASK_COMPLETE'."""

def run_codex_loop(goal: str, max_iterations: int = 5):
    chat = client.chats.create(
        model="gemini-3.6-flash",
        config=dict(system_instruction=SYSTEM_PROMPT)
    )
    
    current_prompt = f"Write a Codex spec to achieve this goal: {goal}"
    
    for i in range(max_iterations):
        print(f"\n?? [Iteration {i+1}] Architect (Gemini) is thinking...")
        
        try:
            response = chat.send_message(current_prompt)
            text_response = response.text
        except Exception as e:
            print(f"API Error: {e}")
            break
            
        if "TASK_COMPLETE" in text_response:
            print("? Architect verified the task is complete.")
            break
            
        print(f"?? Writing spec to {SPEC_PATH}...")
        with open(SPEC_PATH, "w", encoding="utf-8") as f:
            f.write(text_response)
            
        print("?? Invoking local Codex agent in headless mode...")
        # USE 'codex exec' FOR NON-INTERACTIVE SUBPROCESS PIPELINES
        command = f'codex exec -s workspace-write "Execute the spec at {SPEC_PATH}"'
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True
        )
        
        print(result.stdout)
        if result.stderr:
            print(f"Errors: {result.stderr}")
            
        current_prompt = (
            f"Here is the console output from Codex:\n\n{result.stdout}\n\n{result.stderr}\n\n"
            "Did it succeed and pass tests? If yes, output TASK_COMPLETE. If no, write a revised spec to fix the errors."
        )
        time.sleep(2)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python meta_loop.py 'Your high level goal here'")
        sys.exit(1)
        
    run_codex_loop(sys.argv[1])
