"""Interactive NLIP chat with the workspace assistant (start ``nlip_agent`` first).

    python -m agent_applications.workspace_assistant.chat_client
    python -m agent_applications.workspace_assistant.chat_client "What is on my calendar today?"
"""

from __future__ import annotations

import asyncio
import sys

from nlip_sdk import NLIPClient

from ._config import CONFIG
from .nlip_agent import ENTITY_NAME


async def main() -> None:
    client = NLIPClient.from_config(CONFIG, identity="user")
    session = client.create_session(ENTITY_NAME)
    prompts = sys.argv[1:]
    if prompts:
        for prompt in prompts:
            response = await session.send_text(prompt)
            print(response.extract_text(language=None) or response.to_json())
        return

    print("Workspace assistant over NLIP. Type /new for a fresh session, /exit to quit.")
    while True:
        try:
            prompt = input("You: ").strip()
        except EOFError:
            break
        if prompt in {"/exit", "/quit"}:
            break
        if prompt == "/new":
            session = client.create_session(ENTITY_NAME)
            continue
        if prompt:
            response = await session.send_text(prompt)
            print(f"Assistant: {response.extract_text(language=None) or response.to_json()}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
