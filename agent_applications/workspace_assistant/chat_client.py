"""Interactive NLIP chat with the workspace assistant (start ``nlip_agent`` first).

    python -m agent_applications.workspace_assistant.chat_client
    python -m agent_applications.workspace_assistant.chat_client "What is on my calendar today?"

If the server requires sign-in (``oauth_verify`` in its ingress list), the client signs
in first and attaches the ID token to every request as an NLIP authorization token.
"""

from __future__ import annotations

import asyncio
import sys

import httpx

from nlip_sdk import NLIPClient, NLIPMessage

from ._config import CONFIG
from .login import token_email, token_source
from .nlip_agent import ENTITY_NAME


async def main() -> None:
    client = NLIPClient.from_config(CONFIG, identity="user")
    session = client.create_session(ENTITY_NAME)
    login = token_source(CONFIG)
    if login is not None:
        print(f"Signed in as {token_email(login())}")

    async def ask(prompt: str) -> str:
        message = NLIPMessage.text(prompt)
        if login is not None:
            message.add_authentication_token(login())
        try:
            response = await session.send(message)
        except httpx.HTTPStatusError as error:
            # A security extension's block arrives as HTTP 403 with the reason in "detail".
            try:
                detail = error.response.json().get("detail", error.response.text)
            except ValueError:
                detail = error.response.text
            return f"[HTTP {error.response.status_code}] {detail}"
        return response.extract_text(language=None) or response.to_json()

    prompts = sys.argv[1:]
    if prompts:
        for prompt in prompts:
            print(await ask(prompt))
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
            print(f"Assistant: {await ask(prompt)}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
