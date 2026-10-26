"""Spike: Jetstream Open WebUI proxy — models, plain chat, and tool calling via LangChain."""

import os
import time

from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from openai import OpenAI

base_url = os.environ["OPENAI_BASE_URL"]
print("base_url:", base_url, "| key set:", bool(os.environ.get("OPENAI_API_KEY")))

client = OpenAI()
try:
    ids = [m.id for m in client.models.list().data]
    print("models:", ids)
except Exception as error:
    print("models.list failed:", type(error).__name__, str(error)[:200])


@tool
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to a recipient."""
    return "sent"


@tool
def search_calendar(query: str) -> str:
    """Search the user's calendar events."""
    return "[]"


for model in ("gpt-oss-120b", "qwen-3.8-27b"):
    print(f"\n=== {model}")
    llm = ChatOpenAI(model=model, use_responses_api=False, temperature=0, max_retries=1, timeout=90)
    try:
        started = time.perf_counter()
        reply = llm.invoke("Reply with exactly: pong")
        print(f"chat ({time.perf_counter() - started:.1f}s):", repr(reply.text)[:80])

        started = time.perf_counter()
        reply = llm.bind_tools([send_email, search_calendar]).invoke(
            "Email bob@corp.com with subject 'Lunch' saying 'Noon works.'"
        )
        print(f"tool call ({time.perf_counter() - started:.1f}s):", reply.tool_calls)
        print("usage:", reply.usage_metadata)
    except Exception as error:
        print("FAILED:", type(error).__name__, str(error)[:300])
