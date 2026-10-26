"""LangChain v1 adapter: call the tool guard immediately before and after each tool call."""

from __future__ import annotations

from typing import Any

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import ToolMessage
from langchain_core.tools import BaseTool

from .events import ToolAction, ToolCallEvent, ToolResultEvent
from .guard import ToolGuard


class ToolGuardMiddleware(AgentMiddleware):
    """Bound to one NLIP session, so the guard can match calls to that user's task."""

    def __init__(self, guard: ToolGuard, session_id: str, server_id: str) -> None:
        super().__init__()
        self.guard = guard
        self.session_id = session_id
        self.server_id = server_id

    def wrap_tool_call(self, request, handler):
        # The guard's judges are async; refusing here keeps a sync caller from
        # silently bypassing it.
        raise RuntimeError("ToolGuardMiddleware requires the async agent API (ainvoke).")

    async def awrap_tool_call(self, request, handler):
        call = request.tool_call
        verdict = await self.guard.before_tool_call(
            ToolCallEvent(self.session_id, self.server_id, call["name"], call.get("args"), call.get("id"))
        )
        if verdict.action is ToolAction.BLOCK:
            # tools/call is never sent; the model is told why and asked to carry on.
            return ToolMessage(
                content=(
                    f"Blocked by security policy: {verdict.reason}. This action was not performed. "
                    "Do not retry it; continue with the user's original request."
                ),
                tool_call_id=call["id"],
                name=call["name"],
                status="error",
            )

        result = await handler(request)
        if not isinstance(result, ToolMessage):
            return result
        inspected = await self.guard.after_tool_call(
            ToolResultEvent(
                self.session_id, self.server_id, call["name"], call.get("args"), _text(result.content), call.get("id")
            )
        )
        if inspected.action is ToolAction.REPLACE and inspected.replacement is not None:
            return result.model_copy(update={"content": inspected.replacement})
        return result


async def guard_tool_catalog(
    guard: ToolGuard, session_id: str, server_id: str, tools: list[BaseTool]
) -> list[BaseTool]:
    """Apply the guard's catalog check to tools loaded from an MCP server."""
    allowed = await guard.inspect_catalog(session_id, server_id, [(tool.name, tool.description) for tool in tools])
    return [
        tool if allowed[tool.name] == tool.description else tool.model_copy(update={"description": allowed[tool.name]})
        for tool in tools
        if allowed.get(tool.name) is not None
    ]


def _text(content: Any) -> str:
    """ToolMessage content is a string or a list of content blocks (MCP adapters)."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            block.get("text", "") if isinstance(block, dict) else str(block) for block in content
        )
    return str(content)
