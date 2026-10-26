"""MCP server exposing the workspace tools.

The agent reaches the tools only through MCP ``tools/list`` and ``tools/call``. The
server runs in-process over memory streams for evaluation (so the backend state can be
scored), or standalone over stdio for use with any MCP client.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from mcp import ClientSession, types
from mcp.server.lowlevel import Server
from mcp.shared.memory import create_connected_server_and_client_session

from .environment import WorkspaceState

SERVER_NAME = "workspace"


def build_server(state: WorkspaceState) -> Server:
    server: Server = Server(SERVER_NAME)

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [
            types.Tool(name=spec.name, description=spec.description, inputSchema=spec.input_schema)
            for spec in state.tool_specs()
        ]

    # Argument validation is left to the AgentDojo runtime so that a malformed call is
    # reported back to the model as a tool error instead of an MCP protocol error.
    @server.call_tool(validate_input=False)
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
        text, error = state.run(name, arguments)
        if error:
            raise RuntimeError(error)
        return [types.TextContent(type="text", text=text)]

    return server


class InProcessMCP:
    """Hold one in-memory MCP client session open in a task that owns its lifetime.

    anyio cancel scopes must be exited by the task that entered them, while NLIP sessions
    start and end in different request tasks, so the session lives in its own task.
    """

    def __init__(self, state: WorkspaceState) -> None:
        self.state = state
        self._ready: asyncio.Future[ClientSession] | None = None
        self._closed = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> ClientSession:
        self._ready = asyncio.get_running_loop().create_future()
        self._task = asyncio.create_task(self._run())
        return await self._ready

    async def _run(self) -> None:
        assert self._ready is not None
        try:
            async with create_connected_server_and_client_session(build_server(self.state)) as session:
                self._ready.set_result(session)
                await self._closed.wait()
        except Exception as error:
            if not self._ready.done():
                self._ready.set_exception(error)
            else:
                raise

    async def close(self) -> None:
        self._closed.set()
        if self._task is not None:
            await self._task


@asynccontextmanager
async def in_process_session(state: WorkspaceState) -> AsyncIterator[ClientSession]:
    mcp = InProcessMCP(state)
    try:
        yield await mcp.start()
    finally:
        await mcp.close()


def main() -> None:
    """Serve the default (benign) workspace over stdio."""
    from mcp.server.stdio import stdio_server

    async def serve() -> None:
        server = build_server(WorkspaceState.create())
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    asyncio.run(serve())


if __name__ == "__main__":
    main()
