"""Workspace assistant exposed as an NLIP server (ECMA-430 over ECMA-431 HTTP)."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from langchain.agents.middleware import AgentMiddleware
from langchain_core.language_models import BaseChatModel
from nlip_sdk import NLIPMessage, NLIPServer, NLIPSession
from nlip_sdk.nlip_security_extensions import SecurityExtensionManager
from security_extensions.tool_guard import clear_guard, get_guard
from security_extensions.tool_guard.langchain_middleware import ToolGuardMiddleware, guard_tool_catalog

from ._config import CONFIG
from .agent import WorkspaceAgent
from .environment import WorkspaceState
from .mcp_server import SERVER_NAME

ENTITY_NAME = "workspace"


class WorkspaceNLIPAgent(NLIPServer):
    """Each inbound NLIP session owns one workspace backend and one agent.

    ``state_factory`` lets an evaluation seed each new session with injected content;
    by default every session gets the benign seeded workspace.
    """

    def __init__(
        self,
        config: Mapping[str, Any] | None = None,
        *,
        state_factory: Callable[[], WorkspaceState] = WorkspaceState.create,
        model: str | None = None,
        chat_model_factory: Callable[[], BaseChatModel] | None = None,
        extra_middleware: Callable[[], Sequence[AgentMiddleware]] | None = None,
    ) -> None:
        config = config or CONFIG
        clear_guard(ENTITY_NAME)
        security = SecurityExtensionManager.from_config(config, entity=ENTITY_NAME)
        super().__init__(ENTITY_NAME, security=security)
        # Set only if config.toml enables a tool_guard extension with instance "workspace".
        self.guard = get_guard(ENTITY_NAME)
        self._state_factory = state_factory
        self._model = model
        self._chat_model_factory = chat_model_factory
        # Installed inside the guard's middleware (e.g. the demo's observe-only tool logger).
        self._extra_middleware = extra_middleware
        self.agents: dict[str, WorkspaceAgent] = {}

    async def session_started(self, server_session: NLIPSession) -> None:
        chat_model = self._chat_model_factory() if self._chat_model_factory else None
        # The NLIP framework cannot see tool calls, so a tool guard enabled in
        # config.toml is connected to the agent's own tool hook here.
        guard = self.guard
        middleware = [ToolGuardMiddleware(guard, server_session.id, SERVER_NAME)] if guard else []
        if self._extra_middleware is not None:
            middleware += list(self._extra_middleware())
        tool_filter = None
        if guard is not None and guard.catalog is not None:

            async def tool_filter(tools):
                return await guard_tool_catalog(guard, server_session.id, SERVER_NAME, tools)

        agent = WorkspaceAgent(
            self._state_factory(),
            model=self._model,
            chat_model=chat_model,
            middleware=middleware,
            tool_filter=tool_filter,
        )
        await agent.start()
        self.agents[server_session.id] = agent

    async def session_ended(self, server_session: NLIPSession) -> None:
        agent = self.agents.pop(server_session.id, None)
        if agent is not None:
            await agent.close()
        if self.guard is not None:
            self.guard.sessions.drop(server_session.id)

    async def handle(self, message: NLIPMessage, server_session: NLIPSession) -> NLIPMessage:
        text = message.extract_text(language=None)
        if text is None:
            return NLIPMessage.text("The workspace assistant accepts NLIP text messages.")
        agent = self.agents.get(server_session.id)
        if agent is None:
            raise RuntimeError("Workspace session has not started.")
        return NLIPMessage.text(await agent.chat(text))


def create_app():
    return WorkspaceNLIPAgent().create_nlip_app()


def main() -> None:
    import uvicorn

    settings = CONFIG["entities"][ENTITY_NAME]
    uvicorn.run(create_app(), host=settings["host"], port=settings["port"])


if __name__ == "__main__":
    main()
