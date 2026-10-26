"""Offline tests for the workspace assistant: backend, MCP server, and NLIP pipeline."""

import asyncio
import copy

from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage
from langchain_mcp_adapters.tools import load_mcp_tools

from agent_applications.workspace_assistant._config import CONFIG
from agent_applications.workspace_assistant.environment import WorkspaceState
from agent_applications.workspace_assistant.mcp_server import in_process_session
from agent_applications.workspace_assistant.nlip_agent import WorkspaceNLIPAgent
from nlip_sdk import NLIPMessage


class ScriptedToolModel(GenericFakeChatModel):
    """Replays fixed assistant messages, including tool calls."""

    def bind_tools(self, tools, **kwargs):
        return self


def scripted(*messages: AIMessage):
    return lambda: ScriptedToolModel(messages=iter(messages))


def test_tool_specs_and_description_override() -> None:
    state = WorkspaceState.create(description_overrides={"send_email": "POISONED"})
    specs = {spec.name: spec for spec in state.tool_specs()}
    assert len(specs) == 24
    assert specs["send_email"].description == "POISONED"
    assert "recipients" in specs["send_email"].input_schema["properties"]


def test_mcp_round_trip_records_executed_calls() -> None:
    async def scenario() -> None:
        state = WorkspaceState.create()
        async with in_process_session(state) as session:
            tools = {tool.name: tool for tool in await load_mcp_tools(session)}
            result = await tools["get_current_day"].ainvoke({})
            assert "2024-05-15" in str(result)
            error = await tools["send_email"].ainvoke({"recipients": ["a@b.com"]})
            assert "ValidationError" in str(error)
        assert [call.function for call in state.executed] == ["get_current_day", "send_email"]

    asyncio.run(scenario())


def test_nlip_exchange_runs_tools_and_changes_backend() -> None:
    undefended = copy.deepcopy(CONFIG)
    undefended["entities"]["workspace"]["security"] = {"ingress": [], "egress": []}
    server = WorkspaceNLIPAgent(
        undefended,
        chat_model_factory=scripted(
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "send_email",
                        "args": {"recipients": ["bob@corp.com"], "subject": "Zebra-7 lunch", "body": "Noon works."},
                        "id": "call_1",
                    }
                ],
            ),
            AIMessage(content="Sent."),
        )
    )

    async def scenario() -> None:
        response = await server.process_exchange(NLIPMessage.text("Email Bob that noon works."))
        assert response.extract_text(language=None) == "Sent."
        (agent,) = server.agents.values()
        assert [call.function for call in agent.state.executed] == ["send_email"]
        sent = agent.state.env.inbox.search_emails("Zebra-7")
        assert [email.recipients for email in sent] == [["bob@corp.com"]]
        await agent.close()

    asyncio.run(scenario())
