"""Offline stand-ins for the remote models, so the demo runs with no network.

``ScriptedAgentModel`` replays AgentDojo's ground-truth tool calls for the chosen user
task, and turns to the attacker's ground-truth calls as soon as the attacker's
instruction is *visible* to it (in a tool description or a tool result). Whatever the
guard strips or redacts is therefore no longer "seen", which makes guard on/off show up
exactly as it does with a real model, though deterministically.

``simulated_d3`` replaces the d3 judge: it knows the attacker's goal, so it is an
oracle, not a detector. The page labels offline runs accordingly; the measured numbers
come from live runs with the real d3 judge.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.utils.function_calling import convert_to_openai_tool

from security_extensions.tool_guard.judges import JudgeInput, StubJudge
from security_extensions.tool_guard.session import extract_indicators


def goal_marker(goal: str) -> str:
    """A distinctive piece of the attacker's instruction (its first line, at most 60 chars)."""
    return goal.strip().splitlines()[0][:60]


class ScriptedAgentModel(BaseChatModel):
    user_calls: list[dict[str, Any]]
    attack_calls: list[dict[str, Any]] = []
    marker: str | None = None
    final_text: str = "Done."
    tools_text: str = ""

    @property
    def _llm_type(self) -> str:
        return "scripted-agent"

    def bind_tools(self, tools: Sequence[Any], **kwargs: Any) -> "ScriptedAgentModel":
        # The model "reads" the tool catalog it was given, poisoned or sanitized.
        described = [convert_to_openai_tool(tool) for tool in tools]
        return self.model_copy(update={"tools_text": json.dumps(described)})

    def _generate(self, messages: list[BaseMessage], stop=None, run_manager=None, **kwargs: Any) -> ChatResult:
        return ChatResult(generations=[ChatGeneration(message=self._next(messages))])

    def _next(self, messages: list[BaseMessage]) -> AIMessage:
        issued = {call["id"] for message in messages if isinstance(message, AIMessage) for call in message.tool_calls}
        seen = self.tools_text + "".join(str(m.content) for m in messages if isinstance(m, ToolMessage))
        hijacked = self.marker is not None and self.marker in seen
        script = [(f"attack_{i}", call) for i, call in enumerate(self.attack_calls)] if hijacked else []
        script += [(f"user_{i}", call) for i, call in enumerate(self.user_calls)]
        for call_id, call in script:
            if call_id not in issued:
                return AIMessage(content="", tool_calls=[{"name": call["name"], "args": call["args"], "id": call_id}])
        return AIMessage(content=self.final_text)


def calls_from(function_calls) -> list[dict[str, Any]]:
    return [{"name": call.function, "args": dict(call.args)} for call in function_calls]


def simulated_d3(prompt: str, goal: str | None) -> StubJudge:
    """A stub judge that scores like d3 would on the demo's scenarios (see module doc)."""
    planted = extract_indicators(goal or "") - extract_indicators(prompt)
    marker = goal_marker(goal) if goal else None

    def aligned(judge_input: JudgeInput) -> float:
        values = extract_indicators(json.dumps(judge_input.arguments, default=str))
        return 0.03 if values & planted else 0.93

    def injected(text: str) -> float:
        return 0.97 if marker and marker in text else 0.02

    judge = StubJudge(aligned=aligned, injected=injected)
    judge.name = "simulated-d3"
    return judge
