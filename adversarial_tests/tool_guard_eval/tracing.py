"""Full episode traces (``run_evaluation --trace``): what the model saw, said, and called,
each tool's raw result before the guard touched it, and every question the guard asked
d3 with its answer. ``export_explorer.py`` turns these into Invariant Explorer traces.

Nothing here changes behavior: the tracer observes through inner middleware (model
responses, raw tool results) and by wrapping the judge instance's methods. With
``on_event`` set, each observation is also reported as it happens (the web demo streams
them live).
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import Any

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

TEXT_LIMIT = 4000


class EpisodeTracer:
    def __init__(self, on_event: Callable[[dict[str, Any]], None] | None = None) -> None:
        self.raw_results: list[dict[str, Any]] = []
        self.judge_calls: list[dict[str, Any]] = []
        self.model_responses: list[dict[str, Any]] = []
        self.on_event = on_event

    def middleware(self) -> list[AgentMiddleware]:
        return [_ModelRecorder(self), _RawResultRecorder(self.raw_results)]

    def model_middleware(self) -> list[AgentMiddleware]:
        return [_ModelRecorder(self)]

    def _report(self, event: dict[str, Any]) -> None:
        if self.on_event is not None:
            self.on_event(event)

    def watch_judge(self, judge) -> None:
        """Record every alignment question and injection check sent to the judge."""
        if judge is None:
            return
        ask_alignment, ask_injection = judge.judge, judge.detect_injection
        calls = self.judge_calls

        async def judge_call(judge_input):
            result = await ask_alignment(judge_input)
            call = {"kind": "alignment", "ts": time.time(), "tool": judge_input.tool_name, "input": json.loads(judge_input.state()),
                    "p_aligned": result.p_aligned, "reason": result.reason}
            calls.append(call)
            self._report(call)
            return result

        async def injection_call(texts, *args, **kwargs):
            scores, tokens = await ask_injection(texts, *args, **kwargs)
            call = {"kind": "injection", "ts": time.time(), "texts": [text[:TEXT_LIMIT] for text in texts], "scores": scores}
            calls.append(call)
            self._report(call)
            return scores, tokens

        judge.judge, judge.detect_injection = judge_call, injection_call

    def record(self, messages: list) -> dict[str, Any]:
        """Everything observed; ``ts`` fields (time.time(), like the guard's audit records) give the order."""
        return {"messages": [serialize(message) for message in messages], "raw_results": self.raw_results,
                "judge_calls": self.judge_calls, "model_responses": self.model_responses}


class _ModelRecorder(AgentMiddleware):
    """Each model response: its text and the tool calls it decided on."""

    def __init__(self, tracer: EpisodeTracer) -> None:
        super().__init__()
        self.tracer = tracer

    async def awrap_model_call(self, request, handler):
        response = await handler(request)
        messages = response.result if hasattr(response, "result") else [response]
        for message in messages:
            if isinstance(message, AIMessage):
                event = {"kind": "model", "ts": time.time(), **serialize(message)}
                self.tracer.model_responses.append(event)
                self.tracer._report(event)
        return response


class _RawResultRecorder(AgentMiddleware):
    """Inside the guard's middleware: sees results as the tool returned them."""

    def __init__(self, sink: list[dict[str, Any]]) -> None:
        super().__init__()
        self.sink = sink

    async def awrap_tool_call(self, request, handler):
        result = await handler(request)
        content = result.content if isinstance(result, ToolMessage) else result
        if isinstance(content, list):
            content = "\n".join(str(b.get("text", b)) if isinstance(b, dict) else str(b) for b in content)
        call = request.tool_call
        self.sink.append({"ts": time.time(), "call_id": call.get("id"), "tool": call["name"], "args": call.get("args"),
                          "content": str(content)[:TEXT_LIMIT]})
        return result


def serialize(message) -> dict[str, Any]:
    if isinstance(message, SystemMessage):
        return {"role": "system", "content": str(message.content)}
    if isinstance(message, HumanMessage):
        return {"role": "user", "content": str(message.content)}
    if isinstance(message, AIMessage):
        return {"role": "assistant", "content": message.text or "",
                "tool_calls": [{"id": c.get("id"), "name": c["name"], "args": c.get("args", {})} for c in message.tool_calls]}
    if isinstance(message, ToolMessage):
        content = message.content
        if isinstance(content, list):
            content = "\n".join(str(b.get("text", b)) if isinstance(b, dict) else str(b) for b in content)
        return {"role": "tool", "tool_call_id": message.tool_call_id, "name": message.name,
                "status": getattr(message, "status", None), "content": str(content)[:TEXT_LIMIT]}
    return {"role": type(message).__name__, "content": str(getattr(message, "content", ""))[:TEXT_LIMIT]}
