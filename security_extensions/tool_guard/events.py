"""Data the tool guard observes at the tool boundary, and the verdicts it returns."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class ToolAction(str, Enum):
    """Mirrors the framework's SecurityAction so verdicts read the same at every point."""

    ALLOW = "allow"
    BLOCK = "block"
    REPLACE = "replace"


class Layer(str, Enum):
    VALIDATION = "validation"
    POLICY = "policy"
    JUDGE = "judge"
    SCANNER = "scanner"


@dataclass(frozen=True, slots=True)
class ToolCallEvent:
    """A model-proposed tool call, observed before ``tools/call`` is sent."""

    session_id: str
    server_id: str
    tool_name: str
    arguments: Any
    call_id: str | None = None


@dataclass(frozen=True, slots=True)
class ToolResultEvent:
    """A tool result, observed before the model reads it."""

    session_id: str
    server_id: str
    tool_name: str
    arguments: Any
    result: str
    call_id: str | None = None


@dataclass(slots=True)
class ToolVerdict:
    action: ToolAction
    reason: str
    layer: Layer
    # P(call serves the user's task) from the judge, when one ran.
    p_aligned: float | None = None
    latency_ms: float = 0.0
    judge_calls: int = 0
    judge_tokens: int = 0
    # For REPLACE: the sanitized tool result the model sees instead.
    replacement: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["action"] = self.action.value
        data["layer"] = self.layer.value
        data.pop("replacement")
        return data
