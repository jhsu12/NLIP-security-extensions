"""Mock workspace backend: one user's inbox, calendar, and cloud drive.

The data, tools, and task checkers come from the AgentDojo ``workspace`` suite, so
benign tasks and injection attacks can be scored from the backend state instead of
from the model's text.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.task_suite.task_suite import TaskSuite

SUITE_VERSION = "v1.2.2"
SUITE_NAME = "workspace"


def load_suite(version: str = SUITE_VERSION) -> TaskSuite:
    return get_suite(version, SUITE_NAME)


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """What an MCP client sees for one tool in ``tools/list``."""

    name: str
    description: str
    input_schema: dict[str, Any]


@dataclass(slots=True)
class WorkspaceState:
    """A mutable workspace environment plus a record of every executed tool call.

    ``executed`` is ground truth for "did tools/call actually run": a call blocked
    before execution never appears here.
    """

    suite: TaskSuite
    env: Any
    description_overrides: dict[str, str] = field(default_factory=dict)
    executed: list[FunctionCall] = field(default_factory=list)

    @classmethod
    def create(
        cls,
        injections: Mapping[str, str] | None = None,
        *,
        suite: TaskSuite | None = None,
        description_overrides: Mapping[str, str] | None = None,
    ) -> "WorkspaceState":
        """Load the seeded environment, optionally with attacker text at injection vectors."""
        suite = suite or load_suite()
        env = suite.load_and_inject_default_environment(dict(injections or {}))
        return cls(suite, env, dict(description_overrides or {}))

    def tool_specs(self) -> list[ToolSpec]:
        return [
            ToolSpec(
                name=function.name,
                # A poisoned or rug-pulled MCP server is modelled by overriding descriptions.
                description=self.description_overrides.get(function.name, function.description),
                input_schema=function.parameters.model_json_schema(),
            )
            for function in self.suite.tools
        ]

    def run(self, name: str, arguments: Mapping[str, Any]) -> tuple[str, str | None]:
        """Execute one tool against the environment; return (result text, error)."""
        runtime = FunctionsRuntime(self.suite.tools)
        result, error = runtime.run_function(self.env, name, dict(arguments))
        self.executed.append(FunctionCall(function=name, args=dict(arguments)))
        if error:
            return "", error
        return tool_result_to_str(result), None
