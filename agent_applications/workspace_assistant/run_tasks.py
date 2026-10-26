"""Run AgentDojo workspace user tasks through the NLIP pipeline and score them.

Each task gets a fresh NLIP session whose backend is initialised for that task. The
request goes through the same ``process_exchange`` path as HTTP traffic (ingress SEs,
agent, egress SEs), and utility is judged by AgentDojo from the backend state.

    python -m agent_applications.workspace_assistant.run_tasks user_task_0 user_task_6
    python -m agent_applications.workspace_assistant.run_tasks --all
"""

from __future__ import annotations

import argparse
import asyncio
import json
import time

from agentdojo.agent_pipeline.tool_execution import text_content_block_from_string

from nlip_sdk import NLIPMessage

from .environment import WorkspaceState, load_suite
from .nlip_agent import ENTITY_NAME, WorkspaceNLIPAgent

DEFAULT_TASKS = ["user_task_0", "user_task_3", "user_task_6", "user_task_13", "user_task_25"]


async def run_task(task_id: str, *, model: str | None = None) -> dict:
    suite = load_suite()
    task = suite.get_user_task_by_id(task_id)
    pre_environment = {}

    def state_factory() -> WorkspaceState:
        state = WorkspaceState.create(suite=suite)
        state.env = task.init_environment(state.env)
        pre_environment["env"] = state.env.model_copy(deep=True)
        return state

    server = WorkspaceNLIPAgent(state_factory=state_factory, model=model)
    started = time.perf_counter()
    error = None
    try:
        response = await server.process_exchange(NLIPMessage.text(task.PROMPT))
        output = response.extract_text(language=None) or ""
    except Exception as exc:  # report the failure and keep going with other tasks
        output, error = "", f"{type(exc).__name__}: {exc}"
    latency = time.perf_counter() - started

    session_id = next(iter(server.agents), None)
    agent = server.agents.get(session_id) if session_id else None
    utility = False
    executed: list[str] = []
    if agent is not None:
        executed = [call.function for call in agent.state.executed]
        utility = suite._check_task_result(
            task,
            [text_content_block_from_string(output)],
            pre_environment["env"],
            agent.state.env,
            agent.state.executed,
        )
        await agent.close()
    return {
        "task": task_id,
        "utility": bool(utility),
        "latency_s": round(latency, 1),
        "tool_calls": executed,
        "output": output[:300],
        "error": error,
        "entity": ENTITY_NAME,
    }


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("tasks", nargs="*", help="AgentDojo user task ids")
    parser.add_argument("--all", action="store_true", help="Run every workspace user task")
    parser.add_argument("--model", help="Override AGENT_MODEL")
    parser.add_argument("--json", action="store_true", help="Print one JSON object per task")
    args = parser.parse_args()

    task_ids = list(load_suite().user_tasks) if args.all else (args.tasks or DEFAULT_TASKS)
    results = []
    for task_id in task_ids:
        result = await run_task(task_id, model=args.model)
        results.append(result)
        if args.json:
            print(json.dumps(result), flush=True)
        else:
            mark = "PASS" if result["utility"] else "FAIL"
            print(f"{mark} {task_id:14s} {result['latency_s']:6.1f}s  calls={result['tool_calls']}", flush=True)
            if result["error"]:
                print(f"     error: {result['error'][:200]}")
    passed = sum(result["utility"] for result in results)
    print(f"\nutility: {passed}/{len(results)}")


if __name__ == "__main__":
    asyncio.run(main())
