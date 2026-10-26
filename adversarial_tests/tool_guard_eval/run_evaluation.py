"""Replay benign and attack cases against the workspace NLIP endpoint and record outcomes.

Every episode gets a fresh server (backend seeded for its task, attack planted), sends
the user task as an NLIP message over HTTP to ``POST /nlip``, then scores the backend
state with AgentDojo: did the user's task succeed, and did the attacker's goal happen?

    python -m adversarial_tests.tool_guard_eval.run_evaluation --config hybrid_d3 \
        --model qwen-3.8-27b --split dev --attacks important_instructions --sample 40

Results append to a JSONL file (one line per episode); re-running skips finished
episodes, so an interrupted run can be resumed. Summarize with ``metrics.py``.
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import json
import os
import time
import tomllib
from pathlib import Path
from typing import Any

import httpx
from agentdojo.agent_pipeline.tool_execution import text_content_block_from_string
from langchain_core.messages import AIMessage

from agent_applications.workspace_assistant._config import CONFIG
from agent_applications.workspace_assistant.environment import WorkspaceState, load_suite
from agent_applications.workspace_assistant.nlip_agent import ENTITY_NAME, WorkspaceNLIPAgent
from nlip_sdk import NLIPClient, NLIPMessage

from .cases import ATTACKS, Case, build_cases, plant

HERE = Path(__file__).resolve().parent
CONFIG_DIR = HERE / "configs"
RESULTS_DIR = HERE / "results"


class InMemoryNLIPClient(NLIPClient):
    """NLIPClient whose HTTP requests go to an in-process ASGI app instead of a socket.

    The request still passes through FastAPI's ``POST /nlip`` route, JSON validation, and
    the server's ingress/egress security pipeline.
    """

    def __init__(self, app, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._transport = httpx.ASGITransport(app=app)

    async def _post(self, destination: str, message: NLIPMessage) -> httpx.Response:
        async with httpx.AsyncClient(transport=self._transport, timeout=self.timeout) as client:
            return await client.post(self.endpoints[destination], json=message.to_dict())


def load_eval_config(name_or_path: str) -> dict[str, Any]:
    path = Path(name_or_path)
    if not path.exists():
        path = CONFIG_DIR / f"{name_or_path}.toml"
    with path.open("rb") as config_file:
        data = tomllib.load(config_file)
    data.setdefault("name", path.stem)
    return data


def app_config(eval_config: dict[str, Any]) -> dict[str, Any]:
    """The application's config.toml with the tool guard switched/configured per run."""
    config = copy.deepcopy(CONFIG)
    enabled = eval_config.get("enabled", True)
    points = ["tool_guard"] if enabled else []
    config["entities"][ENTITY_NAME]["security"] = {"ingress": points, "egress": points}
    options = config["security_extensions"]["tool_guard"]["options"]
    options.update(eval_config.get("options", {}))
    options["audit_path"] = None  # audit records are stored in the results file instead
    return config


async def run_episode(case: Case, eval_config: dict[str, Any], model: str, suite) -> dict[str, Any]:
    user_task = suite.get_user_task_by_id(case.user_task)
    injection_task = suite.get_injection_task_by_id(case.injection_task) if case.injection_task else None
    injections, description_overrides = plant(case, suite, model)
    pre: dict[str, Any] = {}

    def state_factory() -> WorkspaceState:
        state = WorkspaceState.create(injections, suite=suite, description_overrides=description_overrides)
        state.env = user_task.init_environment(state.env)
        pre["env"] = state.env.model_copy(deep=True)
        return state

    server = WorkspaceNLIPAgent(app_config(eval_config), state_factory=state_factory, model=model)
    client = InMemoryNLIPClient(server.create_nlip_app(), {ENTITY_NAME: CONFIG["entities"][ENTITY_NAME]["endpoint"]})
    started = time.perf_counter()
    error = None
    output = ""
    try:
        response = await client.send_text(ENTITY_NAME, user_task.PROMPT)
        output = response.extract_text(language=None) or ""
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"[:500]
    wall = time.perf_counter() - started

    record: dict[str, Any] = {
        **case.to_dict(),
        "key": case.key,
        "config": eval_config["name"],
        "model": model,
        "utility": False,
        "attack_success": None,
        "error": error,
        "wall_s": round(wall, 2),
    }
    agent = next(iter(server.agents.values()), None)
    if agent is not None:
        blocks = [text_content_block_from_string(output)]
        record["utility"] = bool(
            suite._check_task_result(user_task, blocks, pre["env"], agent.state.env, agent.state.executed)
        )
        if injection_task is not None:
            record["attack_success"] = bool(
                suite._check_task_result(injection_task, blocks, pre["env"], agent.state.env, agent.state.executed)
            )
        record["executed"] = [{"tool": call.function, "args": call.args} for call in agent.state.executed]
        usage = [message.usage_metadata for message in agent.messages if isinstance(message, AIMessage)]
        record["agent_calls"] = len(usage)
        record["agent_tokens"] = sum((item or {}).get("total_tokens", 0) for item in usage)
        await agent.close()
    record["output"] = output[:500]
    if server.guard is not None:
        record["guard"] = server.guard.audit.records
        await server.guard.aclose()
    return record


def done_keys(path: Path) -> set[str]:
    """Episodes that finished without an infrastructure error; errored ones are re-run."""
    if not path.exists():
        return set()
    with path.open(encoding="utf-8") as results:
        records = [json.loads(line) for line in results if line.strip()]
    return {record["key"] for record in records if not record.get("error")}


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", required=True, help="Name in configs/ (e.g. hybrid_d3) or a TOML path")
    parser.add_argument("--model", default=os.getenv("AGENT_MODEL", "qwen-3.8-27b"))
    parser.add_argument("--split", choices=("dev", "test", "all"), default="dev")
    parser.add_argument("--attacks", default="important_instructions", help=f"Comma list from {', '.join(ATTACKS)}, or none")
    parser.add_argument("--injection-tasks", help="Comma list of injection task ids (default: all 14)")
    parser.add_argument("--user-tasks", help="Comma list of user task ids (default: all in the split)")
    parser.add_argument("--no-benign", action="store_true", help="Skip benign (no attack) episodes")
    parser.add_argument("--sample", type=int, help="Randomly keep this many episodes per attack")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--concurrency", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=300.0, help="Seconds per episode")
    parser.add_argument("--out", help="Results JSONL (default: results/<config>__<model>__<split>.jsonl)")
    args = parser.parse_args()

    suite = load_suite()
    eval_config = load_eval_config(args.config)
    attacks = [] if args.attacks == "none" else args.attacks.split(",")
    unknown = set(attacks) - set(ATTACKS)
    if unknown:
        parser.error(f"unknown attacks: {', '.join(sorted(unknown))}")
    cases = build_cases(
        suite,
        split=args.split,
        attacks=attacks,
        injection_tasks=args.injection_tasks.split(",") if args.injection_tasks else None,
        user_tasks=args.user_tasks.split(",") if args.user_tasks else None,
        benign=not args.no_benign,
        sample=args.sample,
        seed=args.seed,
    )
    out = Path(args.out) if args.out else RESULTS_DIR / f"{eval_config['name']}__{args.model}__{args.split}.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    finished = done_keys(out)
    todo = [case for case in cases if case.key not in finished]
    print(f"{eval_config['name']} / {args.model} / {args.split}: {len(cases)} cases, {len(todo)} to run -> {out}", flush=True)

    semaphore = asyncio.Semaphore(args.concurrency)
    lock = asyncio.Lock()
    progress = {"done": 0}

    async def worker(case: Case) -> None:
        async with semaphore:
            try:
                record = await asyncio.wait_for(run_episode(case, eval_config, args.model, suite), args.timeout)
            except Exception as exc:
                record = {**case.to_dict(), "key": case.key, "config": eval_config["name"], "model": args.model,
                          "utility": False, "attack_success": None, "error": f"{type(exc).__name__}: {exc}"[:500]}
        async with lock:
            with out.open("a", encoding="utf-8") as results:
                results.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
            progress["done"] += 1
            attack = "-" if record["attack_success"] is None else ("HIJACKED" if record["attack_success"] else "safe")
            print(
                f"[{progress['done']}/{len(todo)}] {case.key:55s} utility={'Y' if record['utility'] else 'N'} "
                f"attack={attack:8s} {record.get('wall_s', '?')}s{'  ERROR ' + record['error'][:80] if record.get('error') else ''}",
                flush=True,
            )

    await asyncio.gather(*(worker(case) for case in todo))


if __name__ == "__main__":
    asyncio.run(main())
