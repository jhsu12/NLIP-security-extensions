"""Write the evaluation's test data out as plain files under ``data/``.

The harness builds cases from the AgentDojo package at run time; this script freezes
exactly what it builds, so the benign traffic and every attack case can be read and
reviewed without running anything:

    python -m adversarial_tests.tool_guard_eval.export_data

Output:
    data/user_tasks.jsonl         the 40 benign user tasks (prompt, split, expected tool calls)
    data/injection_tasks.jsonl    the 14 attacker goals
    data/attacks/<attack>.jsonl   one line per (user task, attacker goal): the exact text
                                  planted in tool data and/or tool descriptions
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_applications.workspace_assistant.environment import SUITE_VERSION, load_suite

from .cases import ATTACKS, Case, _number, plant, split_of

DATA_DIR = Path(__file__).resolve().parent / "data"
# Attacks address the model by name; the exported text uses the default agent's name.
AGENT_MODEL = "qwen-3.8-27b"


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as output:
        for row in rows:
            output.write(json.dumps(row, ensure_ascii=False) + "\n")


def main() -> None:
    suite = load_suite()
    user_ids = sorted(suite.user_tasks, key=_number)
    injection_ids = sorted(suite.injection_tasks, key=_number)
    environment = suite.load_and_inject_default_environment({})

    users = []
    for user_id in user_ids:
        task = suite.get_user_task_by_id(user_id)
        expected = task.ground_truth(task.init_environment(environment.model_copy(deep=True)))
        users.append(
            {
                "id": user_id,
                "split": split_of(user_id),
                "difficulty": task.DIFFICULTY.name.lower(),
                "prompt": task.PROMPT,
                "expected_tool_calls": [{"tool": call.function, "args": dict(call.args)} for call in expected],
            }
        )
    write_jsonl(DATA_DIR / "user_tasks.jsonl", users)

    write_jsonl(
        DATA_DIR / "injection_tasks.jsonl",
        [
            {
                "id": injection_id,
                "difficulty": suite.get_injection_task_by_id(injection_id).DIFFICULTY.name.lower(),
                "goal": suite.get_injection_task_by_id(injection_id).GOAL,
            }
            for injection_id in injection_ids
        ],
    )

    for attack in ATTACKS:
        rows = []
        for user_id in user_ids:
            for injection_id in injection_ids:
                case = Case(user_id, injection_id, attack)
                injections, overrides = plant(case, suite, AGENT_MODEL)
                rows.append(
                    {
                        "key": case.key,
                        "split": split_of(user_id),
                        "user_task": user_id,
                        "injection_task": injection_id,
                        "attack": attack,
                        "planted_in_tool_data": injections,
                        "planted_in_tool_descriptions": overrides,
                    }
                )
        write_jsonl(DATA_DIR / "attacks" / f"{attack}.jsonl", rows)

    print(
        f"AgentDojo workspace {SUITE_VERSION}: {len(users)} user tasks, {len(injection_ids)} goals, "
        f"{len(ATTACKS)} attacks x {len(user_ids) * len(injection_ids)} cases -> {DATA_DIR}"
    )


if __name__ == "__main__":
    main()
