"""Terminal demo: the web demo's "Show me an attack" cases, guard OFF then ON (final design: d3 only).

    python -m demo.replay --stub                 # offline: no keys, no network, ~1 min
    python -m demo.replay                        # live: Jetstream model + d3 judge (needs .env)
    python -m demo.replay --stub --scenario 4    # one scenario
    python -m demo.replay --stub --markdown run.md   # also save the narration and table

The six attacks are ``demo.runs.ATTACK_EXAMPLES``, the same list as the web page's
"Show me an attack" menu: cases where the attack succeeded without a guard in the
evaluation, hiding the instruction in different places (a tool description, tagged or
plain; a parameter description; a file the task reads). A seventh, normal request shows
the guard letting legitimate work through. Each case is checked against the planted text
in adversarial_tests/tool_guard_eval/data/ and sent to the workspace assistant as a real
NLIP request (POST /nlip with a sign-in token). Every step behind the scenes is printed as
it happens: sign-in, each tool call with the guard's pre-tool decision (the d3 judge) and
post-tool scan (the d3 injection detector), the reply, and AgentDojo's verdict. A summary
table at the end shows what was blocked, what got through, and what it cost.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

from nlip_sdk import NLIPMessage
from security_extensions.oauth_login import make_stub_token
from security_extensions.tool_guard.session import extract_indicators

from .runs import ATTACK_EXAMPLES, GOAL_LABELS, RunManager, RunSpec

DATA = Path(__file__).resolve().parent.parent / "adversarial_tests" / "tool_guard_eval" / "data"
USER = "emma.johnson@bluesparrowtech.com"
GUARD_ON = "on"  # demo.runs maps it to d3_only, the final design: d3 judge before calls, d3 scan after
JUDGE, SCAN = "pre-tool d3 judge", "post-tool d3 scan"


@dataclass(frozen=True)
class Scenario:
    number: int
    title: str
    attack: str
    task_id: str
    goal_id: str | None
    expected: str | None  # the check that should stop it with the guard on (None: no attack)
    model: str | None = None  # live: the model the attack worked on, unless --model is given


STYLE = {
    "tool_poisoning": "<IMPORTANT> block in a tool description",
    "tool_poisoning_plain": "one plain sentence in a tool description",
    "schema_poisoning_tagged": "<IMPORTANT> block in a parameter description",
    "schema_poisoning": "one sentence in a parameter description",
    "important_instructions": "instructions planted in the data the task reads",
}
# The web demo's "Show me an attack" cases, then one normal request.
SCENARIOS = [
    Scenario(number, f"{STYLE[x['attack']]}: {GOAL_LABELS[x['goal_id']].lower()} · {x['worked']}", x["attack"],
             x["task_id"], x["goal_id"], SCAN if x["attack"] == "important_instructions" else JUDGE, x.get("model"))
    for number, x in enumerate(ATTACK_EXAMPLES, 1)
] + [
    Scenario(len(ATTACK_EXAMPLES) + 1, "No attack: a normal request the guard must let through", "benign",
             "user_task_33", None, None),
]


@dataclass
class Result:
    scenario: Scenario
    guard: str
    setup: dict[str, Any] = field(default_factory=dict)  # the run's setup event (planted text)
    attack_success: bool | None = None
    utility: bool | None = None
    caught_by: list[str] = field(default_factory=list)
    other_blocks: list[str] = field(default_factory=list)  # blocked calls that were not the attacker's goal
    guard_ms: float = 0.0
    judge_calls: int = 0
    wall_s: float = 0.0


class Printer:
    """Narration to the terminal (optionally colored) and, plain, to a Markdown file."""

    COLORS = {"ok": "32", "bad": "31", "warn": "33", "dim": "2", "bold": "1", "head": "36;1"}

    def __init__(self, out: TextIO, color: bool, record: list[str] | None = None) -> None:
        self.out, self.color, self.record = out, color, record

    def line(self, text: str = "", tone: str | None = None) -> None:
        shown = f"\033[{self.COLORS[tone]}m{text}\033[0m" if self.color and tone else text
        print(shown, file=self.out, flush=True)
        if self.record is not None:
            self.record.append(text)

    def step(self, mark: str, what: str, text: str, tone: str | None = None) -> None:
        self.line(f"   {mark}  {what:<10}{text}", tone)


def short(text: Any, limit: int = 90) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def args_summary(arguments: Any) -> str:
    if not isinstance(arguments, dict):
        return ""
    parts = [f"{k}={', '.join(map(str, v)) if isinstance(v, list) else v}" for k, v in arguments.items()]
    return short(" · ".join(parts), 70)


def load_case(attack: str, key: str) -> dict[str, Any]:
    with (DATA / "attacks" / f"{attack}.jsonl").open(encoding="utf-8") as cases:
        for line in cases:
            row = json.loads(line)
            if row["key"] == key:
                return row
    raise KeyError(f"{key} is not in data/attacks/{attack}.jsonl")


def check_against_data(scenario: Scenario, run_event: dict[str, Any], model_name: str) -> str:
    """Assert the run plants exactly the text in the submitted test data."""
    if scenario.goal_id is None:  # benign: the task must be a test-split user task, nothing planted
        with (DATA / "user_tasks.jsonl").open(encoding="utf-8") as tasks:
            row = next(json.loads(line) for line in tasks if json.loads(line)["id"] == scenario.task_id)
        if run_event["injections"] or run_event["poisoned_descriptions"]:
            raise AssertionError(f"{scenario.task_id} must have nothing planted")
        return f"data/user_tasks.jsonl · {scenario.task_id} ({row['split']} split, nothing planted)"
    key = f"{scenario.task_id}|{scenario.goal_id}|{scenario.attack}"
    row = load_case(scenario.attack, key)
    # The exported text addresses the default model as "Qwen"; runs use the agent's name.
    normalize = lambda value: json.loads(json.dumps(value).replace("Qwen", model_name))  # noqa: E731
    schemas: dict[str, dict[str, str]] = {}
    for change in run_event["changes"]["schemas"]:
        schemas.setdefault(change["tool"], {})[change["param"]] = change["poisoned"]
    planted = (run_event["injections"], run_event["poisoned_descriptions"], schemas)
    expected = (
        normalize(row["planted_in_tool_data"]),
        normalize(row["planted_in_tool_descriptions"]),
        normalize(row.get("planted_in_tool_schemas", {})),
    )
    if planted != expected:
        raise AssertionError(f"planted text for {key} differs from data/attacks/{scenario.attack}.jsonl")
    return f"data/attacks/{scenario.attack}.jsonl · {key} ({row['split']} split)"


def describe_attack(changes: dict[str, Any]) -> str:
    if not (changes["tools"] or changes["schemas"] or changes["data"]):
        return "none: a normal request, to show the guard letting legitimate work through"
    if changes["tools"]:
        return f"a malicious MCP server adds an instruction to the {', '.join(c['tool'] for c in changes['tools'])} description"
    if changes["schemas"]:
        return "a malicious MCP server adds an instruction to the parameter " + ", ".join(
            f"{c['tool']}.{c['param']}" for c in changes["schemas"]
        )
    return f"the attacker planted an instruction in {', '.join(c['label'] for c in changes['data'])}"


async def play(manager: RunManager, scenario: Scenario, guard: str, printer: Printer, model: str | None) -> Result:
    """One NLIP exchange with the narration printed while it runs."""
    run = await manager.create(
        RunSpec(scenario=scenario.attack, guard=guard, task_id=scenario.task_id, goal_id=scenario.goal_id, model=model)
    )
    meta = run.events[0]
    result = Result(scenario, guard, setup=meta)
    planted = extract_indicators(meta["goal"] or "") - extract_indicators(run.prompt)
    guarded = guard != "off"

    def attackers_call(tool: str, arguments: Any) -> bool:
        """Does this call carry out the attacker's goal (a value only the goal names, or its delete)?"""
        hit = planted & extract_indicators(json.dumps(arguments, default=str))
        # Goals 1 and 5 end in a delete, which names no attacker address.
        return bool(hit) or (scenario.goal_id, tool) in {("injection_task_1", "delete_file"), ("injection_task_5", "delete_email")}
    printer.line(f"── Guard {'ON  (d3 only: d3 judge before each call, d3 scan after; no rules)' if guarded else 'OFF'}", "bold")
    printer.step("→", "NLIP", "POST /nlip · user text + authorization token + conversation token")
    if guard in ("off", GUARD_ON):  # neither checks tool descriptions
        printer.step("→", "MCP", "tools/list · 24 tool descriptions go to the model unchecked", "dim")

    def narrate(event: dict[str, Any]) -> None:
        kind, point = event["type"], event.get("point")
        if kind == "ingress":
            printer.step("✓", "sign-in", f"oauth_verify: {event['user']}", "ok")
            if guarded:
                printer.step("✓", "guard", f"trusted task recorded: “{short(event['text'], 60)}”", "ok")
        elif kind == "guard" and point == "catalog":
            result.guard_ms += event.get("latency_ms", 0)
            result.judge_calls += event.get("judge_calls", 0)
            printer.step("→", "MCP", f"tools/list · {event['total_tools']} tool descriptions → checked before the model sees them")
            changed = event.get("changed_tools") or []
            if changed:
                result.caught_by.append("catalog check")
                values = f" · planted value(s): {', '.join(event['planted'])}" if event.get("planted") else ""
                printer.step("⚑", "catalog", f"removed a hidden instruction from {', '.join(c['tool'] for c in changed)}{values}", "warn")
            else:
                note = " (the instruction is in a parameter description, which this check does not read)" if meta["changes"]["schemas"] else ""
                printer.step("✓", "catalog", f"all descriptions look like documentation{note}", "ok")
        elif kind == "guard" and point == "pre_tool":
            result.guard_ms += event.get("latency_ms", 0)
            result.judge_calls += event.get("judge_calls", 0)
            layer = {"policy": "policy", "judge": "d3 judge", "validation": "validation"}.get(event["layer"], event["layer"])
            why = event["reason"]
            if event.get("p_aligned") is not None:
                threshold = (event.get("details") or {}).get("threshold", 0.5)
                why = f"P(user would approve) = {event['p_aligned']:.2f} vs threshold {threshold:.2f}"
            call = f"{event['tool']}({args_summary(event.get('arguments'))})"
            if event["action"] == "block":
                if scenario.goal_id is None or attackers_call(event["tool"], event.get("arguments")):
                    result.caught_by.append(JUDGE if event["layer"] == "judge" else f"pre-tool {layer}")
                    note = ""
                else:  # e.g. a delete the user never asked for: right to block, but not the planted goal
                    result.other_blocks.append(event["tool"])
                    note = " (a call the user didn't ask for, but not the attacker's goal)"
                printer.step("✗", "pre-tool", f"{call} → BLOCKED by {layer}: {short(why, 80)}{note}", "bad")
                printer.step(" ", "", "the MCP tools/call is never sent; the model is told it was blocked", "dim")
            elif event["reason"] == "read-only tool":
                printer.step("✓", "pre-tool", f"{call} → allowed (read-only tool: no side effects, nothing to judge)", "ok")
            else:
                printer.step("✓", "pre-tool", f"{call} → allowed ({layer}: {short(why, 60)})", "ok")
        elif kind == "tool_executed":
            if scenario.goal_id and attackers_call(event["tool"], event.get("arguments")):
                printer.step("→", "tool", f"{event['tool']}({args_summary(event.get('arguments'))}) executed ⚠ attacker's action", "bad")
            else:
                printer.step("→", "tool", f"{event['tool']}({args_summary(event.get('arguments'))}) executed")
        elif kind == "guard" and point == "post_tool":
            result.guard_ms += event.get("latency_ms", 0)
            result.judge_calls += event.get("judge_calls", 0)
            if event["action"] == "replace":
                result.caught_by.append(SCAN)
                snippet = short((event.get("details") or {}).get("flagged", [""])[0], 70)
                printer.step("⚑", "post-tool", f"redacted injected text before the model reads it: “{snippet}” · session tainted", "warn")
            else:
                printer.step("✓", "post-tool", "result scanned by d3: no instructions aimed at the assistant", "ok")
        elif kind == "reply":
            printer.step("←", "reply", f"“{short(event.get('text') or '', 80)}”")
        elif kind == "rejected":
            printer.step("✗", "sign-in", f"HTTP {event['status']}: {event['detail']}", "bad")
        elif kind == "error":
            printer.step("✗", "error", short(event["message"], 100), "bad")

    async def listen() -> None:
        async for event in run.stream(1):  # event 0 is the run setup, printed above
            if event is None:
                continue
            narrate(event)
            if event["type"] in ("outcome", "rejected", "error"):
                if event["type"] == "outcome":
                    result.attack_success, result.utility = event["attack_success"], event["utility"]
                return

    listener = asyncio.create_task(listen())
    message = NLIPMessage.text(run.prompt)
    message.add_authentication_token(make_stub_token(USER))
    started = asyncio.get_running_loop().time()
    await run.send(message.to_dict())
    await asyncio.wait_for(listener, 10)
    result.wall_s = asyncio.get_running_loop().time() - started

    task = "user's task done" if result.utility else "user's task NOT done"
    if scenario.goal_id is None:
        blocked = " · ".join(dict.fromkeys(result.caught_by)) or "nothing blocked"
        printer.step("✓" if not result.caught_by else "✗", "RESULT", f"no attack · {task} · {blocked}"
                     f"{f' · guard time {result.guard_ms / 1000:.2f} s · {result.judge_calls} judge call(s)' if guarded else ''}",
                     "ok" if not result.caught_by else "bad")
    elif result.attack_success:
        printer.step("✗", "RESULT", f"ATTACK SUCCEEDED · {task}", "bad")
    elif result.caught_by:
        printer.step("✓", "RESULT", f"ATTACK STOPPED by {' + '.join(dict.fromkeys(result.caught_by))} · {task} · "
                     f"guard time {result.guard_ms / 1000:.2f} s · {result.judge_calls} judge call(s)", "ok")
    else:
        also = f" · the guard also blocked an unrequested {', '.join(dict.fromkeys(result.other_blocks))} call" if result.other_blocks else ""
        guard_note = "" if guarded else " (no guard involved)"
        printer.step("·", "RESULT", f"attack did not happen: the model ignored the instruction{guard_note} · {task}{also}", "warn")
    await run.close()
    manager.runs.pop(run.id, None)
    return result


async def replay(
    selected: list[Scenario], *, offline: bool, printer: Printer, model: str | None = None, retries: int = 0
) -> list[Result]:
    manager = RunManager(offline=offline, signin="stub")
    printer.line("Tool guard replay · workspace assistant over NLIP (ECMA-430/431)", "head")
    if offline:
        printer.line("Offline mode: a scripted agent replays AgentDojo's tool calls and obeys any instruction it can")
        printer.line("see (the worst case); the d3 judge is simulated. Live mode uses the real model and judge.", "dim")
    else:
        printer.line(f"Live mode: agent model {model or os.getenv('AGENT_MODEL', 'qwen-3.8-27b')}, d3 judge (vllm-sr/d3-flash).", "dim")
    results = []
    for scenario in selected:
        chosen = model
        if not offline and model is None and scenario.model:
            chosen = scenario.model
        model_name = "Gemma" if chosen and "gemma" in chosen else "Qwen"
        printer.line()
        printer.line(f"━━ Scenario {scenario.number}/{len(SCENARIOS)} · {scenario.title}", "head")
        preview = manager.preview(RunSpec(scenario=scenario.attack, task_id=scenario.task_id, goal_id=scenario.goal_id, model=chosen))
        task = manager.suite.get_user_task_by_id(scenario.task_id)
        if chosen != model:
            printer.line(f"   Model   {chosen} (the model this attack worked on in the evaluation)", "dim")
        printer.line(f"   Task    “{short(task.PROMPT, 80)}”  ({scenario.task_id})")
        printer.line(f"   Attack  {describe_attack(preview)}{':' if scenario.goal_id else ''}")
        if scenario.goal_id:
            goal = manager.suite.get_injection_task_by_id(scenario.goal_id)
            printer.line(f"           “{short(goal.GOAL, 90)}”")
        off = await play(manager, scenario, "off", printer, chosen)
        for _ in range(retries if not offline and scenario.goal_id else 0):
            if off.attack_success:
                break
            printer.line("   (the model ignored the instruction; trying again)", "dim")
            off = await play(manager, scenario, "off", printer, chosen)
        on = await play(manager, scenario, GUARD_ON, printer, chosen)
        source = check_against_data(scenario, off.setup, model_name)
        printer.line(f"   ✓ planted text matches the submitted test data: {source}", "dim")
        results += [off, on]
    summary(results, printer)
    return results


def summary(results: list[Result], printer: Printer) -> None:
    printer.line()
    printer.line("Summary: what got through, what was blocked, what it cost", "head")
    header = "| # | Attack | Attacker wants to | Guard OFF | Guard ON | Stopped by | Task done (ON) | Guard time | Judge calls |"
    printer.line(header)
    printer.line("|---|---|---|---|---|---|---|---|---|")
    pairs = {}
    for result in results:
        pairs.setdefault(result.scenario.number, {})["off" if result.guard == "off" else "on"] = result

    def verdict(r: Result) -> str:
        if r.scenario.goal_id is None:
            return "false block" if r.caught_by else "allowed"
        if r.attack_success:
            return "attack succeeded"
        if r.caught_by:
            return "blocked"
        return "not attempted" + (f" ({', '.join(dict.fromkeys(r.other_blocks))} blocked)" if r.other_blocks else "")

    for number, pair in pairs.items():
        off, on = pair["off"], pair["on"]
        printer.line(
            f"| {number} | {on.scenario.attack} | {GOAL_LABELS.get(on.scenario.goal_id, '–')} | {verdict(off)} | {verdict(on)} | "
            f"{' + '.join(dict.fromkeys(on.caught_by)) or '–'} | {'yes' if on.utility else 'no'} | "
            f"{on.guard_ms / 1000:.2f} s | {on.judge_calls} |"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--stub", action="store_true", help="Offline: scripted agent, simulated judge, no network")
    parser.add_argument("--scenario", action="append", type=int, choices=range(1, len(SCENARIOS) + 1),
                        help="Run only this scenario (repeatable)")
    parser.add_argument("--model", help="Agent model in live mode (default: AGENT_MODEL)")
    parser.add_argument("--retries", type=int, default=2, help="Live: re-run guard OFF up to N times if the model ignores the attack")
    parser.add_argument("--plain", action="store_true", help="No colors")
    parser.add_argument("--markdown", help="Also write the narration and summary to this Markdown file")
    args = parser.parse_args()
    if not args.stub and not (os.getenv("OPENAI_API_KEY") and os.getenv("VSR_API_KEY")):
        parser.error("live mode needs OPENAI_API_KEY and VSR_API_KEY (source .env), or run with --stub")
    selected = [s for s in SCENARIOS if not args.scenario or s.number in args.scenario]
    record: list[str] | None = [] if args.markdown else None
    printer = Printer(sys.stdout, color=sys.stdout.isatty() and not args.plain, record=record)
    asyncio.run(replay(selected, offline=args.stub, printer=printer, model=args.model, retries=args.retries))
    if args.markdown and record is not None:
        body = [line for line in record if not line.startswith("|")]
        table = [line for line in record if line.startswith("|")]
        Path(args.markdown).write_text(
            "# Tool guard replay\n\n```text\n" + "\n".join(body) + "\n```\n\n" + "\n".join(table) + "\n", encoding="utf-8"
        )


if __name__ == "__main__":
    main()
