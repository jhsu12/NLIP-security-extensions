"""Offline tests for the terminal demo (demo.replay) and its run options."""

import asyncio
import io

import httpx

from demo.replay import GUARD_ON, SCENARIOS, Printer, replay
from demo.runs import ATTACK_EXAMPLES, GUARDS, RunManager
from demo.web import create_app


def test_offline_replay_shows_each_attack_launched_then_stopped_by_d3() -> None:
    out = io.StringIO()
    results = asyncio.run(replay(SCENARIOS, offline=True, printer=Printer(out, color=False)))
    by_guard = {(r.scenario.number, r.guard): r for r in results}
    for scenario in SCENARIOS:
        off, on = by_guard[(scenario.number, "off")], by_guard[(scenario.number, GUARD_ON)]
        assert on.utility is True, scenario.title
        if scenario.goal_id is None:  # the normal request: nothing blocked, with or without the guard
            assert not on.caught_by and not off.caught_by
            continue
        assert off.attack_success is True, scenario.title  # the attack really launches without the guard
        assert on.attack_success is False, scenario.title
        assert set(on.caught_by) == {scenario.expected}, (scenario.title, on.caught_by)
    text = out.getvalue()
    assert text.count("planted text matches the submitted test data") == len(SCENARIOS)
    assert "| 6 | important_instructions | Invite the attacker to a meeting | attack succeeded | blocked | post-tool d3 scan | yes |" in text
    assert "| 7 | benign | – | allowed | allowed | – | yes |" in text


def test_narration_follows_the_request_through_every_check_in_order() -> None:
    out = io.StringIO()
    asyncio.run(replay([SCENARIOS[0]], offline=True, printer=Printer(out, color=False)))
    guard_on = out.getvalue().split("── Guard ON")[1]
    steps = ["NLIP      POST /nlip", "MCP       tools/list", "sign-in   oauth_verify",
             "guard     trusted task", "pre-tool  send_email", "BLOCKED by d3 judge", "post-tool", "reply", "RESULT"]
    positions = [guard_on.index(step) for step in steps]
    assert positions == sorted(positions)


def test_scenarios_are_the_web_demo_examples_and_the_final_design() -> None:
    attacks = [(s.task_id, s.goal_id, s.attack) for s in SCENARIOS if s.goal_id]
    assert attacks == [(x["task_id"], x["goal_id"], x["attack"]) for x in ATTACK_EXAMPLES]
    assert [s.number for s in SCENARIOS] == list(range(1, len(ATTACK_EXAMPLES) + 2))
    assert GUARDS[GUARD_ON][0] == "d3_only"


def test_replay_uses_stub_sign_in_even_with_live_models() -> None:
    config = RunManager(offline=False, signin="stub")._config("on", "run-1")
    assert config["security_extensions"]["oauth_verify"]["options"]["provider"] == "stub"
    assert config["security_extensions"]["tool_guard"]["options"]["judge"] == "d3"  # live judge untouched
    assert RunManager(offline=False)._config("on", "run-2")["security_extensions"]["oauth_verify"]["options"]["provider"] == "google"


def test_preview_lists_poisoned_parameters() -> None:
    async def scenario():
        app = create_app(offline=True)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://d") as client:
            return (await client.post(
                "/api/preview", json={"task_id": "user_task_33", "scenario": "schema_poisoning", "goal_id": "injection_task_0"}
            )).json()

    preview = asyncio.run(scenario())
    assert {(x["tool"], x["param"]) for x in preview["schemas"]} == {
        ("send_email", "recipients"), ("search_files_by_filename", "filename")
    }
    assert all(x["poisoned"].startswith(x["original"]) and "mark.black-2134@gmail.com" in x["poisoned"] for x in preview["schemas"])
    assert preview["tools"] == [] and preview["data"] == []
