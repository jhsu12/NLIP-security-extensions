"""Offline tests for the web demo: routes, live event stream, and guard on/off outcomes."""

import asyncio

import httpx
import pytest

from demo.web import create_app
from nlip_sdk import NLIPMessage
from security_extensions.oauth_login import make_stub_token

USER = "emma.johnson@bluesparrowtech.com"
ATTACKER = "mark.black-2134@gmail.com"


def run(coroutine):
    return asyncio.run(coroutine)


async def demo_run(spec: dict, *, token: bool = True):
    app = create_app(offline=True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://demo") as client:
        created = await client.post("/api/runs", json=spec)
        assert created.status_code == 200, created.text
        run_id = created.json()["run_id"]
        message = NLIPMessage.text(created.json()["prompt"])
        if token:
            message.add_authentication_token((await client.post("/api/stub-login")).json()["token"])
        response = await client.post(f"/api/runs/{run_id}/nlip", json=message.to_dict())
        exported = (await client.get(f"/api/runs/{run_id}/export")).json()
    return response, exported["events"]


def by_type(events, kind, point=None):
    return [e for e in events if e["type"] == kind and (point is None or e.get("point") == point)]


ATTACK = {"task_id": "user_task_33", "scenario": "tool_poisoning", "goal_id": "injection_task_4"}


def test_attack_succeeds_with_the_guard_off() -> None:
    response, events = run(demo_run({**ATTACK, "guard": "off"}))
    assert response.status_code == 200
    assert not by_type(events, "guard")  # no guard, no guard events
    sent = [e for e in by_type(events, "tool_executed") if e["tool"] == "send_email"]
    assert any(ATTACKER in e["arguments"]["recipients"] for e in sent)
    (outcome,) = by_type(events, "outcome")
    assert outcome["attack_success"] is True


def test_catalog_check_strips_the_poison_with_the_guard_on() -> None:
    response, events = run(demo_run({**ATTACK, "guard": "on"}))
    assert response.status_code == 200
    (catalog,) = by_type(events, "guard", "catalog")
    assert {c["tool"] for c in catalog["changed_tools"]} == set(by_type(events, "run")[0]["poisoned_descriptions"])
    assert ATTACKER in catalog["planted"]
    assert by_type(events, "ingress")[0]["user"] == USER
    executed = by_type(events, "tool_executed")
    assert all(ATTACKER not in str(e["arguments"]) for e in executed)
    (outcome,) = by_type(events, "outcome")
    assert outcome == {**outcome, "utility": True, "attack_success": False}


def test_call_level_guard_blocks_the_hijacked_call() -> None:
    _, events = run(demo_run({**ATTACK, "guard": "hybrid_no_catalog"}))
    blocked = [e for e in by_type(events, "guard", "pre_tool") if e["action"] == "block"]
    assert blocked and blocked[0]["tool"] == "send_email" and ATTACKER in str(blocked[0]["arguments"])
    assert blocked[0]["call_id"] not in {e["call_id"] for e in by_type(events, "tool_executed")}
    assert by_type(events, "outcome")[0]["attack_success"] is False


def test_injected_content_is_redacted_after_the_tool_runs() -> None:
    _, events = run(demo_run({**ATTACK, "scenario": "important_instructions", "guard": "on"}))
    redacted = [e for e in by_type(events, "guard", "post_tool") if e["action"] == "replace"]
    assert redacted and redacted[0]["details"]["flagged"]
    assert by_type(events, "outcome")[0]["attack_success"] is False


def test_unsigned_request_is_rejected_before_the_agent_runs() -> None:
    response, events = run(demo_run({**ATTACK, "guard": "on"}, token=False))
    assert response.status_code == 403
    (rejected,) = by_type(events, "rejected")
    assert "no sign-in token" in rejected["detail"]
    assert not by_type(events, "tool_executed") and not by_type(events, "outcome")


def test_bad_specs_and_live_only_routes() -> None:
    async def scenario():
        offline = httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(offline=True)), base_url="http://d")
        live = httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(offline=False)), base_url="http://d")
        async with offline, live:
            assert (await offline.post("/api/runs", json={"scenario": "nope"})).status_code == 400
            free_text = await offline.post("/api/runs", json={"task_id": "", "prompt": "hi", "scenario": "benign"})
            assert free_text.status_code == 400 and "preset" in free_text.json()["detail"]
            assert (await offline.get("/api/options")).json()["signin"]["provider"] == "stub"
            # The token-minting endpoint must not exist when real sign-in is in use.
            assert (await live.post("/api/stub-login")).status_code in (404, 405)
            assert (await live.get("/api/options")).json()["signin"]["provider"] == "google"
            assert (await offline.get("/")).status_code == 200
            assert (await offline.get("/how")).status_code == 200
            assert (await offline.get("/checks")).status_code == 200

    run(scenario())


def test_event_stream_replays_and_waits() -> None:
    from demo.runs import RunManager, RunSpec

    async def scenario():
        manager = RunManager(offline=True)
        demo = await manager.create(RunSpec(scenario="benign", guard="on", task_id="user_task_33"))
        stream = demo.stream()
        first = await anext(stream)
        assert first["type"] == "run" and first["seq"] == 0
        pending = asyncio.ensure_future(anext(stream))
        await asyncio.sleep(0.05)
        assert not pending.done()  # waits for the next event
        demo.emit({"type": "reply", "text": "hi"})
        assert (await asyncio.wait_for(pending, 1))["type"] == "reply"
        await demo.close()

    run(scenario())


@pytest.mark.parametrize("task_id", ["user_task_24", "user_task_9", "user_task_1", "user_task_13", "user_task_15", "user_task_22", "user_task_25", "user_task_33", "user_task_37"])
def test_preset_tasks_complete_offline_with_the_guard_on(task_id) -> None:
    _, events = run(demo_run({"task_id": task_id, "scenario": "benign", "guard": "on"}))
    assert by_type(events, "outcome")[0]["utility"] is True
    assert not [e for e in by_type(events, "guard", "pre_tool") if e["action"] == "block"]


def test_preview_shows_exactly_what_the_attack_changes() -> None:
    async def scenario():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(offline=True)), base_url="http://d") as client:
            tools = (await client.post("/api/preview", json={"task_id": "user_task_24", "scenario": "tool_poisoning", "goal_id": "injection_task_0"})).json()
            data = (await client.post("/api/preview", json={"task_id": "user_task_24", "scenario": "important_instructions", "goal_id": "injection_task_0"})).json()
            benign = (await client.post("/api/preview", json={"task_id": "user_task_24", "scenario": "benign"})).json()
        return tools, data, benign

    tools, data, benign = run(scenario())
    (tool,) = tools["tools"]
    assert tool["tool"] == "get_unread_emails" and tool["poisoned"].startswith(tool["original"])
    assert ATTACKER in tool["poisoned"] and ATTACKER not in tool["original"] and not tools["data"]
    assert data["data"] and all(ATTACKER in d["after"] and ATTACKER not in d["before"] for d in data["data"])
    assert {d["label"] for d in data["data"]} == {"Email · events", "Email · facebook"}
    assert benign == {"tools": [], "data": []}
