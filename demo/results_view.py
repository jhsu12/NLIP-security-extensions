"""Browse saved evaluation episodes in the web page (``/runs``), one by one.

Each episode in ``adversarial_tests/tool_guard_eval/results/*.jsonl`` is turned into the
same event stream the live demo receives (run setup, sign-in, guard decisions, model
responses, d3 questions, raw tool results, reply, AgentDojo outcome), merged in recorded
time order, so the page renders it exactly like a live run. Episodes recorded with
``run_evaluation --trace`` show the full trace; older ones show the guard's decisions.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from adversarial_tests.tool_guard_eval.export_explorer import _fields, _norm
from adversarial_tests.tool_guard_eval.run_evaluation import RESULTS_DIR

from .checks import check_details
from .runs import GUARDS, SCENARIOS, RunManager

OUTCOMES = ("attack succeeded", "attack stopped by guard", "model ignored attack",
            "benign: task done", "benign: task failed", "benign: false block", "error")


class ResultsBrowser:
    def __init__(self, manager: RunManager, results_dir: Path = RESULTS_DIR) -> None:
        self.manager = manager
        self.dir = results_dir
        self._cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}

    # --- files and episodes -------------------------------------------------------------------

    def files(self) -> list[dict[str, Any]]:
        out = []
        for path in sorted(self.dir.glob("*.jsonl")):
            parts = path.stem.split("__")
            if len(parts) < 3:  # e.g. catalog_eval__judge.jsonl is not an episode file
                continue
            records = self._records(path.name)
            out.append({"name": path.name, "config": parts[0], "model": parts[1], "split": parts[2],
                        "tag": parts[3] if len(parts) > 3 else "", "episodes": len(records),
                        "traced": sum(1 for r in records if "trace" in r)})
        return out

    def episodes(self, name: str) -> list[dict[str, Any]]:
        rows = []
        for record in self._records(name):
            guard = record.get("guard", [])
            blocks = sum(1 for g in guard if g["point"] == "pre_tool" and g["action"] == "block")
            redactions = sum(1 for g in guard if g["point"] == "post_tool" and g["action"] == "replace")
            rows.append({
                "key": record["key"], "user_task": record["user_task"], "goal": record.get("injection_task"),
                "attack": record.get("attack") or "benign", "outcome": outcome(record, blocks, redactions),
                "task_done": bool(record.get("utility")), "blocks": blocks, "redactions": redactions,
                "judge_calls": sum(g.get("judge_calls", 0) for g in guard),
                "guard_ms": round(sum(g.get("latency_ms", 0) for g in guard)), "wall_s": record.get("wall_s"),
                "traced": "trace" in record,
            })
        return rows

    def events(self, name: str, key: str) -> list[dict[str, Any]]:
        record = next((r for r in self._records(name) if r["key"] == key), None)
        if record is None:
            raise KeyError(key)
        return to_events(record, self.manager)

    def _records(self, name: str) -> list[dict[str, Any]]:
        path = self.dir / name
        if path.parent != self.dir or not path.is_file() or path.suffix != ".jsonl":
            raise KeyError(name)
        mtime = path.stat().st_mtime
        cached = self._cache.get(name)
        if cached is None or cached[0] != mtime:
            # Latest record per episode, preferring one without an infrastructure error.
            latest: dict[str, dict[str, Any]] = {}
            with path.open(encoding="utf-8") as lines:
                for line in lines:
                    if line.strip():
                        record = json.loads(line)
                        previous = latest.get(record["key"])
                        if previous is None or not record.get("error") or previous.get("error"):
                            latest[record["key"]] = record
            cached = (mtime, list(latest.values()))
            self._cache[name] = cached
        return cached[1]


def outcome(record: dict[str, Any], blocks: int, redactions: int) -> str:
    if record.get("error"):
        return "error"
    if not record.get("attack"):
        if blocks:
            return "benign: false block"
        return "benign: task done" if record.get("utility") else "benign: task failed"
    if record.get("attack_success"):
        return "attack succeeded"
    return "attack stopped by guard" if (blocks or redactions) else "model ignored attack"


def to_events(record: dict[str, Any], manager: RunManager) -> list[dict[str, Any]]:
    """The live demo's event stream for one saved episode, in recorded order."""
    suite = manager.suite
    trace = record.get("trace") or {}
    task = suite.get_user_task_by_id(record["user_task"])
    goal = suite.get_injection_task_by_id(record["injection_task"]) if record.get("injection_task") else None
    guard_key = next((k for k, (config, _) in GUARDS.items() if config == record["config"]), record["config"])
    descriptions = trace.get("poisoned_descriptions") or {}
    schemas = trace.get("poisoned_schemas") or {}
    injections = trace.get("planted_in_data") or {}
    events: list[dict[str, Any]] = [{
        "type": "run", "scenario": record.get("attack") or "benign",
        "scenario_label": SCENARIOS.get(record.get("attack") or "benign", record.get("attack") or "benign"),
        "guard": "off" if record["config"] == "none" else guard_key, "guard_label": f"{record['config']} · {record['model']}",
        "config": record["config"], "offline": False, "task_id": record["user_task"], "prompt": task.PROMPT,
        "goal_id": record.get("injection_task"), "goal": goal.GOAL if goal else None,
        "poisoned_descriptions": descriptions, "injections": injections,
        "changes": manager._changes(injections, descriptions, schemas), "key": record["key"],
    }]
    timeline: list[tuple[float, dict[str, Any]]] = []
    guard = record.get("guard", [])
    ingress = next((g for g in guard if g["point"] == "ingress"), None)
    start = min([g["ts"] for g in guard if "ts" in g] + [e["ts"] for e in trace.get("model_responses", []) if "ts" in e] or [0.0])
    events.append({"type": "ingress", "user": (ingress or {}).get("user_id"), "text": (ingress or {}).get("user_text") or task.PROMPT})
    for g in guard:
        if g["point"] in ("ingress", "egress"):
            continue
        event = {"type": "guard", **g}
        if g["point"] == "catalog":
            changed = g.get("tools") or {}
            event["total_tools"] = len(suite.tools)
            event["changed_tools"] = [{"tool": t, "original": descriptions.get(t, ""), "shown": "[sanitized]"} for t in changed]
            event["planted"] = []
        timeline.append((g.get("ts", start), event))
    anchor = _Anchors(guard, trace.get("raw_results", []), start)
    for e in trace.get("model_responses", []):
        timeline.append((e.get("ts", start), {"type": "trace", **e}))
    for e in trace.get("judge_calls", []):
        timeline.append((e["ts"] if "ts" in e else anchor.judge(e), {"type": "trace", **e}))
    for e in trace.get("raw_results", []):
        timeline.append((e["ts"] if "ts" in e else anchor.raw(e), {"type": "tool_executed", "tool": e["tool"], "call_id": e["call_id"],
                                                                     "arguments": e.get("args"), "result": e["content"]}))
    timeline.sort(key=lambda item: item[0])
    events += [{**event, "t": round(ts - start, 3)} for ts, event in timeline]
    reply = next((m.get("content") for m in reversed(trace.get("messages", [])) if m["role"] == "assistant" and m.get("content")),
                 record.get("output", ""))
    events.append({"type": "reply", "text": reply, "t": record.get("wall_s")})
    # Saved episodes don't keep the account state, so the pop-up shows the checker without a diff.
    checks = {"utility": check_details(task), "attack": check_details(goal) if goal else None}
    events.append({"type": "outcome", "utility": record.get("utility"), "attack_success": record.get("attack_success"),
                   "executed": record.get("executed", []), "checks": checks, "changes": None, "reply": reply,
                   "t": record.get("wall_s")})
    for seq, event in enumerate(events):
        event["seq"] = seq
    return events


class _Anchors:
    """Place trace events recorded without timestamps (older traces) next to their guard records."""

    def __init__(self, guard: list[dict[str, Any]], raw_results: list[dict[str, Any]], start: float) -> None:
        self.pre = {g.get("call_id"): g for g in guard if g["point"] == "pre_tool"}
        self.post = {g.get("call_id"): g for g in guard if g["point"] == "post_tool"}
        self.raw_results = raw_results
        self.start = start

    def raw(self, e: dict[str, Any]) -> float:
        pre, post = self.pre.get(e["call_id"]), self.post.get(e["call_id"])
        return pre["ts"] + 1e-3 if pre else post["ts"] - 2e-3 if post else self.start

    def judge(self, e: dict[str, Any]) -> float:
        if e["kind"] == "alignment":
            for pre in self.pre.values():
                if pre.get("tool") == e["tool"] and pre.get("arguments") == e["input"]["tool_call"]["arguments"]:
                    return pre["ts"] - 1e-3
            return self.start
        for raw in self.raw_results:  # injection check: the result whose fields it scanned
            fields = _fields(raw["content"])
            if any(_norm(text) in fields for text in e["texts"]) and raw["call_id"] in self.post:
                return self.post[raw["call_id"]]["ts"] - 1e-3
        return self.start  # e.g. tool descriptions at session start
