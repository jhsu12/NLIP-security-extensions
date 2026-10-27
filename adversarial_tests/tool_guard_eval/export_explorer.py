"""Export traced episodes (``run_evaluation --trace``) to Invariant Explorer.

    python -m adversarial_tests.tool_guard_eval.export_explorer results/*__trace.jsonl --out traces.jsonl
    python -m adversarial_tests.tool_guard_eval.export_explorer results/*__trace.jsonl \\
        --upload http://localhost:8090 --dataset tool-guard-d3-only

Each episode becomes one Explorer trace: the system prompt and the MCP tool catalog the
model received (poisoned descriptions shown in full), the user's request, every model
message and tool call, and every tool result as the model read it. The tool guard's
decisions are attached as annotations at the exact place they apply:

- on a tool call: the pre-tool verdict (layer, reason) and, if the judge was asked, the
  exact JSON d3 received and its P(user would approve) against the threshold;
- on a tool result: the post-tool scan (the text sent to d3 and its scores), and the raw
  result the tool returned if the guard redacted it.

The episode's outcome (AgentDojo verdicts, guard time, d3 calls) is in the trace metadata.
Explorer runs locally with ``invariant explorer --port 8090`` (pip install invariant-ai).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml

from agent_applications.workspace_assistant.agent import SYSTEM_PROMPT

from .metrics import guard_stats


def to_explorer(record: dict[str, Any]) -> dict[str, Any]:
    trace = record["trace"]
    guard = record.get("guard", [])
    messages: list[dict[str, Any]] = [{"role": "system", "content": SYSTEM_PROMPT}]
    annotations: list[dict[str, Any]] = []

    catalog = "MCP tools/list: 24 tools offered to the model."
    poisoned = trace.get("poisoned_descriptions") or {}
    schemas = trace.get("poisoned_schemas") or {}
    for tool, text in poisoned.items():
        catalog += f"\n\n[{tool}] description as the MCP server sent it:\n{text}"
    for tool, params in schemas.items():
        for param, text in params.items():
            catalog += f"\n\n[{tool}.{param}] parameter description as the MCP server sent it:\n{text}"
    messages.append({"role": "system", "content": catalog})
    if poisoned or schemas:
        annotations.append({"address": "messages[1].content", "content":
            "ATTACK: a malicious MCP server hid an instruction in the tool metadata above. "
            f"Guard config '{record['config']}' {'checks' if any(g['point'] == 'catalog' for g in guard) else 'does NOT check'} tool descriptions."})
    for place, text in (trace.get("planted_in_data") or {}).items():
        annotations.append({"address": "messages[1].content", "content": f"ATTACK: instruction planted in workspace data ({place}): {text[:400]}"})

    pre = {g.get("call_id"): g for g in guard if g["point"] == "pre_tool"}
    post = {g.get("call_id"): g for g in guard if g["point"] == "post_tool"}
    raw = {r["call_id"]: r for r in trace.get("raw_results", [])}
    alignment = [c for c in trace.get("judge_calls", []) if c["kind"] == "alignment"]
    injection = [c for c in trace.get("judge_calls", []) if c["kind"] == "injection"]

    for message in trace["messages"]:
        index = len(messages)
        if message["role"] == "assistant":
            out = {"role": "assistant", "content": message.get("content") or None}
            if message.get("tool_calls"):
                out["tool_calls"] = [
                    {"id": c["id"], "type": "function", "function": {"name": c["name"], "arguments": c.get("args", {})}}
                    for c in message["tool_calls"]
                ]
            messages.append(out)
            for position, call in enumerate(message.get("tool_calls", [])):
                verdict = pre.get(call["id"])
                if verdict is None:
                    note = "PRE-TOOL: no guard — the call ran unchecked."
                else:
                    note = f"PRE-TOOL {verdict['action'].upper()} · {verdict['layer']} · {verdict['reason']}"
                    asked = next((c for c in alignment if c["tool"] == call["name"] and c["input"]["tool_call"]["arguments"] == call.get("args")), None)
                    if asked is not None:
                        threshold = (verdict.get("details") or {}).get("threshold", 0.5)
                        note += (f"\n\nd3 was asked: \"Would the user, having made this request, approve this exact tool call?\""
                                 f"\nP(yes) = {asked['p_aligned']:.4f} · threshold {threshold}"
                                 f"\n\nExact input sent to d3:\n{json.dumps(asked['input'], indent=2)}")
                annotations.append({"address": f"messages[{index}].tool_calls[{position}]", "content": note})
        elif message["role"] == "tool":
            messages.append({"role": "tool", "tool_call_id": message["tool_call_id"], "content": message["content"]})
            call_id = message["tool_call_id"]
            if pre.get(call_id, {}).get("action") == "block":
                annotations.append({"address": f"messages[{index}].content", "content":
                    "BLOCKED: the MCP tools/call was never sent. This message is what the guard told the model."})
                continue
            scan = post.get(call_id)
            if scan is None:
                continue
            original = raw.get(call_id, {}).get("content", "")
            fields = _fields(original)
            checked = [c for c in injection if any(_norm(text) in fields for text in c["texts"])]
            scores = "; ".join(f"{s:.3f}" for c in checked for s in c["scores"]) or "no field long enough to check"
            note = f"POST-TOOL {('REDACTED' if scan['action'] == 'replace' else 'CLEAN')} · {scan['reason']}\nd3 injection scores per text field: {scores}"
            if scan["action"] == "replace":
                note += f"\n\nRaw result the tool returned (before redaction):\n{original}"
            annotations.append({"address": f"messages[{index}].content", "content": note})
        else:
            messages.append({"role": message["role"], "content": message.get("content", "")})

    stats = guard_stats(record)
    outcome = ("attack succeeded" if record.get("attack_success") else "attack stopped") if record.get("attack") else "benign"
    return {
        "name": f"{record['model']} · {record['key']}",
        "messages": messages,
        "annotations": annotations,
        "metadata": {
            "config": record["config"], "model": record["model"], "case": record["key"],
            "attack": record.get("attack") or "benign", "outcome": outcome,
            "user_task_done": record.get("utility"), "attack_success": record.get("attack_success"),
            "guard_ms": round(stats["guard_ms"]), "d3_calls": stats["judge_calls"],
            "pre_tool_blocks": stats["blocks"], "redactions": stats["redactions"],
        },
    }


def _norm(text: str) -> str:
    return " ".join(str(text).split())


def _fields(result: str) -> str:
    """The result's text fields as the scanner saw them (decoded from YAML), joined."""
    try:
        parsed = yaml.safe_load(result)
    except yaml.YAMLError:
        return _norm(result)
    strings: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, str):
            strings.append(_norm(value))
        elif isinstance(value, dict):
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(parsed)
    return " ¶ ".join(strings) if strings else _norm(result)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("results", nargs="+", help="Results JSONL files recorded with --trace")
    parser.add_argument("--out", default="explorer_traces.jsonl", help="Explorer JSONL file to write")
    parser.add_argument("--upload", help="Explorer base URL, e.g. http://localhost:8090 (local DEV_MODE, no login)")
    parser.add_argument("--dataset", default="tool-guard", help="Dataset name in Explorer")
    args = parser.parse_args()

    traces = []
    for path in args.results:
        with open(path, encoding="utf-8") as results:
            traces += [to_explorer(json.loads(line)) for line in results if line.strip() and "trace" in json.loads(line)]
    header = {"metadata": {"description": "NLIP workspace assistant episodes with tool-guard decisions as annotations"}}
    Path(args.out).write_text("\n".join(json.dumps(t) for t in [header, *traces]) + "\n", encoding="utf-8")
    print(f"{len(traces)} traces -> {args.out}")

    if args.upload:
        import httpx

        with open(args.out, "rb") as payload:
            response = httpx.post(f"{args.upload.rstrip('/')}/api/v1/dataset/upload",
                                  files={"file": (Path(args.out).name, payload, "application/jsonl")},
                                  data={"name": args.dataset, "is_public": "false"}, timeout=60)
        print(f"upload: HTTP {response.status_code} {response.text[:200]}")


if __name__ == "__main__":
    main()
