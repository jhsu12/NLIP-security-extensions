"""Summarize evaluation results into the paper's metrics.

    python -m adversarial_tests.tool_guard_eval.metrics results/*.jsonl
    python -m adversarial_tests.tool_guard_eval.metrics results/*.jsonl --by-attack --csv summary.csv

Per (config, model):
  benign utility        user tasks solved with no attack present
  utility under attack  user tasks solved while an attack was planted
  ASR                   attack success rate: attacker goal achieved (from backend state)
  false-block rate      benign episodes in which the guard blocked at least one call
  guard ms / episode    time spent inside the guard (judge calls included)
  judge calls, tokens   per episode, from the guard's audit records
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from statistics import mean, median
from typing import Any


def load(paths: list[str]) -> list[dict[str, Any]]:
    """One record per (config, model, episode): the latest run, preferring one without errors."""
    latest: dict[tuple, dict[str, Any]] = {}
    for path in paths:
        with Path(path).open(encoding="utf-8") as results:
            for line in results:
                if not line.strip():
                    continue
                record = json.loads(line)
                key = (record["config"], record["model"], record["key"])
                previous = latest.get(key)
                if previous is None or record.get("error") is None or previous.get("error") is not None:
                    latest[key] = record
    return list(latest.values())


def guard_stats(record: dict[str, Any]) -> dict[str, float]:
    audit = [entry for entry in record.get("guard", []) if entry.get("point") in ("pre_tool", "post_tool", "catalog")]
    return {
        "blocks": sum(1 for entry in audit if entry["point"] == "pre_tool" and entry["action"] == "block"),
        "redactions": sum(1 for entry in audit if entry["point"] == "post_tool" and entry["action"] == "replace"),
        "catalog_changes": sum(len(entry.get("tools", {})) for entry in audit if entry["point"] == "catalog"),
        "guard_ms": sum(entry.get("latency_ms", 0.0) for entry in audit),
        "judge_calls": sum(entry.get("judge_calls", 0) for entry in audit),
        "judge_tokens": sum(entry.get("judge_tokens", 0) for entry in audit),
    }


def rate(values: list[bool]) -> str:
    return f"{100 * sum(values) / len(values):.1f}% ({sum(values)}/{len(values)})" if values else "-"


def summarize(records: list[dict[str, Any]], by_attack: bool) -> list[dict[str, Any]]:
    groups: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        key = (record["config"], record["model"]) + ((record.get("attack") or "benign",) if by_attack else ())
        groups[key].append(record)

    rows = []
    for key, all_records in sorted(groups.items()):
        # Infrastructure errors (rate limits, proxy failures) are reported, not scored.
        group = [r for r in all_records if not r.get("error")] or all_records
        benign = [r for r in group if not r.get("attack")]
        attacked = [r for r in group if r.get("attack")]
        stats = [guard_stats(r) for r in group]
        rows.append(
            {
                "config": key[0],
                "model": key[1],
                **({"attack": key[2]} if by_attack else {}),
                "episodes": len(group),
                "errors": sum(1 for r in all_records if r.get("error")),
                "benign_utility": rate([r["utility"] for r in benign]),
                "utility_under_attack": rate([r["utility"] for r in attacked]),
                "ASR": rate([bool(r["attack_success"]) for r in attacked if r["attack_success"] is not None]),
                "false_block_rate": rate([guard_stats(r)["blocks"] > 0 for r in benign]),
                "guard_ms_median": f"{median(s['guard_ms'] for s in stats):.0f}" if stats else "-",
                "judge_calls_mean": f"{mean(s['judge_calls'] for s in stats):.1f}" if stats else "-",
                "judge_tokens_mean": f"{mean(s['judge_tokens'] for s in stats):.0f}" if stats else "-",
                "agent_tokens_mean": f"{mean(r.get('agent_tokens', 0) for r in group):.0f}",
                "wall_s_median": f"{median(r.get('wall_s', 0) for r in group):.1f}",
            }
        )
    return rows


def markdown(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "(no results)"
    headers = list(rows[0])
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(str(row[h]) for h in headers) + " |" for row in rows]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("results", nargs="+", help="Results JSONL files")
    parser.add_argument("--by-attack", action="store_true", help="Break rows down by attack type")
    parser.add_argument("--csv", help="Also write the table to this CSV file")
    args = parser.parse_args()

    rows = summarize(load(args.results), args.by_attack)
    print(markdown(rows))
    if args.csv and rows:
        with open(args.csv, "w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)


if __name__ == "__main__":
    main()
