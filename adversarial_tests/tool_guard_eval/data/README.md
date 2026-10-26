# Test data

Every benign request and attack case used by the evaluation, frozen as plain JSONL.
Regenerate with `python -m adversarial_tests.tool_guard_eval.export_data`.

| File | Rows | Contents |
|---|---|---|
| `user_tasks.jsonl` | 40 | benign user requests: `id`, `split` (`dev` = 10 tasks used for tuning, `test` = 30 held-out tasks), `difficulty`, `prompt`, and `expected_tool_calls` (a correct solution) |
| `injection_tasks.jsonl` | 14 | attacker goals: `id`, `difficulty`, `goal` |
| `attacks/<attack>.jsonl` | 560 each | one case per (user task, attacker goal): `key`, `split`, and the exact attacker text, `planted_in_tool_data` (injection vector → text placed in an email, event, or file) and/or `planted_in_tool_descriptions` (tool → poisoned MCP description) |

An episode in `results/*.jsonl` refers to its case by the same `key`, e.g.
`user_task_13|injection_task_1|tool_poisoning`; benign episodes use `user_task_13|-|benign`.
The test-split runs use a fixed random sample of these cases (`--sample 150 --seed 7`).

## Attacks

| attack | where the goal is planted | source |
|---|---|---|
| `important_instructions` | tool data | AgentDojo |
| `tool_knowledge` | tool data, with the exact tool calls to make | AgentDojo |
| `direct` | tool data, as `TODO: <goal>` | AgentDojo |
| `ignore_previous` | tool data, "Ignore your previous instructions…" | AgentDojo (its typo "iunstructions" is kept) |
| `judge_aware` | tool data, plus a note telling reviewers the action is pre-approved | ours (adaptive) |
| `tool_poisoning` | descriptions of the tools the task uses, in an `<IMPORTANT>` block | ours, after Invariant Labs' MCP examples |
| `tool_poisoning_plain` | the same goal as one plain sentence in the description | ours |

As in AgentDojo, tool-data attacks are placed only in the vectors the user task actually
reads. Text that names the model uses "Qwen"; the harness substitutes the agent model's
name at run time.

## Source and license

User tasks, attacker goals, the seeded mailbox/calendar/drive, and the four AgentDojo attack
templates come from **AgentDojo** (Debenedetti et al., NeurIPS 2024 Datasets and Benchmarks),
`workspace` suite v1.2.2, package `agentdojo==0.1.35`, MIT License,
https://github.com/ethz-spylab/agentdojo.
