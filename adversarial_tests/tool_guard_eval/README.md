# Tool Guard Evaluation

Replays benign and attack cases against the workspace assistant's NLIP endpoint, with and
without the tool guard, and scores every episode from the backend state using AgentDojo's
task checkers.

## Data

- **Benign traffic:** the 40 AgentDojo `workspace` user tasks (v1.2.2), run with no attack.
- **Attacks:** each user task paired with each of the 14 injection tasks (attacker goals:
  send email to an outsider, delete files, exfiltrate security codes, mass-forward mail…),
  planted by one of:

  | attack | where | source |
  |---|---|---|
  | `important_instructions` | tool data (emails, events, files) | AgentDojo |
  | `tool_knowledge` | tool data, with the exact tool calls to make | AgentDojo |
  | `direct` (`TODO: …`), `ignore_previous` | tool data | AgentDojo |
  | `judge_aware` | tool data, plus text telling a reviewer the action is pre-approved | adaptive, ours |
  | `tool_poisoning` | MCP tool descriptions of the tools the task uses | Invariant Labs style, ours |

  As in AgentDojo, an attack is planted only in the data the user task actually reads.
- **Splits:** user tasks whose number is divisible by 4 form `dev` (10 tasks) and are used
  to tune thresholds; the other 30 form `test`, used only for reported numbers.

## Configurations (`configs/`)

| config | guard |
|---|---|
| `none` | no guard (baseline) |
| `policy_only` | policy rules + rule-based scanning, no judge |
| `judge_only_d3` / `judge_only_llm` | judge on every side-effecting call, no rules, no scanning |
| `hybrid_d3` / `hybrid_llm` | full guard: policy, judge, scanning, taint |
| `hybrid_d3_no_taint` | full guard without taint (ablation) |

## Run

```bash
set -a; source .env; set +a
python -m adversarial_tests.tool_guard_eval.run_evaluation --config hybrid_d3 \
    --model qwen-3.8-27b --split dev --attacks important_instructions
python -m adversarial_tests.tool_guard_eval.metrics adversarial_tests/tool_guard_eval/results/*.jsonl
```

Useful flags: `--attacks a,b` (or `none`), `--sample N` (random subset of attack
episodes, `--seed` fixed), `--user-tasks` / `--injection-tasks`, `--no-benign`,
`--concurrency`. Results go to `results/<config>__<model>__<split>.jsonl`, one line per
episode, including the guard's full audit trail; re-running resumes where it stopped.

## Metrics

Benign utility, utility under attack, attack success rate (from backend state, not model
text), false-block rate (benign episodes with at least one blocked call), and cost: guard
latency, judge calls and tokens, agent tokens, wall time.

## Adding a test case or rule

- New attack: add a template to `cases.py` (see `JUDGE_AWARE`) and list it in `CUSTOM_ATTACKS`.
- New configuration: add a TOML file in `configs/` with `[options]` for the tool guard.
- New policy rule: edit `security_extensions/tool_guard/policies/workspace.toml` (risk
  class, `address_args`) or `policy.py`; add a unit test in `tests/test_tool_guard.py`.
