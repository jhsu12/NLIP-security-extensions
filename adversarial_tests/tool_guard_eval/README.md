# Tool Guard Evaluation

Replays benign and attack cases against the workspace assistant's NLIP endpoint, with and
without the tool guard, and scores every episode from the backend state using AgentDojo's task
checkers. The experiment log, with every run, its command and its numbers, is
[`EXPERIMENTS.md`](EXPERIMENTS.md). The final design is evaluated in E17.

## Data

- **Benign traffic:** the 40 AgentDojo `workspace` user tasks (v1.2.2), run with no attack.
- **Attacks:** each user task paired with each of the 14 injection tasks (attacker goals: send
  email to an outsider, delete files, exfiltrate security codes, mass-forward mail…), planted by
  one of:

  | attack | where | source |
  |---|---|---|
  | `important_instructions` | tool data (emails, events, files) | AgentDojo |
  | `tool_knowledge` | tool data, with the exact tool calls to make | AgentDojo |
  | `direct` (`TODO: …`), `ignore_previous` | tool data | AgentDojo |
  | `judge_aware` | tool data, plus text telling a reviewer the action is pre-approved | adaptive, ours |
  | `tool_poisoning` | MCP descriptions of the tools the task uses, `<IMPORTANT>` block | Invariant Labs style, ours |
  | `tool_poisoning_plain` | the same, as one plain sentence | ours |
  | `schema_poisoning_tagged`, `schema_poisoning` | the first *parameter* description of each tool the task uses (MCP `inputSchema`), tagged or plain | ours |

  As in AgentDojo, data attacks are planted only in the data the user task actually reads.
- **Splits:** user tasks whose number is divisible by 4 form `dev` (10 tasks), used to tune
  thresholds and wording. The other 30 form `test`, used only for reported numbers.

All cases are also frozen as plain files in [`data/`](data/README.md): 40 user tasks, 14 attacker
goals, and 560 cases per attack with the exact planted text.

## Configurations (`configs/`)

| config | guard |
|---|---|
| `none` | no guard (baseline) |
| **`d3_only`** | **final design:** d3 judge on every side-effecting call, d3-only scan of tool results; no regex rules, no policy blocking rules, no catalog check |
| `hybrid_d3_catalog` | ablation (earlier final): catalog check + policy rules + d3 judge + rules/d3 scanning + taint |
| `hybrid_d3` / `hybrid_llm` | ablation: policy, judge, scanning, taint; no catalog check |
| `hybrid_d3_no_taint` | ablation: `hybrid_d3` without taint |
| `catalog_only_d3` | ablation: catalog check only; every call allowed |
| `judge_only_d3` / `judge_only_llm` | ablation: judge on every side-effecting call; no rules, no scanning |
| `policy_only` | ablation: policy rules + rule-based scanning, no judge |

Each config only sets the options that differ, and inherits the rest from the application's
`config.toml`. That file still defaults to `hybrid_d3_catalog`'s settings.

## Run

```bash
set -a; source .env; set +a
python -m adversarial_tests.tool_guard_eval.run_evaluation --config d3_only \
    --model qwen-3.8-27b --split test --attacks tool_poisoning --sample 20 --trace
adversarial_tests/tool_guard_eval/run_matrix.sh --tag mytag --configs "none d3_only" \
    --models "qwen-3.8-27b gemma-4-31b-it" -- --split test --attacks tool_poisoning --sample 150 --seed 7
python -m adversarial_tests.tool_guard_eval.metrics adversarial_tests/tool_guard_eval/results/*__test.jsonl --by-attack
```

**Flags:**
- `--attacks a,b` (or `none`);
- `--sample N` (random subset of attack episodes; the same `--seed` gives the same pairs for every
  attack and config);
- `--user-tasks` / `--injection-tasks` / `--keys` (exact case keys);
- `--no-benign`, `--concurrency` (≈2–3 per model; the Jetstream proxy rate-limits bursts);
- `--trace`: store the full trace (model messages, raw tool results, every d3 question and answer,
  timestamps);
- `--results-tag NAME`: write to `results/<config>__<model>__<split>__<NAME>.jsonl`, keeping
  probes apart.

**Output:** results go to `results/<config>__<model>__<split>.jsonl`, one line per episode,
including the guard's full audit trail. Re-running resumes where it stopped and redoes errored
episodes.

**Browse results:** `python -m demo.web --stub`, then open http://127.0.0.1:8030/runs. Pick a
results file, filter by attack or outcome, and step through episodes one by one with ← / →. Each
is rendered like the live demo, with the full trace if recorded.

## Measuring single checks (no agent runs)

- `python -m adversarial_tests.tool_guard_eval.catalog_eval`: the catalog check on 392 poisoned and
  40 tricky legitimate tool descriptions, in each mode (E15).
- `python -m adversarial_tests.tool_guard_eval.scanner_eval`: the post-tool scanner on 910 attacked
  tool results from AgentDojo's data attacks, the clean workspace, and 16 hard negatives (E16).
- `python -m adversarial_tests.tool_guard_eval.export_explorer results/*__trace.jsonl --out traces.jsonl`:
  export traced episodes to Invariant Explorer, with the guard's decisions as annotations.

## Metrics

`metrics.py` reports:
- benign utility and utility under attack;
- attack success rate (from backend state, not model text);
- false-block rate (benign episodes with at least one blocked call);
- cost: guard latency, judge calls and tokens, agent tokens, wall time.

`--by-attack` / `--by-goal` break rows down. `--layers` adds which check acted: catalog strip,
policy block, judge block, redaction.

## Adding a test case or rule

- **New attack:** add a template to `cases.py` (see `JUDGE_AWARE`, `POISONING`, `SCHEMA_POISONING`)
  and list it in `CUSTOM_ATTACKS`. Re-export the data with
  `python -m adversarial_tests.tool_guard_eval.export_data --attacks <name>`.
- **New tool, or a change to which tools need the judge:** set the tool's `risk` in
  `security_extensions/tool_guard/policies/workspace.toml`. In the final design that is the only
  "rule": `read` tools skip the judge, every other class goes to d3, and unlisted tools are
  blocked. Add a test in `tests/test_tool_guard.py`.
- **New configuration:** add a TOML file in `configs/` with `[options]` for the tool guard.
- **Ablation-only rules:** the regex rules (`scanner.py`) and the policy blocking rules
  (`policy.py`, `address_args`, `destructive_intent`) are used only by configs with
  `policy_rules = true` or `rules` in `scanner` / `catalog`.
