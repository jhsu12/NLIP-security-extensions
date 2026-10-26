# CLAUDE.md: CS598 AI Security, Track 3 project

Context handoff for Claude sessions in this repo. Written 2026-10-25 at the end of the
session that built everything on branch `tool-guard`.

## The project

- Course: CS598 AI Security, **Track 3: agent security in the context of NLIP**. Solo.
  Deadline **2026-11-30 AoE**. Spec PDF: `../CS598-AISecurity/Track 3 updated (Aug. 26) (1).pdf`.
- Deliverable: one pluggable **Type-3 security function** at the **tool/model boundary**
  (invoked immediately before/after tool calls), in a realistic NLIP agent app, evaluated
  with and without the defense: effectiveness, false alarms, running cost, honest limits.
  The threat model is **already approved by the instructor**.
- This repo is the user's fork (`origin` = `jhsu12/NLIP-security-extensions`; `upstream` =
  instructor's `systemsecurity-uiuc/NLIP-security-extensions`). Work on branch `tool-guard`.
- `../CS598-AISecurity` is an old weather-agent prototype; no longer the build target.

### Grading points to keep in mind
- Application row (20%): realistic agentic app grounded in NLIP, and it **must support
  login through OAuth** (e.g. Google). Not done yet.
- Paper (5 pages, ACM two-column): threat model; cite **ECMA-434 Clause 7 SCOs** by subclause
  number and title (primary: §7.3.1 Prevention of Prompt Injection; check the others against
  the standard, since the exact numbers were never confirmed); why it matters for agents; design; fair test
  data; results; **what it does not catch**.
- Submission: repo with MIT license (fork is MIT), runnable function, test data, setup,
  reproduction steps for every number, how to add a rule/test case, and a demo that runs
  from a fresh copy (offline/stub mode or recorded run if Jetstream is unavailable).

## User preferences
- **Run experiments/evaluations in the background** (anything over ~1 min) so the user can
  keep discussing; report results when the job finishes.
- Commit/push only when the user agrees. Never print or commit API keys.

## Environment
- Python 3.13 venv at `.venv` (framework needs ≥3.11). Install: `pip install -e '.[workspace,test]'`.
- Secrets in `.env` (gitignored): `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `AGENT_MODEL`,
  `VSR_API_KEY`. Load with `set -a; source .env; set +a`.
- LLMs: **Jetstream Open WebUI proxy** `https://llm.jetstream-cloud.org/api` (works from
  anywhere with the key). Direct `/<model>/v1/` endpoints work only inside Jetstream's network.
  Agent models: **qwen-3.8-27b** (default) and **gemma-4-31b-it**. gpt-oss-120b was dropped
  (70–80 s per call).
- Judge: **vLLM-SR Decision API** (`https://decision.vllm-sr.ai/v1/systemone`), models
  `vllm-sr/d3-flash` (default) / `d3-turbo`. Returns calibrated P(yes) via `noul` questions.
  Max 8 extra `states` per request (the code batches 9 per request). Gemma is the alternative LLM judge.

## What exists (all committed on `tool-guard`)

- `agent_applications/workspace_assistant/`: NLIP email/calendar/drive assistant.
  Backend, tools, tasks and checkers come from **AgentDojo `workspace` v1.2.2** (24 tools; user
  Emma Johnson). Tools are served via an in-process **MCP** server (`mcp_server.py`); a LangChain
  `create_agent` (`agent.py`) has a model-call cap of 20 per turn; `nlip_agent.py` is the
  `NLIPServer` with one backend and agent per NLIP session. `config.toml` enables extensions.
- `security_extensions/tool_guard/`: **the security function**. See `WORKFLOW.md` (Mermaid).
  - `guard.py` `ToolGuard`: L0 validation (fail closed) → L1 `policy.py` (+ `policies/workspace.toml`:
    risk classes; block unknown tools, values planted in injected content, and deletes without user intent)
    → L2 `judges.py` (d3 / LLM / stub; "would the user approve this exact call?"; threshold
    0.5, 0.7 once tainted; evidence lines from earlier results) → L3 `scanner.py` (rules + d3,
    redacts the injected span, taints the session) → `catalog.py` (scans and pins MCP tool
    descriptions; strips poison before the model sees it; catalog findings record planted
    indicators but do **not** raise the threshold).
  - `nlip_extension.py`: NLIP ingress SE records the user's text as the trusted task (egress closes the turn).
  - `langchain_middleware.py`: `awrap_tool_call` adapter + `guard_tool_catalog`.
  - Enabled by listing `tool_guard` in `config.toml` ingress/egress; options under
    `[security_extensions.tool_guard.options]` (judge, threshold, scanner, catalog, catalog_judge, policy_rules, taint…).
- `adversarial_tests/tool_guard_eval/`: harness. `cases.py` (dev = user tasks with number
  divisible by 4, i.e. 10 tasks; test = the other 30; attacks: AgentDojo `important_instructions`, `tool_knowledge`,
  `direct`, `ignore_previous`; ours: `judge_aware`, `tool_poisoning` (`<IMPORTANT>` block in
  MCP descriptions), `tool_poisoning_plain` (plain sentence)), `run_evaluation.py` (replays
  via an in-memory ASGI NLIP client to `POST /nlip`; resumable; errored episodes re-run),
  `run_matrix.sh` (configs in sequence, models in parallel), `metrics.py`, `configs/*.toml`, `results/`.
- `tests/`: 28 offline tests (`pytest`, no network needed).

## Key findings so far (dev split)
- Data-channel injections barely work on these models even **without** the guard
  (`important_instructions`: 0% qwen / 0.8% gemma; other data attacks 0%).
- **MCP tool-description poisoning works**: ASR without guard 14.3% qwen / 25.0% gemma (tagged),
  2.9% / 6.4% (plain). This became the main threat evaluated.
- Every guard config → **0% ASR** on both poisoning variants.
  `policy_only` stops attacks but costs utility (10% benign false blocks, lower utility under attack).
  `hybrid_d3` ≈ 99% / 89% utility under attack; **`hybrid_d3_catalog` → 100% / 100%**, 0 false
  blocks, about 0.6 s guard time per episode (mostly the per-session catalog scan; could be cached).
- **Final config: `hybrid_d3_catalog`** (decided with the user on 2026-10-25): catalog check =
  prevention, call-level guard = backstop; the other configs are ablations.
- Judge wording ("approve") was tuned on dev: benign 0.80–0.98 vs attacks ≤0.03 on d3-flash.

**Full experiment history, results, failure analysis, and next steps:
`adversarial_tests/tool_guard_eval/EXPERIMENTS.md`. Keep it updated after every run.**
Known issue found in the test split: the guard reorders parallel side-effecting tool calls
(each waits on its own judge call), which fails order-sensitive AgentDojo checkers
(user_task_25). Planned fix: serialize guarded calls per session.

## Current state / next steps
- **Test-split run was launched** from the previous session (tag `test`; configs `none
  hybrid_d3_catalog policy_only judge_only_d3 hybrid_d3 catalog_only_d3`; both models;
  `--split test --attacks tool_poisoning,tool_poisoning_plain --sample 150 --seed 7`).
  It may have been stopped when that session ended. Check `results/logs/test_*.log` and
  `results/*__test.jsonl`; **re-running the same command resumes it**:
  ```bash
  adversarial_tests/tool_guard_eval/run_matrix.sh --tag test \
    --configs "none hybrid_d3_catalog policy_only judge_only_d3 hybrid_d3 catalog_only_d3" \
    --models "qwen-3.8-27b gemma-4-31b-it" -- --split test \
    --attacks tool_poisoning,tool_poisoning_plain --sample 150 --seed 7
  ```
  Then `python -m adversarial_tests.tool_guard_eval.metrics adversarial_tests/tool_guard_eval/results/*__test.jsonl --by-attack`.
- Remaining work, in rough priority order:
  1. Finish the test-split run; commit the results.
  2. Limitations probe (small): goal 13 (legitimate recipients, malicious content) and
     poisoning inside `inputSchema` parameter descriptions (the catalog check does not read
     those yet). Report what isn't caught.
  3. Google OAuth login: login client that gets a Google ID token, sent as an NLIP
     authentication token submessage; `oauth_verify` ingress SE; offline test mode. Needs
     the user's Google Cloud OAuth client ID.
  4. Demo script (`--stub` offline + live) and a recorded run.
  5. Paper (5 pages ACM) and fresh-clone reproducibility check.

## Gotchas learned
- The shell is zsh: no word-splitting of `$VAR` args (use `run_matrix.sh`), and there's no `timeout` command on macOS.
- Closing the laptop lid sleeps macOS and pauses runs; `caffeinate -i` only prevents idle sleep.
  Long runs can go to the user's Jetstream VM (clone the fork, run in `tmux`).
- Jetstream proxy rate-limits bursts (429): keep concurrency ≈3 per model; clients retry 6×.
- `run_matrix.sh` starts a new Python process per config, so **editing code mid-run changes
  later configs**. Keep new behavior behind options that default to off while a run is going.
- AgentDojo seed data has typo'd addresses (`luesparrowtech.com`); `ignore_previous` attack
  misspells "iunstructions" (rules miss it, by design of the benchmark).
