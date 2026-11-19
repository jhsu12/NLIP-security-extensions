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
- Repo home (since 2026-10-26): `origin` = `MCP-Tool-Guard/ToolGuard` (the user's GitHub
  org). Its `main` = our work; `tool-guard` is kept in sync with it. Old fork = remote
  `jhsu12-fork` (`jhsu12/NLIP-security-extensions`); `upstream` = instructor's
  `systemsecurity-uiuc/NLIP-security-extensions`. Work on branch `tool-guard`.
- `../CS598-AISecurity` is an old weather-agent prototype; no longer the build target.

### Grading points to keep in mind
- Application row (20%): realistic agentic app grounded in NLIP, and it **must support
  login through OAuth** (e.g. Google). Done: `login.py` + `oauth_verify`.
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

## What exists

- `agent_applications/workspace_assistant/`: NLIP email/calendar/drive assistant.
  - Backend, tools, tasks and checkers come from **AgentDojo `workspace` v1.2.2** (24 tools; user
    Emma Johnson).
  - Tools are served via an in-process **MCP** server (`mcp_server.py`).
  - A LangChain `create_agent` (`agent.py`) has a model-call cap of 20 per turn.
  - `nlip_agent.py` is the `NLIPServer`, with one backend and agent per NLIP session.
  - `config.toml` enables extensions; Google sign-in is in `login.py`.
- `security_extensions/tool_guard/`: **the security function**. See `WORKFLOW.md` (Mermaid,
  final design + optional components).
  - **Final design `d3_only`** (`configs/d3_only.toml`):
    - validation (fail closed);
    - the deployer's risk label from `policies/workspace.toml` (read-only → allow without d3;
      unknown → block; side-effecting → judge);
    - the d3 judge in `judges.py` ("would the user approve this exact call?", threshold 0.5, or 0.7
      once tainted; evidence lines from earlier results);
    - the d3-only scan in `scanner.py` (redacts the injected span, taints the session).
  - **Optional, ablations only:** `catalog.py` (scans and pins tool descriptions), the regex rules
    in `scanner.py`, and the policy blocking rules in `policy.py` (planted values, deletes without
    user intent).
  - **`config.toml`, web demo "Guard On" and `demo.replay` all use `d3_only`** (switched
    2026-11-10). The earlier design is the `hybrid` demo variant / `hybrid_d3_catalog` config. The
    ablation configs pin `policy_rules = true` themselves, so they resolve as in the recorded runs.
  - `nlip_extension.py`: an NLIP ingress SE that records the user's text as the trusted task (egress
    closes the turn).
  - `langchain_middleware.py`: the `awrap_tool_call` adapter + `guard_tool_catalog`.
- `security_extensions/oauth_login/`: the `oauth_verify` ingress SE (Google ID tokens, Desktop +
  Web client IDs; stub mode).
- `adversarial_tests/tool_guard_eval/`: the harness.
  - `cases.py`: dev = user tasks whose number is divisible by 4, i.e. 10 tasks; test = the other 30.
  - Attacks: AgentDojo data attacks, `judge_aware`, `tool_poisoning`, `tool_poisoning_plain`,
    `schema_poisoning[_tagged]`.
  - `run_evaluation.py`: `--trace`, `--keys`, `--results-tag`; resumable; errored episodes re-run.
  - Also: `run_matrix.sh`, `metrics.py` (`--by-goal`, `--layers`), `catalog_eval.py`,
    `scanner_eval.py`, `tracing.py`, `export_explorer.py`, `configs/*.toml`, `data/`, `results/`.
- `demo/`:
  - `replay.py`: the terminal demo for graders, d3-only: the web page's 6 "Show me an attack"
    examples (`runs.ATTACK_EXAMPLES`, 3 are dev split) + 1 benign;
  - `web.py`: the web demo with the live full trace, plus `/runs` (browse saved episodes one by
    one), `/how` and `/checks`.
- `tests/`: 77 offline tests (`pytest`, no network needed).

## Key findings (details in `adversarial_tests/tool_guard_eval/EXPERIMENTS.md`)
- **Data-channel injections barely work on these models, even without the guard** (1 of 580 dev
  episodes). MCP tool poisoning does work (test split, no guard):
  - tagged: 11–13%;
  - plain: 1–2%;
  - parameter descriptions, tagged: 7–12%.
- **Final `d3_only` (E17, test split, traced `d3final`):**
  - **0/900 attack episodes succeeded; 0/60 benign false blocks;** ≈0.35 s and ≈3 d3 calls per
    episode;
  - of 69 cases that succeeded without the guard, the judge blocked 67 (P ≤ 0.026); in 2 the model
    didn't act;
  - cost of dropping the catalog check: task success under tagged poisoning is 87/85% vs 96/93%
    for `hybrid_d3_catalog`;
  - 4 false redactions (the agent's own sent email in `user_task_25`).
- **Why no rules:**
  - the regex rules match the attack templates themselves;
  - the catalog check strips 42–80% of tricky legitimate docs (E15);
  - d3 alone catches 91% of AgentDojo's data injections, missing `<INFORMATION>` in 3 calendar
    events (E16).
- **Decided with the user on 2026-10-26: final config `d3_only`.** Earlier configs (E11, E14) are
  ablations.
- Judge wording ("approve") was tuned in E3 on judge inputs from **test** tasks 13 and 25 (not dev):
  benign 0.80–0.98 vs attacks ≤0.03 on d3-flash. The paper discloses this and reports E17 without those
  two tasks as well.
- **Known issue:** the guard reorders parallel side-effecting tool calls (each waits on its own
  judge call), which fails order-sensitive AgentDojo checkers (`user_task_25`). Planned fix:
  serialize guarded calls per session.

## Current state / next steps
- Everything through `bc3bf47` is committed and pushed; the `d3_only` default switch (2026-11-10)
  is uncommitted unless git says otherwise.
- **Open, in rough priority order:**
  1. Paper (5 pages ACM; not started; ECMA-434 §7.3.1 confirmed by the spec; check the other SCO
     numbers in the standard).
  2. Serialize guarded calls per session, and retry d3 on 429/disconnects; measure with `d3_only`.
  3. Fresh-clone reproducibility check.
  4. Optionally: scan only read-tool results (removes the false redactions), `judge_reads`.

## Gotchas learned
- The shell is zsh: no word-splitting of `$VAR` args (use `run_matrix.sh`), and there's no `timeout` command on macOS.
- Closing the laptop lid sleeps macOS and pauses runs; `caffeinate -i` only prevents idle sleep.
  Long runs can go to the user's Jetstream VM (clone the fork, run in `tmux`).
- Jetstream proxy rate-limits bursts (429): keep concurrency ≈3 per model; clients retry 6×.
- `run_matrix.sh` starts a new Python process per config, so **editing code mid-run changes
  later configs**. Keep new behavior behind options that default to off while a run is going.
- AgentDojo seed data has typo'd addresses (`luesparrowtech.com`); `ignore_previous` attack
  misspells "iunstructions" (rules miss it, by design of the benchmark).
