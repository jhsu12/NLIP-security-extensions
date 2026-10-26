# Exploratory scripts (E0–E2)

One-off scripts used before the evaluation harness existed. They are kept so the numbers
in `../EXPERIMENTS.md` (E0–E2) can be traced, **not** as maintained tools: the guard has
changed since they were run (judge wording, evidence lines, redaction, thresholds), so
re-running them will not reproduce those numbers exactly. All reported results from E3 on
come from `run_evaluation.py`.

| Script | Experiment | Needs |
|---|---|---|
| `e0_middleware_hook.py` | E0: can LangChain middleware block/rewrite tool calls? | nothing (fake model) |
| `e0_jetstream_models.py` | E0: Jetstream models, tool calling, latency | `OPENAI_API_KEY`, `OPENAI_BASE_URL` |
| `e0_d3_judge.py` | E0: d3 as an alignment judge on 8 hand-written calls | `VSR_API_KEY` |
| `e1_judge_wording.py` | E1: judge question wordings, benign vs attack calls | both keys; its "current" variant now means the adopted wording |
| `e2_preview.py` | E2: preview of attacks with/without the guard | both keys; `python e2_preview.py qwen-3.8-27b gemma-4-31b-it` |

Run from the repository root with `.env` loaded, e.g.
`.venv/bin/python adversarial_tests/tool_guard_eval/spikes/e0_d3_judge.py`.
