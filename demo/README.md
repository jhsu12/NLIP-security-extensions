# Tool guard web demo

One page that runs the workspace assistant once and shows each check the tool guard
makes while it runs. You choose:

- **Task:** one of 7 preset AgentDojo tasks, or your own request (live mode only).
- **Scenario:**
  - benign;
  - tool poisoning, either an `<IMPORTANT>` block or a plain sentence;
  - injected email/file content.
- **Attacker's goal:** one of AgentDojo's 14.
- **Tool guard:** off, on (`hybrid_d3_catalog`), or an ablation.

The page sends your request over NLIP with your sign-in token and renders, live:

| Card | Comes from |
|---|---|
| Where the attack lives | the planted text (poisoned tool descriptions or workspace data) |
| Catalog check | the guard's catalog audit record: rewritten tools, removed text, planted values |
| NLIP ingress | `oauth_verify` (verified email) and the trusted task |
| Tool call: pre-tool / tool / post-tool | the guard's `pre_tool` (layer, reason, judge P vs threshold), the tools that really executed, and the `post_tool` scan (redactions, taint) |
| Outcome | AgentDojo's checkers: was the user's task done, did the attack succeed |

Each run is built the same way as an evaluation episode: same config files, same planted
attack, same checkers (see `runs.py`).

## Run it

Offline (no network, no keys; works from a fresh clone):

```bash
python -m demo.web --stub          # http://127.0.0.1:8030
```

In offline mode, the agent replays AgentDojo's ground-truth tool calls and turns to the
attacker's calls when it can *see* the attacker's instruction. The d3 judge is
simulated by a stub that knows the attacker's goal. Offline runs show *how* the
pipeline works; the measured numbers come from live runs.

Live (Jetstream model, d3 judge, Google sign-in):

```bash
set -a; source .env; set +a        # OPENAI_*, VSR_API_KEY, GOOGLE_WEB_CLIENT_ID
python -m demo.web
```

Google sign-in in the browser needs an OAuth client of type **Web application**. Its
Authorized JavaScript origins must be `http://localhost:8030` and
`http://127.0.0.1:8030`. Put its ID in `.env` as `GOOGLE_WEB_CLIENT_ID`; no secret is
needed. The server accepts tokens issued to either this client or the CLI's Desktop
client.

**Try:**
- "Quick compare" → *attack · guard off* (the attack succeeds),
  *attack · guard on* (the catalog check strips the poison; the task is still done), and
  *attack · call-level only* (the hijacked call is blocked at pre-tool).
- Untick "Attach sign-in token" to see `oauth_verify` reject the request with 403.

**Export / replay:** "Export run (JSON)" saves a run's events. "Replay an exported run"
plays one back in the page without a server run, for example a recorded live run.

Tests: `pytest tests/test_demo.py`.
