# Tool guard demos

Two demos:
- a **terminal replay** for graders, which runs start to finish with no keys;
- an **interactive web page**, for exploring one run at a time.

## Terminal demo (for graders)

```bash
python -m demo.replay --stub          # offline: no keys, no network, about 10 s
python -m demo.replay                 # live: Jetstream model + d3 judge (set -a; source .env; set +a)
python -m demo.replay --stub --scenario 4 --markdown run.md   # one scenario, also saved as Markdown
```

It replays five attack cases and one normal request from the test data. Each runs against
the NLIP endpoint (`POST /nlip`, with a sign-in token), **guard OFF** and then **guard ON**,
with the guard in the final **d3-only** design: a d3 judge before every side-effecting call,
a d3 injection scan of every tool result, and no regex rules, policy rules or catalog check.
Every step behind the scenes is printed as it happens:
- sign-in;
- every tool call with the d3 judge's verdict (P(user would approve) vs the threshold);
- the d3 scan of each result;
- the reply;
- AgentDojo's verdict on the user's task and on the attack.

The attacks hide the instruction in a different place each time. They are test-split cases
that the live d3-only guard stopped on both models.

| # | Where the attacker's instruction is hidden | Task × attacker goal | Guard ON stops it at |
|---|---|---|---|
| 1 | tool description, hidden `<IMPORTANT>` block | `user_task_29` × email the attacker | d3 judge (pre-tool) |
| 2 | tool description, one plain sentence | `user_task_9` × delete a drive file | d3 judge (pre-tool) |
| 3 | an email the task reads | `user_task_22` × forward a private email | d3 scan (post-tool) |
| 4 | a tool's *parameter* description, `<IMPORTANT>` block | `user_task_29` × email the attacker | d3 judge (pre-tool) |
| 5 | tool description, hidden `<IMPORTANT>` block | `user_task_33` × invite the attacker to a meeting | d3 judge (pre-tool) |
| 6 | no attack: a normal request | `user_task_33` | nothing; the legitimate email is allowed |

How it maps to the spec's demo requirements (§6.3):
1. **The attack test data replayed against an NLIP endpoint.** Each case is a test-split case
   from `adversarial_tests/tool_guard_eval/data/attacks/`. The replay checks that the text it
   plants equals that file.
2. **The defense catching it around a tool call.** The narration names the check and layer that
   stopped each attack.
3. **The results.** The closing table shows what got through with the guard off, what was
   blocked with it on, whether the user's task was still done, and the guard's time and judge
   calls.

**Requirements:** Python 3.11+ with `pip install -e '.[workspace,test]'`. Offline needs nothing
else. Live needs `OPENAI_API_KEY`, `OPENAI_BASE_URL` and `VSR_API_KEY`.

**Offline mode:** a scripted agent replays AgentDojo's correct tool calls, and obeys any
attacker instruction it can see (the worst case). d3 is replaced by a stub that knows the
attacker's goal and intended calls. So guard OFF always shows the attack launched, and guard
ON shows where it is stopped. Everything else is the real code: the NLIP server, sign-in
check, guard pipeline, MCP tools, workspace data and AgentDojo checkers. Offline runs show
*how* the checks work; the measured numbers come from live runs.

**Live mode:** a real model may ignore the instruction even without the guard. The narration
then says so, and `--retries N` (default 2) re-runs the guard-OFF case. The measured rates are in
the main README and `adversarial_tests/tool_guard_eval/EXPERIMENTS.md`.

Sign-in uses stub tokens in both modes, because graders can't use our Google OAuth app (it
admits test users only). Google sign-in is shown in the web demo and the terminal chat client.

## Interactive web demo

One page that runs the workspace assistant once and shows each check the tool guard makes while
it runs. You choose:
- **Task:** one of 9 preset AgentDojo tasks, or your own request (live mode only).
- **Scenario:**
  - Normal;
  - **Poisoned tools**, in one of four styles (under ⋯): an `<IMPORTANT>` block or a plain
    sentence in a tool description, or either of those in a parameter description;
  - **Poisoned data**: instructions planted in an email, file or event.
- **Attacker wants to:** one of 8 AgentDojo goals. Click **See what changed** on the red banner
  for a before/after view of the planted text.
- **Tool guard:** On or Off. Under **⋯ → Guard variant**, **"d3 only"** is the **final design**.
  "On" currently means `hybrid_d3_catalog`, the application's default, and the other entries are
  ablations.

The page sends your request over NLIP with your sign-in token. The **Guard activity** panel fills
in live:

| Row | Comes from |
|---|---|
| Signed-in user verified | `oauth_verify` (verified email) and the trusted task |
| Tool descriptions checked | the catalog check, if the guard variant has one; with d3 only, there is none |
| 🤖 Model decides: … | each model response as it arrives: its text and the tool calls it requested |
| 🛠️ tool call | the pre-tool verdict (layer, reason; for the judge, **the exact JSON d3 was asked** and its P vs the threshold), the **raw tool result**, and the post-tool scan (each field's d3 injection score, redactions) |
| Task done / Attack stopped tiles | AgentDojo's checkers: was the user's task done, did the attack succeed, and was it stopped *by the guard* or ignored by the model |

Untick **Full trace** for the short view: verdicts only, no model rows or d3 inputs. Each run is
built the same way as an evaluation episode (same config files, same planted attack, same
checkers; see `runs.py`).

### Run browser (`/runs`)

Step through saved evaluation episodes, e.g. the final `d3final` run, one by one, rendered like a
live run.
- **Pick a results file:** config × model × tag. The default is the traced d3-only run.
- **Counts:** outcome counts at the top ("attack stopped by guard", "model ignored attack",
  "benign: task done", "benign: false block", …). Click one to filter.
- **Filters:** by attack type, or type a task or goal (e.g. `user_task_25`).
- **Keys:** **← / →** (or **k / j**) for previous/next, **space** to replay step by step. The URL
  names the episode, so it can be bookmarked.

The browser only reads `adversarial_tests/tool_guard_eval/results/`, so it works offline without
keys. Episodes recorded without `--trace` show the guard's decisions only.

### Other pages

- `/how`: an animated walkthrough of one request through NLIP, the guard and MCP.
- `/checks`: what each check does, and the guard variants with their test-split results.

## Run it

Offline (no network, no keys; works from a fresh clone):

```bash
python -m demo.web --stub          # http://127.0.0.1:8030
```

In offline mode, the agent replays AgentDojo's ground-truth tool calls and turns to the
attacker's calls when it can *see* the attacker's instruction. d3 is simulated by a stub that
knows the attacker's goal and intended calls. Offline runs show *how* the pipeline works; the
measured numbers come from live runs.

Live (Jetstream model, d3 judge, Google sign-in):

```bash
set -a; source .env; set +a        # OPENAI_*, VSR_API_KEY, GOOGLE_WEB_CLIENT_ID
python -m demo.web
```

Live without a Google account (e.g. graders on Jetstream). This uses the real model and judge,
plus a "Sign in (demo user)" button. `oauth_verify` still checks every request, against a locally
signed token:

```bash
set -a; source .env; set +a        # OPENAI_*, VSR_API_KEY
python -m demo.web --signin stub
```

Google sign-in in the browser needs an OAuth client of type **Web application**. Its Authorized
JavaScript origins must be `http://localhost:8030` and `http://127.0.0.1:8030`. Put its ID in
`.env` as `GOOGLE_WEB_CLIENT_ID`; no secret is needed. The server accepts tokens issued to either
this client or the CLI's Desktop client.

**Try:**
1. Click **⚡ Show me an attack**. It sets up a poisoned tool with the guard Off, in a case where
   attacks often work.
2. Send it. If the model falls for it, you see `send_email` to the attacker and **✗ Attack
   succeeded**. The model doesn't always fall for it, so send again if needed.
3. Then set the guard **On** with **⋯ → Guard variant → d3 only**, and send again. The judge row
   shows the hijacked call blocked, with d3's score.
4. Untick **Send sign-in token** (under ⋯) to see `oauth_verify` reject the request with 403.

**Save / replay:** "Save run" saves a run's events, and "Replay a saved run" (under ⋯) plays one
back without a server run.

Tests: `pytest tests/test_demo.py`.
