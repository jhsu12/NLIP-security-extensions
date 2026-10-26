# Workspace Assistant

An NLIP-enabled email, calendar, and cloud-drive assistant for Emma Johnson at Blue
Sparrow Tech. It is the application used to exercise the Type-3 tool-boundary security
extension.

```text
NLIP client --HTTP POST /nlip--> WorkspaceNLIPAgent (NLIPServer, ingress/egress SEs)
  + Google ID token                -> oauth_verify: reject unsigned requests (403)
    (NLIP authorization token)     -> tool_guard: record the user's task
                                   -> LangChain agent (Jetstream LLM)
                                   -> MCP tools/list, tools/call
                                   -> workspace MCP server -> mock inbox/calendar/drive
```

- **Backend and tasks:** the [AgentDojo](https://github.com/ethz-spylab/agentdojo)
  `workspace` suite (v1.2.2): 24 tools, seeded mailbox, calendar and drive, 40 user tasks,
  14 injection tasks and 16 injection vectors. Benign utility and attack success are both
  judged from the backend state.
- **Tools:** reached only through MCP. The server runs in-process over memory streams, so
  the evaluation can read the backend state, or standalone over stdio
  (`python -m agent_applications.workspace_assistant.mcp_server`).
- **Sessions:** each NLIP session gets its own backend and agent, and keeps chat history
  across turns.

## Setup

From the repository root, with Python 3.11 or newer:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[workspace,test]'
cp .env.example .env    # then fill in OPENAI_API_KEY, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
set -a; source .env; set +a
```

## Run

Server and interactive client, in two terminals:

```bash
python -m agent_applications.workspace_assistant.nlip_agent     # http://127.0.0.1:8021/nlip
python -m agent_applications.workspace_assistant.chat_client
```

The client signs in with Google before the first message (see below).

Score AgentDojo user tasks through the NLIP pipeline (in-process, same `process_exchange`
path as HTTP):

```bash
python -m agent_applications.workspace_assistant.run_tasks                  # 5-task smoke set
python -m agent_applications.workspace_assistant.run_tasks user_task_13 --model gemma-4-31b-it
python -m agent_applications.workspace_assistant.run_tasks --all --json     # all 40 tasks
```

Offline tests (no API key needed): `pytest tests/test_workspace_assistant.py`.

## Configuration

`config.toml` defines the `workspace` NLIP entity and the security extensions enabled at
its ingress and egress. Tool-boundary middleware is passed to `WorkspaceAgent(middleware=...)`.

## Sign-in (Google OAuth)

Every request must carry a Google ID token. The client sends it as an NLIP
`authorization` token submessage. The `oauth_verify` ingress extension
([security_extensions/oauth_login](../../security_extensions/oauth_login)) does four things:

- It checks the token's signature against Google's keys, plus the audience (this OAuth
  client), the issuer, the expiry and that the email is verified.
- It applies the optional `allowed_emails` / `allowed_domains` lists.
- It binds the NLIP session to that email. Another user presenting the same
  conversation token is rejected.
- It removes the token before the agent sees the message.

Rejected requests get HTTP 403. The tool guard records the verified email as the user
behind each trusted task.

Sign-in only proves who the user is. The mailbox, calendar and drive are still the
simulated AgentDojo data, not the user's Google account. The only scopes requested
are `openid` and `email`.

One-time Google Cloud setup:

1. **Google Auth Platform → Branding/Audience:** set up the consent screen, set
   *External* and *Testing*, and add your Gmail under *Test users*.
2. **Clients → Create client:** choose *Desktop app*.
3. Put the client ID and secret in `.env` as `GOOGLE_CLIENT_ID` and
   `GOOGLE_CLIENT_SECRET`.

```bash
python -m agent_applications.workspace_assistant.login            # opens the browser once
python -m agent_applications.workspace_assistant.login --logout
```

Credentials are cached in `~/.cache/nlip-workspace/` (mode 600). Later runs refresh
the ID token without opening the browser.

**Offline:** set `provider = "stub"` under `[security_extensions.oauth_verify.options]`.
The client then mints a locally signed token for `NLIP_STUB_USER`, which defaults to
Emma's address, and the server verifies it with the shared stub secret. Use this for
tests and the offline demo only. **To turn sign-in off**, remove `"oauth_verify"` from
`ingress`.

Offline tests: `pytest tests/test_oauth_login.py`.
