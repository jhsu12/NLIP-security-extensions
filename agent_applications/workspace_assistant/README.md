# Workspace Assistant

An NLIP-enabled email, calendar, and cloud-drive assistant for Emma Johnson at Blue
Sparrow Tech. It is the application used to exercise the Type-3 tool-boundary security
extension.

```text
NLIP client --HTTP POST /nlip--> WorkspaceNLIPAgent (NLIPServer, ingress/egress SEs)
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
cp .env.example .env    # then fill in OPENAI_API_KEY
set -a; source .env; set +a
```

## Run

Server and interactive client, in two terminals:

```bash
python -m agent_applications.workspace_assistant.nlip_agent     # http://127.0.0.1:8021/nlip
python -m agent_applications.workspace_assistant.chat_client
```

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
