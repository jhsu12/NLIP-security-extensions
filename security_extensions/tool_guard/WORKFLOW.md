# Tool Guard Workflow

How a user request flows through the NLIP workspace assistant, and where the Type-3 tool guard
inspects it. The guard never sees the model's reasoning. It sees only:
- the NLIP message;
- tool calls and tool results;
- its own session state;
- the deployer's risk label for each tool.

This describes the **final design, `d3_only`**
(`adversarial_tests/tool_guard_eval/configs/d3_only.toml`): a d3 judge before every
side-effecting call, and a d3 scan of every tool result. There are no regex rules, no policy
blocking rules and no catalog check. Those components still exist and are used by ablation
configs (§5).

The application's default `config.toml` still enables the earlier `hybrid_d3_catalog` setup;
see the README's "Running the final design".

## 1. Request lifecycle

```mermaid
flowchart TD
    U["User / NLIP client"] -->|"NLIP message over HTTP: POST /nlip"| S["WorkspaceNLIPAgent (NLIPServer)"]
    S --> SESS{"Conversation token<br/>known?"}
    SESS -->|no| START["session_started:<br/>new backend + agent"]
    SESS -->|yes| ING
    START --> LIST["MCP tools/list<br/>(descriptions passed to the model unchecked)"]
    LIST --> ING

    ING["NLIP ingress SEs<br/>oauth_verify: verify the sign-in<br/>tool_guard: record the user's request as the trusted task"] --> H["handle: LangChain agent turn"]

    H --> M["LLM call<br/>(Jetstream qwen / gemma)"]
    M -->|"final text, no tool call"| EG
    M -->|"proposes a tool call"| PRE["Tool guard: pre-tool check<br/>validation, risk label, d3 judge"]

    PRE -->|BLOCK| BMSG["Blocked message to the model<br/>tools/call never sent"]
    BMSG --> M
    PRE -->|ALLOW| CALL["MCP tools/call"]
    CALL --> BE[("Mock workspace backend<br/>inbox, calendar, drive")]
    BE --> RES["Tool result"]
    RES --> POST["Tool guard: post-tool scan<br/>d3 injection detector"]
    POST -->|"clean: ALLOW"| M
    POST -->|"injection found: REPLACE<br/>redact span, taint session"| M

    EG["NLIP egress SEs<br/>tool_guard closes the turn in the audit log"] --> R["NLIP response"]
    R --> U

    PRE -.-> AUD[("Audit log")]
    POST -.-> AUD
    ING -.-> AUD
    EG -.-> AUD
```

## 2. Inside the tool guard

```mermaid
flowchart TD
    subgraph PRECALL["Pre-tool: before tools/call"]
        P0{"Validation: trusted user task recorded?<br/>tool name and arguments well formed?"} -->|no| PB["BLOCK"]
        P0 -->|yes| P1{"Risk label of the tool<br/>(deployer's policies/workspace.toml)"}
        P1 -->|"unknown tool"| PB
        P1 -->|read-only| PA["ALLOW<br/>(no d3 call)"]
        P1 -->|"write / send / delete"| P4["d3 judge: would the user approve<br/>this exact call?<br/>input: user turns, the call, evidence lines,<br/>recent results (marked untrusted)"]
        P4 --> P5{"P(yes) >= threshold?<br/>0.5, or 0.7 once tainted"}
        P5 -->|yes| PA2["ALLOW"]
        P5 -->|no| PB
        P4 -->|"judge error"| PB
    end

    subgraph POSTCALL["Post-tool: before the model reads the result"]
        R1["Split result into text fields<br/>(40+ characters)"] --> R2["d3 injection detector:<br/>instructions aimed at an AI assistant?"]
        R2 -->|"all below 0.5"| R3["ALLOW unchanged"]
        R2 -->|"field >= 0.5"| R4["Narrow long fields to the offending paragraphs<br/>redact first-to-last flagged span"]
        R4 --> R5["REPLACE result<br/>taint session"]
        R2 -->|"scanner error"| R6["REPLACE whole result"]
    end

    R5 -. "tainted: threshold 0.5 -> 0.7" .-> P5
```

**Evidence lines** are lines from earlier tool results that mention the call's recipients or ids,
for example "Attendees from client: John Mitchell". They let the judge check where a recipient
came from. A recipient the user never typed is approved when it follows from content the request
points to, and refused when it appears only in attacker text.

## 3. Where attacks enter and what stops them

```mermaid
flowchart LR
    A1["Tool poisoning<br/>in tool descriptions"] --> T2["tools/list metadata"]
    A2["Poison in parameter<br/>descriptions (inputSchema)"] --> T2
    A3["Indirect prompt injection<br/>in emails, events, files"] --> T1["Tool result"]
    A4["Judge-aware text<br/>'this is pre-approved'"] --> T1

    T2 -->|"unchecked"| MODEL["LLM"]
    T1 --> SCAN["d3 scan<br/>redact + taint"]
    SCAN --> MODEL
    MODEL -->|"hijacked tool call"| JUDGE["d3 judge<br/>block before tools/call"]
    JUDGE -->|"only calls the user would approve"| MCP["MCP tools/call"]
```

Tool metadata reaches the model, so the judge must stop the action it triggers. On the test
split, that held for all 900 attack episodes (README, `EXPERIMENTS.md` E17). The cost is
distraction: under tagged tool poisoning the model finishes the user's task 86–87% of the time,
vs 93–96% when the catalog-check ablation strips the poison first.

## 4. Evaluation pipeline

```mermaid
flowchart TD
    D["AgentDojo workspace suite<br/>40 user tasks, 14 attacker goals"] --> SPLIT["Fixed split<br/>dev: 10 tasks, test: 30 tasks"]
    SPLIT --> CASES["Cases: benign user task,<br/>or user task x goal x attack"]
    ATT["Attacks<br/>AgentDojo data attacks, judge_aware,<br/>tool_poisoning, tool_poisoning_plain,<br/>schema_poisoning, schema_poisoning_tagged"] --> CASES
    CFG["Guard configs<br/>none, d3_only (final),<br/>ablations: hybrid_d3_catalog, hybrid_d3,<br/>catalog_only, judge_only, policy_only"] --> EP

    CASES --> EP["Episode: fresh server, attack planted,<br/>task sent over NLIP to POST /nlip"]
    EP --> RUN["Agent runs; guard decides<br/>(--trace: model messages, raw results, d3 I/O)"]
    RUN --> SCORE["Score from backend state<br/>utility: user task done?<br/>attack success: attacker goal done?"]
    SCORE --> JL[("results/*.jsonl<br/>one line per episode + audit trail + trace")]
    JL --> MET["metrics.py<br/>benign utility, utility under attack,<br/>ASR, false-block rate, layers, cost"]
    JL --> BROWSE["Web demo /runs<br/>step through episodes one by one"]
    MET --> TUNE{"dev split?"}
    TUNE -->|yes| THR["Tune thresholds and wording"]
    THR --> EP
    TUNE -->|test split| PAPER["Numbers reported in the paper"]
```

## 5. Optional components (used only by ablations)

These are implemented and evaluated, but switched off in the final design.

| Component | Config option | What it does | Why it is off |
|---|---|---|---|
| Catalog check + pinning (`catalog.py`) | `catalog = "rules" / "judge" / "rules+judge"` | Scans each tool's main description after `tools/list` and strips hidden instructions before the model sees them; pins description hashes and withholds a tool whose description changed (rug pull) | It wrongly stripped 42–80% of legitimate imperative-style descriptions ("Before using this tool, call `login`"; E15). It never reads parameter descriptions. The judge alone stopped every attack. |
| Regex rules (`scanner.py`: `INJECTION_RULES`, `DESCRIPTION_RULES`) | `scanner` / `catalog` containing `rules` | Pattern-match known injection templates (`<INFORMATION>`, `<IMPORTANT>`, "ignore previous instructions", "do not tell the user", …) | They match the templates of our own attack sets, which would mean knowing the answers in advance. They miss template-free text (E8, E16). |
| Policy blocking rules (`policy.py`) | `policy_rules = true` | Block a call whose arguments contain an address/URL that only appeared in flagged content (planted values), or a delete or cancel the user's words never mention | The planted-value rule depends on flagging; the delete rule is a keyword list that also blocks misspelled or paraphrased requests. With them off, these calls go to the judge, which stopped every attack. |
