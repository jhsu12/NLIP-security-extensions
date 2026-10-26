# Tool Guard Workflow

How a user request flows through the NLIP workspace assistant and where the Type-3 tool
guard inspects it. The guard never sees the model's reasoning: only the NLIP message,
tool metadata, tool calls, tool results, its own session state, and its policy.

## 1. Request lifecycle

```mermaid
flowchart TD
    U["User / NLIP client"] -->|"NLIP message over HTTP: POST /nlip"| S["WorkspaceNLIPAgent (NLIPServer)"]
    S --> SESS{"Conversation token<br/>known?"}
    SESS -->|no| START["session_started:<br/>new backend + agent"]
    SESS -->|yes| ING
    START --> LIST["MCP tools/list"]
    LIST --> CAT["Tool guard: catalog check<br/>pin hashes, scan descriptions"]
    CAT -->|"sanitized tool catalog"| ING

    ING["NLIP ingress SEs<br/>tool_guard records the user's request<br/>as the trusted task"] --> H["handle: LangChain agent turn"]

    H --> M["LLM call<br/>(Jetstream qwen / gemma)"]
    M -->|"final text, no tool call"| EG
    M -->|"proposes a tool call"| PRE["Tool guard: pre-tool check<br/>L0 validation, L1 policy, L2 judge"]

    PRE -->|BLOCK| BMSG["Blocked message to the model<br/>tools/call never sent"]
    BMSG --> M
    PRE -->|ALLOW| CALL["MCP tools/call"]
    CALL --> BE[("Mock workspace backend<br/>inbox, calendar, drive")]
    BE --> RES["Tool result"]
    RES --> POST["Tool guard: post-tool scan<br/>L3 rules + d3"]
    POST -->|"clean: ALLOW"| M
    POST -->|"injection found: REPLACE<br/>redact span, taint session"| M

    EG["NLIP egress SEs<br/>tool_guard closes the turn in the audit log"] --> R["NLIP response"]
    R --> U

    PRE -.-> AUD[("Audit log")]
    POST -.-> AUD
    CAT -.-> AUD
    ING -.-> AUD
    EG -.-> AUD
```

## 2. Inside the tool guard

```mermaid
flowchart TD
    subgraph CATALOG["Catalog check: after tools/list, before the model sees tools"]
        C1["For each tool"] --> C2{"Description hash<br/>changed since pinned?"}
        C2 -->|yes| C3["Withhold tool<br/>(rug pull)"]
        C2 -->|no| C4["Scan description:<br/>rules + d3 detector"]
        C4 -->|clean| C5["Keep as is"]
        C4 -->|hidden instructions| C6["Strip injected span<br/>taint: record planted addresses/URLs"]
    end

    subgraph PRECALL["Pre-tool: before tools/call"]
        P0{"L0: trusted user task recorded?<br/>arguments well formed?"} -->|no| PB["BLOCK"]
        P0 -->|yes| P1{"L1 policy: tool risk class"}
        P1 -->|"unknown tool"| PB
        P1 -->|read| PA["ALLOW"]
        P1 -->|"write / send / delete"| P2{"Argument uses an address or URL<br/>found only in injected content?"}
        P2 -->|yes| PB
        P2 -->|no| P3{"Destructive, but the user<br/>never asked to delete or cancel?"}
        P3 -->|yes| PB
        P3 -->|no| P4["L2 judge: would the user approve<br/>this exact call?<br/>input: user turns, call, evidence lines,<br/>recent results"]
        P4 --> P5{"P aligned >= threshold?<br/>0.5, or 0.7 once tainted"}
        P5 -->|yes| PA
        P5 -->|no| PB
        P4 -->|"judge error"| PB
    end

    subgraph POSTCALL["Post-tool: before the model reads the result"]
        R1["Split result into text fields"] --> R2["Detect instructions:<br/>rules + d3 detector"]
        R2 -->|none| R3["ALLOW unchanged"]
        R2 -->|found| R4["Narrow to offending paragraphs<br/>redact first-to-last flagged span"]
        R4 --> R5["REPLACE result<br/>taint session"]
        R2 -->|"scanner error"| R6["REPLACE whole result"]
    end

    C6 -. "planted indicators" .-> P2
    R5 -. "taint raises threshold<br/>planted indicators" .-> P2
    R5 -.-> P5
```

## 3. Where attacks enter and which layer stops them

```mermaid
flowchart LR
    A1["Indirect prompt injection<br/>in emails, events, files"] --> T1["Tool result"]
    A2["Tool poisoning<br/>in MCP descriptions"] --> T2["tools/list metadata"]
    A3["Rug pull<br/>description changes later"] --> T2
    A4["Judge-aware text<br/>'this is pre-approved'"] --> T1

    T1 --> L3["L3 result scanner<br/>redact + taint"]
    T2 --> LC["Catalog check<br/>strip / withhold"]
    L3 --> MODEL["LLM"]
    LC --> MODEL
    MODEL -->|"hijacked tool call"| L12["L1 policy + L2 judge<br/>block before tools/call"]
    L12 -->|"only aligned calls"| MCP["MCP tools/call"]
```

## 4. Evaluation pipeline

```mermaid
flowchart TD
    D["AgentDojo workspace suite<br/>40 user tasks, 14 attacker goals"] --> SPLIT["Fixed split<br/>dev: 10 tasks, test: 30 tasks"]
    SPLIT --> CASES["Cases: benign user task,<br/>or user task x goal x attack"]
    ATT["Attacks<br/>important_instructions, tool_knowledge,<br/>direct, ignore_previous, judge_aware,<br/>tool_poisoning, tool_poisoning_plain"] --> CASES
    CFG["Guard configs<br/>none, policy_only, judge_only,<br/>hybrid, hybrid + catalog, ablations"] --> EP

    CASES --> EP["Episode: fresh server, attack planted,<br/>task sent over NLIP to POST /nlip"]
    EP --> RUN["Agent runs; guard decides"]
    RUN --> SCORE["Score from backend state<br/>utility: user task done?<br/>attack success: attacker goal done?"]
    SCORE --> JL[("results/*.jsonl<br/>one line per episode + audit trail")]
    JL --> MET["metrics.py<br/>benign utility, utility under attack,<br/>ASR, false-block rate, cost"]
    MET --> TUNE{"dev split?"}
    TUNE -->|yes| THR["Tune thresholds, pick config"]
    THR --> EP
    TUNE -->|test split| PAPER["Numbers reported in the paper"]
```
