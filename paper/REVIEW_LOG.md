# Paper review log

Independent review rounds of the draft. Each round is run by a fresh agent that gets only the
paper, the code, the results files, ECMA-434 and the course spec, with no summary of what the
paper is supposed to say. It checks:
- numbers;
- design claims against the code;
- test-data claims against the harness;
- SCO numbers and titles;
- spec coverage, overclaims, format and citations.

Below each round: what it found, and what was changed (or why not).

## Round 1 (2026-11-13)

Found 30 issues: 2 critical, 11 major, 17 minor. The reviewer recomputed every number
independently, and all macros and both tables matched the results files.

| # | Finding | Action |
|---|---|---|
| 15, 16 | **Critical.** "Tuned on dev only" was false: E3's wording study used judge inputs from **test** tasks 13 and 25, with attacker calls matching goals 0, 1, 2 and 4–5. Also, the test split was run (E11–E16, two pilot `d3_only` runs) before the final design was chosen. | New paragraph in §5, "Deviations from a clean hold-out". §6 reports every headline number with tasks 13 and 25 excluded (0/852 attacks, 0/56 benign blocks, 62/64 paired, 0 wrong blocks). E3's label and the pilot runs are corrected in EXPERIMENTS.md, the eval README and CLAUDE.md. |
| 7 | Legitimate calls blocked in attack episodes (3 of 900, tasks 13 and 25) were not reported, and legitimate scores (≥0.014) overlap the attacker maximum (0.026). | Reported in §6 False alarms, the abstract and the conclusion. The claim that "no threshold would have let an attack through" is removed. |
| 17 | "Stopped every attack" overstates narrow evidence: 67 informative cases from 5 goals. | §6 now says 0/67 attempted hijacks across goals 0, 1, 2, 4, 5, with 95% upper bounds (4.4%; benign 4.9%; all attack episodes 0.3%). Abstract and conclusion are narrowed. |
| 18 | The final guard was never run end to end against data injections. | Intro and §6 now say so. |
| 8, 9, 11, 12, 26 | Missing limits: 4,000-character scan cap, context truncation, tool-name shadowing, third-party API data flow (§7.2.6), judge reading attacker text. | All added to §4 and §7. |
| 5 | The appendix claimed every number came from results files, and gave wrong run flags. | The claim now covers result numbers only. The table has flags per row (E5 all pairs, E6 `--sample 40 --seed 1`, E15/E16 no agent runs). |
| 1–4 | Re-run episodes, errored dev episodes, "d3 calls" undefined, and cost given as a median only. | Reported: 24 re-run; 20 errored and excluded; 3.8 HTTP requests per episode; mean 0.44 s, p90 0.85 s, max 3.0 s; extra agent steps excluded. |
| 6 | "8 points" didn't say against which row. | Now names the "+ catalog check" row. |
| 10, 13, 14, 19–23 | Block message content; OAuth also checks the issuer and allow-list; adapter size; in-process transport, and sign-in disabled in the harness; goal-13 probe was the plain variant; example task was not a real AgentDojo task; parameter-poisoning fallback; demo retries and stub sign-in. | All corrected in the text. |
| 24 | SCOs all correct; conformance should be disclaimed. | Added: no conformance claimed, since Profile 1 needs TLS. |
| 26 (minor) | "Rule-based layers add false blocks" overstated; the regex rules' precision advantage was omitted. | Now "policy rules"; the rules' precision is shown in Figure 3 and §4. |
| 27 | Author placeholder. | **Open:** waiting for the author's name and affiliation. |
| 28 | Overfull boxes; Figure 1 text small. | Figure 1 fonts enlarged; most lists turned into prose. Body still ends on page 5. |
| 29 | Citations exist; MELON and Task Shield page numbers unverified. | Unchanged (page numbers came from the proceedings listings found by web search). |
| 30 | Inconsistent names: P(yes), P(approve), "detector". | Now P(approve) and "scanner"; "tagged" and "catalog check" are defined. |

Also added at the user's request: precision, recall and F1 (Figure 3) for the judge (per call, E17)
and the scanner (per tool result, E16), with the labelling rule stated in §6.

## Round 2 (2026-11-13)

Found 25 issues: 2 critical, 5 major, 18 minor. Every macro and table cell matched the
reviewer's independent recomputation, and the SCO numbers and titles match ECMA-434 exactly.
I re-checked each critical and major claim against the data before changing anything.

| # | Finding | Action |
|---|---|---|
| 1 | **Critical.** "Scored from the backend state, not the model's text" is wrong for utility: 22 of 40 utility checks read the agent's answer. | §5 now says attack success comes from the state, and utility from the state plus the answer for 22 of 40 tasks (macro computed from AgentDojo's source). |
| 2 | **Critical.** The scanner's misses are not all in three calendar events: 72 of 82 are, and 10 are in two drive files. | §6 states the split (macros). EXPERIMENTS.md E16 is corrected too. |
| 3 | The tuning leak includes the evaluated goals' own attacker calls, and excluding tasks 13 and 25 doesn't remove them. | Disclosed in §5 and §6, along with the mitigating fact that every wording scored them ≤0.03, so the benign side drove the choice. The abstract is softened. |
| 4 | Taint and the scanner did nothing in E17: 0 tainted decisions, no attacker text redacted, 29 calls allowed between 0.5 and 0.7. | §6: "the result is due to the judge alone", with these numbers. |
| 5 | Author placeholder. | **Still open:** waiting for the author's name and affiliation. |
| 6 | Untested bypass: poisoned metadata telling the agent what to write into arguments. | Added to §7. |
| 7 | §7.3.1 mapping overstated. | Table 1: §7.3.1 is now "Primary, in part" (blocks induced calls; scanner measured offline; descriptions not filtered). §7.2.2 row added. §2 says it is addressed at the action level. |
| 8 | Evidence understated: attacker calls were blocked across 9 goals, 113 calls, max P 0.106. | Added to §6. |
| 9 | Unsupported causal claim; paraphrase shown in quotes. | Removed. Now states that the same calls were allowed in benign runs. |
| 10 | Per-call precision is inflated by retries. | Stated: one episode has 12 of the 17 false positives. |
| 11, 12 | Median reported as one value; the bounds are one-sided and assume independence. | Abstract gives the 0.33–0.35 s range. "One-sided" and the independence caveat are stated. |
| 13 | Cost covered guard time only. | Added d3 input tokens (~1,792), agent calls unchanged (3.2 vs 3.2), and why wall time is not compared. Utility moved out of the Cost paragraph. |
| 14, 15 | Hand-typed numbers; incomplete reproduction flags. | Remaining counts are now macros (16, 600/60, 40/33, 22). The appendix table gives full flags (attacks, `--no-benign`, `--results-tag`). |
| 16 | Ablation columns undefined; reordering not mentioned. | Table moved to the appendix (for space) with defined columns and the reordering note. |
| 17 | Deviations list incomplete. | Added: the decision to drop the rules used the E15/E16 test-data measurements. |
| 18, 19 | Short fields not scanned; whole-field replace and line fallback; privacy covers every scanned field. | Added to §4 and §7. |
| 20 | Threat instantiation. | §2: the poison is in the workspace server's own tools (compromised or rug-pulled server); a new server's tools are blocked as unknown. |
| 21 | Catalog benign set is not all imperative. | "40 descriptions, 33 with imperative wording" (macros). |
| 22 | Ingress records only text submessages. | §4 says so, and says what happens with none. |
| 23 | Layout gap; BibTeX warnings; MCP spec attributed to Anthropic. | Layout reflowed. MCP author changed to the Model Context Protocol project; MELON publisher added. |
| 24 | Where the harness ran. | §5: on our own laptop, with models on Jetstream2. |

To keep the body at 5 pages, the attack table (now Table 3) and the ablation table (Table 4) moved
to the appendix, and short lists became prose. The PDF is 7 pages, the maximum allowed.

## Round 3 (2026-11-13)

Found 24 issues: 1 critical, 7 major, 16 minor. The generated tables and macros regenerate
byte-identical, and the reviewer's own scripts match every headline number. Because a critical
finding remained, the stopping rule requires a round 4.

| # | Finding | Action |
|---|---|---|
| 1 | **Critical.** "No session became tainted" was false: the 4 false-redaction sessions were tainted, each after its last judged call. | Corrected (verified against the egress audit records). |
| 9 | Test-split tuning under-disclosed: ranked evidence lines and the 1,500-character preview (E3), and span redaction and the 20-call cap (E4), also came from tasks 13 and 25. | Added to deviation (i). |
| 10 | Wrong explanation of benign losses in the ablation table. | Verified per config: losses without a block are `user_task_25` (out-of-order completion) and `user_task_11` (also fails with no guard). Text corrected. |
| 12, 13 | §7.2.2 row overclaims (read-only calls aren't checked; sign-in was off in the harness); §7.2.4 only partly met; odd row order. | Rows reworded ("Partly"), sorted by subclause. |
| 15 | Precision depends on the base rate. | False positives on the 16 hard negatives are reported: d3 5, rules 2, both 7; none on clean results. |
| 16 | Catalog over-blocking presented as inherent; the earlier rules + d3 result omitted; benign set written by us. | All three stated, including that part of it may be fixable through the question wording. |
| 17 | The abstract's "adds 0.33–0.35 s" isn't what was measured. | Now "spends … on its checks". |
| 2, 3 | Paired count used any judge block; labelling-rule blind spots. | Generator now counts only attacker-call blocks (same 67). The recall caveat is in the text. |
| 4, 8 | "0.03" comes from the E3 spike; the evaluated runs used the old d3 batch format. | Both stated in Appendix D. |
| 5 | F1 0.996 printed as 1.00. | Values below 1 that would round to 1.00 now get 3 decimals (figure and macros). |
| 6, 7, 14, 18, 24 | Scan details; subject-line example; session eviction (not just use-up); trusted pasted text; d3-flash weights unverified. | All corrected or added. |
| 21, 22, 25, 26 | Rule collision in Appendix D; Table 4 caption and row label; utility sentence in the Cost paragraph; "agent models". | Fixed. |
| 20, 23 | Author placeholder; `paper/` untracked. | **Open:** needs the author block from the user; commit once the user approves. |

Also corrected EXPERIMENTS.md's "set by hand on dev".

## Round 4 (2026-11-13)

Found 21 issues: 1 critical, 4 major, 16 minor. All macros and tables regenerate byte-identical
and match the reviewer's independent recomputation. The offline demo (`demo.replay --stub`) ran
cleanly. Because a critical finding remained, round 5 follows; that is the last round before
checking with the user.

| # | Finding | Action |
|---|---|---|
| 1 | **Critical.** "Goal 13 untested" and "no other goal ever worked without a guard" are contradicted by dev data: goal 13 succeeded 3 times undefended (E7), and the judge-only config blocked all 3 (P ≤ 0.007). | Verified. The paired-goal sentence is scoped to the test split. §7 now reports the dev evidence (macros) and that the final config was not run on those pairs. EXPERIMENTS.md "What we know now" #7 corrected. |
| 2 | "The judge alone stopped every attack these components stopped" holds only for tool poisoning. | Restricted to tool poisoning; for data injections the rules catch what d3 misses, and the judge as backstop is untested. |
| 3 | A compromised server also sees the arguments of unjudged read-only calls, so exfiltration through them goes undetected. | Added to §7. |
| 4 | The tainted 0.7 threshold is unvalidated and plausibly harmful (benign `user_task_25` calls scored as low as 0.63). | Added to §7 (macro). |
| 5 | `paper/` is not in the linked repo. | **Open:** commit and push once the user approves. |
| 6–20 | Minor: Table 3's cross-reference pointed to the wrong appendix; the two rule sets were conflated; the label rule was described inexactly and an unreproducible "we checked" claim was made; the scanner's "caught" was undefined; the independence caveat applied to only one bound; d3-flash weights do exist (now cited); the §7.2.2 row was too strong; the unknown-tool claim conflicted with §7; `judge_aware` was called adaptive (now "static, judge-aware"); the policy-only row label was incomplete; "not security" was unsupported; "the model sees" should be "d3 sees"; the `/nlip` path belongs to the course framework, not ECMA-431; reproducibility wording; NLIP vs tool boundaries in the conclusion. | All fixed. The unreproducible check was removed rather than kept. |
| 21 | Author placeholder. | **Open.** |

Space: related work became one paragraph and §7 was tightened; Figures 1 and 2 are slightly
shorter. The body ends on page 5 and the PDF is 7 pages.

## Round 5 (2026-11-14)

Found 19 issues: **0 critical**, 3 major, 16 minor. All generated files regenerate byte-identical,
and the reviewer's independent checks confirm every headline number. They also confirm:
- the two "no-act" paired cases are genuine;
- no unlabelled attacker call sits behind recall = 1.00;
- the `user_task_25` reordering;
- all SCO numbers and titles;
- all design constants.

| # | Finding | Action |
|---|---|---|
| M1 | The threat model was inconsistent: a compromised server needs no agent to do harm. | The attacker now controls only tool metadata and returned content (e.g. a malicious description update via a registry or proxy). Backend compromise is out of scope, and shadowing across servers is stated as untested. |
| M2 | The primary SCO is §7.3.1, but the end-to-end evidence is for §7.3.2 / §7.2.3. | Kept §7.3.1 as the primary *threat*. §2 and Table 1 now say plainly that the end-to-end evidence is for blocking induced actions, and the filtering part (the scanner) was evaluated only offline. |
| M3 | The case for dropping the catalog check omitted the evidence for it. | It is now framed as a trade-off: best end-to-end task completion, and kept 100% of real AgentDojo descriptions, against stripping all documentation from 57 of 392 poisoned tools and the parameter blind spot. Details moved to Appendix C (macros). |
| m1–m16 | Conclusion scoped to the labelling rule; E12 (plain parameter poisoning, 2/300) reported; scanner text fixed for unstructured results; `<INFORMATION>` misses include our `judge_aware`; "caught" defined (first 40 characters, test split only); attacker-triggered taint added as a denial-of-service limit; ablation label; generator prints the actual goal set and has an "attacker call allowed" bucket (0); reproduction table covers E5 `hybrid_d3` and the dev goal-13 runs; §7.2.2 row credits the allow-list; no Type-3 hook in the framework, so the tool-boundary adapter is per framework; long sentences split; one rounding precision for percentages; the Type-3 definition attributed to the course architecture; `judge_aware` says nothing about judge resistance. | All applied. m15 (citations unverifiable offline): MCP-Guard and the d3-flash card were verified by web search earlier. |

**Stopping:** this is the fifth round, the cap set in the plan. Rounds 1–4 each had a critical
error; round 5 had none, and its majors were framing issues, which are now addressed. The body
ends on page 5, and the PDF is 7 pages.

## After round 5: reframing (2026-11-15, at the user's request)

The headline is now the paired with/without comparison instead of "0 of 900":
- 69 cases succeeded without ToolGuard, and none with it (67 blocked, 2 not attempted);
- benign tasks completed 58/60 with ToolGuard and 59/60 without.

Changed: abstract, contribution 3, the first two results paragraphs ("Attacks with and without
ToolGuard", "Benign tasks with and without ToolGuard") and the conclusion. Figure 2's top panel
now shows hijacked-case counts (of 150) instead of percentages. Plain parameter poisoning (2/300)
moved into §7. All numbers still come from macros. No new claims, so no further review round.
