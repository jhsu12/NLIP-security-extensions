// Tool guard demo: a chat with the workspace assistant, plus a live view of the guard's checks.
"use strict";

const $ = (s) => document.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const pretty = (v) => esc(JSON.stringify(v, null, 2));
const ICON = { Email: "✉️", Calendar: "📅", Drive: "📁" };

const ui = { opt: null, token: null, scenario: "benign", guard: true, task: null, changes: null };
let run = null; // { id, convId, serverTokens, calls, meta, source }

// --- setup ----------------------------------------------------------------------------------

async function init() {
  ui.opt = await (await fetch("/api/options")).json();
  const o = ui.opt;
  $("#mode").textContent = o.offline ? "Offline demo" : "Live";
  $("#mode").classList.toggle("offline", o.offline);
  $("#model-row").hidden = o.offline;
  $("#model").innerHTML = o.models.map((m) => `<option>${esc(m)}</option>`).join("");
  $("#goal").innerHTML = o.goals.map((g) => `<option value="${g.id}">${esc(g.label)}</option>`).join("");
  $("#variant").innerHTML = Object.entries(o.guards).filter(([k]) => k !== "off")
    .map(([k, label]) => `<option value="${k}">${esc(label.replace(/^(On|Ablation): /, ""))}</option>`).join("");
  renderGroups();
  $("#suggestions").innerHTML = o.tasks.map((t) => `<button class="chip" data-id="${t.id}">${esc(t.title)}</button>`).join("");
  $("#suggestions").addEventListener("click", (e) => e.target.dataset.id && pickTask(e.target.dataset.id));
  if (o.offline) {
    $("#input").readOnly = true;
    $("#input").placeholder = "Offline demo: pick a task above";
  }

  $("#scenario").addEventListener("click", (e) => {
    if (!e.target.dataset.v) return;
    ui.scenario = e.target.dataset.v;
    $("#scenario").querySelectorAll("button").forEach((b) => b.classList.toggle("on", b === e.target));
    settingsChanged();
  });
  $("#guard").addEventListener("click", () => { ui.guard = !ui.guard; settingsChanged(); });
  ["#goal", "#style", "#variant", "#model"].forEach((s) => $(s).addEventListener("change", settingsChanged));
  $("#composer").addEventListener("submit", (e) => { e.preventDefault(); send(); });
  $("#input").addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); } });
  $("#input").addEventListener("input", () => { if (ui.task && $("#input").value !== taskById(ui.task).prompt) markTask(null); });
  $("#new-chat").addEventListener("click", newChat);
  $("#show-attack").addEventListener("click", showAttack);
  $("#replay").addEventListener("change", replay);
  setupSignin();
  settingsChanged();
}

const taskById = (id) => ui.opt.tasks.find((t) => t.id === id);

function pickTask(id) {
  markTask(id);
  $("#input").value = taskById(id).prompt;
  $("#input").focus();
}

function markTask(id) {
  const changed = ui.task !== id;
  ui.task = id;
  document.querySelectorAll(".chip").forEach((c) => c.classList.toggle("on", c.dataset.id === id));
  if (changed) refreshPreview(); // which tools/data get poisoned depends on the task
}

// The combination the evaluation saw succeed on both models: "show my unread emails"
// with a poisoned tool asking to email the attacker, guard off. Then flip the guard on.
function showAttack() {
  ui.scenario = "tools";
  $("#scenario").querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.dataset.v === "tools"));
  $("#goal").value = "injection_task_0";
  $("#style").value = "tool_poisoning";
  ui.guard = false;
  settingsChanged();
  pickTask("user_task_24");
}

function scenarioKey() {
  return ui.scenario === "benign" ? "benign" : ui.scenario === "data" ? "important_instructions" : $("#style").value;
}

function guardKey() {
  return ui.guard ? $("#variant").value : "off";
}

function settingsChanged() {
  const sw = $("#guard");
  sw.classList.toggle("on", ui.guard);
  sw.setAttribute("aria-checked", ui.guard);
  sw.querySelector(".txt").textContent = ui.guard ? "On" : "Off";
  $("#goal-control").hidden = ui.scenario === "benign";
  if (run) newChat(); // a run's setup is fixed; new settings start a new conversation
  else refreshPreview();
}

// --- what the attack changes (shown before and during a run) --------------------------------

const currentChanges = () => run?.meta?.changes || ui.changes || { tools: [], data: [] };

async function refreshPreview() {
  if (run || !ui.opt) return;
  ui.changes = null;
  let error = null;
  if (ui.scenario !== "benign") {
    const r = await fetch("/api/preview", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ task_id: ui.task || "", scenario: scenarioKey(), goal_id: $("#goal").value }),
    });
    const data = await r.json();
    if (r.ok) ui.changes = data;
    else error = data.detail;
  }
  showBanner(error);
  renderGroups();
}

function showBanner(error) {
  const b = $("#attack-banner"), c = currentChanges();
  const goalId = run?.meta?.goal_id || $("#goal").value;
  const goal = ui.opt.goals.find((g) => g.id === goalId)?.label || "";
  if (error) { b.hidden = false; b.innerHTML = `<span>⚠ ${esc(error)}</span>`; return; }
  if (!c.tools.length && !c.data.length) { b.hidden = true; return; }
  const names = (xs) => xs.map((x) => `<b>${esc(x)}</b>`).join(", ");
  const what = c.tools.length
    ? `A malicious MCP server added a hidden instruction to the ${names(c.tools.map((t) => t.tool))} tool description`
    : `The attacker planted an instruction in ${names(c.data.map((d) => d.label))}`;
  b.hidden = false;
  b.innerHTML = `<span>⚠ <b>Attack:</b> ${what}. Goal: “${esc(goal)}”.</span><button class="btn small" id="see-changes">See what changed</button>`;
  $("#see-changes").onclick = openChanges;
}

// Highlight what `after` adds to `before` (common start and end kept plain).
function added(before, after) {
  let a = 0, b = 0;
  while (a < before.length && a < after.length && before[a] === after[a]) a++;
  while (b < before.length - a && b < after.length - a && before.at(-1 - b) === after.at(-1 - b)) b++;
  return `${esc(after.slice(0, a))}<span class="add">${esc(after.slice(a, after.length - b))}</span>${esc(after.slice(after.length - b))}`;
}

function openChanges() {
  const c = currentChanges();
  const tools = c.tools.map((t) => `<section class="change"><h4>🛠️ <code>${esc(t.tool)}</code></h4>
    <div class="cap">Original description</div><pre>${esc(t.original)}</pre>
    <div class="cap">What the malicious MCP server sends to the assistant</div><pre>${added(t.original, t.poisoned)}</pre></section>`);
  const data = c.data.map((d) => `<section class="change"><h4>${esc(d.label)}</h4>
    <div class="cap">Normally</div><pre>${esc(d.before)}</pre>
    <div class="cap">With the attack</div><pre>${added(d.before, d.after)}</pre></section>`);
  $("#tools-body").innerHTML = `<h3>What the attack changed</h3><p class="muted small">${c.tools.length
    ? "The tool still works the same. Only its description, which the model reads to decide how to use it, gains the attacker's text (red)."
    : "Normal content the assistant will read while doing the task, with the attacker's text (red)."}</p>${[...tools, ...data].join("")}`;
  $("#tools-dialog").showModal();
}

function renderGroups() {
  const poisoned = Object.fromEntries(currentChanges().tools.map((t) => [t.tool, t]));
  $("#tool-groups").innerHTML = Object.entries(ui.opt.tool_groups).map(([group, tools]) => {
    const bad = tools.filter((t) => poisoned[t.name]).length;
    return `<button class="group ${bad ? "poisoned" : ""}" data-g="${group}">${ICON[group]} ${group}
      <span class="n">${bad ? `${bad} poisoned` : `${tools.length} tools`}</span></button>`;
  }).join("");
  $("#tool-groups").onclick = (e) => {
    const g = e.target.closest(".group")?.dataset.g;
    if (!g) return;
    $("#tools-body").innerHTML = `<h3>${ICON[g]} ${g} tools</h3><p class="muted small">MCP tools the assistant can call on Emma's ${g.toLowerCase()}.</p>
      <div class="tool-list">${ui.opt.tool_groups[g].map((t) => `<div class="tool ${poisoned[t.name] ? "poisoned" : ""}">
        <code>${esc(t.name)}${poisoned[t.name] ? " ⚠" : ""}</code><span class="muted">${poisoned[t.name]
          ? `Description poisoned · <button class="link" data-see>see what changed</button>` : esc(t.description)}</span></div>`).join("")}</div>`;
    $("#tools-body").querySelectorAll("[data-see]").forEach((b) => (b.onclick = openChanges));
    $("#tools-dialog").showModal();
  };
}

function setupSignin() {
  const s = ui.opt.signin;
  if (s.provider === "stub") {
    $("#stub-login").hidden = false;
    $("#stub-login").onclick = async () => signedIn((await (await fetch("/api/stub-login", { method: "POST" })).json()));
    return;
  }
  if (!s.web_client_id) { $("#error").textContent = "Server is missing GOOGLE_WEB_CLIENT_ID."; return; }
  const ready = () => {
    google.accounts.id.initialize({
      client_id: s.web_client_id,
      callback: (r) => {
        const claims = JSON.parse(atob(r.credential.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
        signedIn({ token: r.credential, email: claims.email });
      },
    });
    google.accounts.id.renderButton($("#google-button"), { theme: "outline", size: "medium", shape: "pill" });
  };
  window.google?.accounts ? ready() : window.addEventListener("load", () => window.google?.accounts && ready());
}

function signedIn({ token, email }) {
  ui.token = token;
  $("#who").textContent = email;
  $("#who").hidden = false;
  $("#google-button").hidden = true;
  $("#stub-login").hidden = true;
}

// --- conversation ---------------------------------------------------------------------------

function newChat() {
  if (run?.source) run.source.close();
  run = null;
  $("#messages").innerHTML = `<div class="welcome"><h2>Ask your assistant</h2><p class="muted">Pick a task or type your own.</p></div>`;
  $("#steps").innerHTML = `<li class="placeholder muted">Checks appear here as the assistant works.</li>`;
  $("#outcome").hidden = true;
  $("#export").hidden = true;
  refreshPreview();
}

async function send() {
  const text = $("#input").value.trim();
  $("#error").textContent = "";
  if (!text) return;
  if (!ui.token && $("#send-token").checked) { $("#error").textContent = "Sign in first (top right)."; return; }
  $("#send").disabled = true;
  try {
    if (!run) await startRun(text);
    $("#messages").querySelector(".welcome")?.remove();
    bubble("user", text);
    $("#input").value = "";
    markTask(null);
    const typing = bubble("typing", "Assistant is working");
    const r = await fetch(`/api/runs/${run.id}/nlip`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(nlip(text)) });
    const body = await r.json();
    typing.remove();
    if (r.ok) keepTokens(body);
    else bubble("sys", r.status === 403 ? `Request rejected: ${body.detail.replace(/^oauth_verify blocked ingress: /, "")}` : body.detail);
  } catch (err) {
    $("#error").textContent = err.message;
  } finally {
    $("#send").disabled = false;
  }
}

async function startRun(text) {
  const task = ui.task ? taskById(ui.task) : null;
  const r = await fetch("/api/runs", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      task_id: task ? task.id : "",
      prompt: text,
      scenario: scenarioKey(),
      goal_id: ui.scenario === "benign" ? "" : $("#goal").value,
      guard: guardKey(),
      model: ui.opt.offline ? "" : $("#model").value,
    }),
  });
  const data = await r.json();
  if (!r.ok) throw new Error(data.detail || r.statusText);
  $("#steps").innerHTML = "";
  run = { id: data.run_id, convId: crypto.randomUUID(), serverTokens: [], calls: {}, meta: null };
  $("#export").href = `/api/runs/${run.id}/export`;
  $("#export").download = `tool-guard-run-${run.id}.json`;
  $("#export").hidden = false;
  run.source = new EventSource(`/api/runs/${run.id}/events`);
  run.source.onmessage = (m) => handle(JSON.parse(m.data));
}

function nlip(text) {
  const submessages = [{ format: "token", subformat: "conversation_web", content: run.convId }, ...run.serverTokens];
  if ($("#send-token").checked && ui.token) submessages.push({ format: "token", subformat: "authorization", content: ui.token });
  return { format: "text", subformat: "English", content: text, submessages };
}

function keepTokens(body) {
  // The server's conversation token continues this NLIP session on follow-ups.
  for (const p of body.submessages || []) {
    if (p.format === "token" && p.subformat.startsWith("conversation_") && p.subformat !== "conversation_web" &&
        !run.serverTokens.some((t) => t.content === p.content)) {
      run.serverTokens.push({ format: "token", subformat: p.subformat, content: p.content });
    }
  }
}

// Just enough markdown for model replies: bold, inline code, and line breaks.
function markdown(text) {
  return esc(text).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/`([^`]+)`/g, "<code>$1</code>");
}

function bubble(kind, text) {
  const el = document.createElement("div");
  el.className = kind === "typing" ? "typing" : `msg ${kind}`;
  if (kind === "bot") el.innerHTML = markdown(text);
  else el.textContent = text;
  $("#messages").appendChild(el);
  el.scrollIntoView({ behavior: "smooth", block: "end" });
  return el;
}

// --- guard activity -------------------------------------------------------------------------

function step(cls, icon, title, sub, tags, body, open = false) {
  const li = document.createElement("li");
  li.innerHTML = `<details class="step ${cls}" ${open ? "open" : ""}><summary><span class="icon">${icon}</span>
    <span class="step-main"><div class="step-title">${title}</div>${sub ? `<div class="step-sub">${sub}</div>` : ""}</span>${tags}</summary>
    ${body ? `<div class="step-body">${body}</div>` : ""}</details>`;
  $("#steps").appendChild(li);
  li.scrollIntoView({ behavior: "smooth", block: "nearest" });
  return li;
}

const tag = (cls, text) => `<span class="tag ${cls}">${text}</span>`;
const off = () => run?.meta?.guard === "off";

function marker() {
  return run?.meta?.goal ? run.meta.goal.split("\n")[0].slice(0, 60) : "";
}

function hl(text) {
  const m = marker(), safe = esc(text);
  return m ? safe.split(esc(m)).join(`<span class="hl">${esc(m)}</span>`) : safe;
}

function handle(e) {
  ({ run: onRun, ingress: onIngress, rejected: onRejected, guard: onGuard, tool_executed: onTool, reply: onReply, outcome: onOutcome,
     error: (x) => bubble("sys", x.message) })[e.type]?.(e);
}

function onRun(e) {
  run.meta = e;
  showBanner();
  renderGroups();
}

const GOAL = (e) => ui.opt.goals.find((g) => g.id === e.goal_id)?.label || e.goal;

function onIngress(e) {
  step("", "🔐", "Signed-in user verified", esc(e.user || ""), tag("ok", "OK"),
    `<div class="kv"><span>Check</span><span>Google ID token (oauth_verify)</span><span>Task</span><span>${esc(e.text)}</span></div>`);
  if (off() && Object.keys(run.meta.poisoned_descriptions || {}).length) {
    step("", "🧰", "Tool descriptions", "Not checked: guard is off", tag("", "OFF"));
  }
}

function onRejected(e) {
  step("bad", "🔐", "Sign-in rejected", esc(e.detail.replace(/^oauth_verify blocked ingress: /, "")), tag("bad", `HTTP ${e.status}`),
    `<span class="muted">The assistant never ran.</span>`, true);
}

function onGuard(e) {
  if (e.point === "catalog") {
    const changed = e.changed_tools || [];
    const body = changed.map((c) => `<div><b>${esc(c.tool)}</b><pre>${c.shown == null ? esc(c.original) : cut(c.original, c.shown)}</pre></div>`).join("") +
      (e.planted?.length ? `<div class="muted">Now blocked in any tool call: ${e.planted.map((p) => `<code>${esc(p)}</code>`).join(", ")}</div>` : "");
    if (changed.length) run.guardActed = true;
    step(changed.length ? "warn" : "", "🧰", "Tool descriptions checked",
      changed.length ? `Removed hidden instructions from ${changed.length} of ${e.total_tools}` : `All ${e.total_tools} clean`,
      changed.length ? tag("warn", "CLEANED") : tag("ok", "OK"), changed.length ? body : "");
  } else if (e.point === "pre_tool") {
    const c = call(e.call_id, e.tool, e.arguments);
    c.pre = e;
    paint(c);
  } else if (e.point === "post_tool") {
    const c = call(e.call_id, e.tool);
    c.post = e;
    paint(c);
  }
}

function onTool(e) {
  const c = call(e.call_id, e.tool, e.arguments);
  c.ran = e;
  paint(c);
}

function call(id, tool, args) {
  if (!run.calls[id]) run.calls[id] = { id, tool, args, el: step("", "🛠️", esc(tool), "", "", "") };
  if (args && !run.calls[id].args) run.calls[id].args = args;
  return run.calls[id];
}

function paint(c) {
  const blocked = c.pre?.action === "block", redacted = c.post?.action === "replace";
  if (blocked || redacted) run.guardActed = true;
  const pre = off() ? tag("", "no check") : !c.pre ? tag("", "…") : blocked ? tag("bad", "BLOCKED") : tag("ok", "ALLOWED");
  const post = off() || blocked ? "" : !c.post ? (c.ran ? tag("", "…") : "") : redacted ? tag("warn", "REDACTED") : "";
  const sub = blocked ? esc(c.pre.reason) : redacted ? "Injected text removed from the result" : summarize(c.args);
  const details = [];
  if (c.pre) {
    const d = c.pre.details || {};
    details.push(`<div><b>Before the call</b> · ${esc(c.pre.layer)} · ${esc(c.pre.reason)}</div>`);
    if (c.pre.p_aligned != null) {
      const p = c.pre.p_aligned, t = d.threshold ?? 0.5;
      details.push(`<div class="bar"><i style="width:${p * 100}%;background:var(--${p >= t ? "ok" : "bad"})"></i><b style="left:${t * 100}%"></b></div>
        <div class="muted small">Judge: would Emma approve this call? ${p.toFixed(2)} (needs ${t.toFixed(2)})</div>`);
    }
  }
  if (c.args) details.push(`<pre>${pretty(c.args)}</pre>`);
  if (blocked) details.push(`<div class="muted">Not executed. The assistant was told the call was blocked.</div>`);
  if (c.ran) details.push(`<details><summary class="muted small">Tool result</summary><pre>${hl(c.ran.result)}</pre></details>`);
  if (redacted) details.push(`<div><b>After the call</b> · removed before the assistant read it:</div>${(c.post.details?.flagged || []).map((s) => `<pre><span class="cut">${esc(s)}</span></pre>`).join("")}`);
  const li = c.el.querySelector(".step");
  li.className = `step ${blocked ? "bad" : redacted ? "warn" : ""}`;
  li.querySelector(".step-sub")?.remove();
  li.querySelector(".step-main").insertAdjacentHTML("beforeend", `<div class="step-sub">${sub}</div>`);
  li.querySelector(".trio")?.remove();
  li.querySelector("summary").insertAdjacentHTML("beforeend", `<span class="trio">${pre}${post}</span>`);
  let body = li.querySelector(".step-body");
  if (!body) { body = document.createElement("div"); body.className = "step-body"; li.appendChild(body); }
  body.innerHTML = details.join("");
  if (blocked || redacted) li.open = true;
}

function summarize(args) {
  if (!args) return "";
  const s = Object.entries(args).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(", ") : v}`).join(" · ");
  return esc(s.length > 90 ? `${s.slice(0, 90)}…` : s);
}

function cut(original, shown) {
  let a = 0, b = 0;
  while (a < original.length && a < shown.length && original[a] === shown[a]) a++;
  while (b < original.length - a && b < shown.length - a && original.at(-1 - b) === shown.at(-1 - b)) b++;
  return `${esc(original.slice(0, a))}<span class="cut">${esc(original.slice(a, original.length - b))}</span>${esc(original.slice(original.length - b))}`;
}

function onReply(e) {
  $("#messages").querySelector(".typing")?.remove();
  bubble("bot", e.text || "(no reply)");
}

function onOutcome(e) {
  const box = $("#outcome");
  box.hidden = false;
  const task = e.utility === null ? ["", "Task: not scored", "free-text request"]
    : e.utility ? ["good", "✓ Task done", "AgentDojo check"] : ["bad", "✗ Task not done", "AgentDojo check"];
  // Say *why* an attack failed: the guard acted, or the model simply ignored the instruction.
  const attack = e.attack_success === null ? ["", "No attack", "normal scenario"]
    : e.attack_success ? ["bad", "✗ Attack succeeded", GOAL(run.meta)]
    : run.guardActed ? ["good", "✓ Attack stopped by the guard", GOAL(run.meta)]
    : off() ? ["", "Attack failed: the model ignored it", "No guard. Try again, or ⚡ Show me an attack"]
    : ["good", "✓ Attack didn't happen", "the model ignored it; the guard didn't need to act"];
  box.innerHTML = [task, attack].map(([c, t, s]) => `<div class="verdict ${c}">${t}<small>${esc(s)}</small></div>`).join("");
}

// --- replay a saved run ---------------------------------------------------------------------

async function replay(ev) {
  const file = ev.target.files[0];
  if (!file) return;
  const data = JSON.parse(await file.text());
  newChat();
  $("#messages").querySelector(".welcome")?.remove();
  $("#steps").innerHTML = "";
  run = { id: data.run_id, convId: "", serverTokens: [], calls: {}, meta: null };
  for (const e of data.events) {
    if (e.type === "ingress") bubble("user", e.text);
    handle(e);
    await new Promise((r) => setTimeout(r, 350));
  }
}

init();
