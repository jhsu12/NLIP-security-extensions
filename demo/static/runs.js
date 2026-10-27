// Run browser: pick a results file, filter its episodes, and step through them one by one.
"use strict";

(() => {
  const q = (s) => document.querySelector(s);
  const escape = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  const TONE = { "attack succeeded": "bad", "attack stopped by guard": "ok", "model ignored attack": "", "benign: task done": "ok",
                 "benign: task failed": "warn", "benign: false block": "bad", error: "warn" };
  const state = { files: [], episodes: [], shown: [], index: -1, events: null };

  async function load() {
    const data = await (await fetch("/api/results")).json();
    state.files = data.files;
    const preferred = data.files.find((f) => f.tag === "d3final") || data.files.find((f) => f.traced) || data.files[0];
    q("#file").innerHTML = data.files
      .map((f) => `<option value="${escape(f.name)}">${escape(f.config)} · ${escape(f.model)} · ${escape(f.split)}${f.tag ? " · " + escape(f.tag) : ""} — ${f.episodes} episodes${f.traced ? ` (${f.traced} traced)` : ""}</option>`)
      .join("");
    q("#f-outcome").innerHTML += data.outcomes.map((o) => `<option>${escape(o)}</option>`).join("");
    const hash = new URLSearchParams(location.hash.slice(1));
    q("#file").value = hash.get("file") || preferred?.name || "";
    await openFile(hash.get("key"));
  }

  async function openFile(key) {
    const name = q("#file").value;
    if (!name) return;
    state.episodes = (await (await fetch(`/api/results/${encodeURIComponent(name)}`)).json()).episodes;
    const attacks = [...new Set(state.episodes.map((e) => e.attack))].sort();
    const current = q("#f-attack").value;
    q("#f-attack").innerHTML = `<option value="">All attacks</option>` + attacks.map((a) => `<option>${escape(a)}</option>`).join("");
    if (attacks.includes(current)) q("#f-attack").value = current;
    renderCounts();
    applyFilters(key);
  }

  function renderCounts() {
    const counts = {};
    state.episodes.forEach((e) => (counts[e.outcome] = (counts[e.outcome] || 0) + 1));
    q("#counts").innerHTML = Object.entries(counts)
      .map(([o, n]) => `<button class="count tag ${TONE[o] || ""}" data-o="${escape(o)}">${escape(o)} · ${n}</button>`).join("");
    q("#counts").onclick = (ev) => {
      const o = ev.target.dataset.o;
      if (!o) return;
      q("#f-outcome").value = q("#f-outcome").value === o ? "" : o;
      applyFilters();
    };
  }

  function applyFilters(key) {
    const attack = q("#f-attack").value, out = q("#f-outcome").value, text = q("#f-text").value.trim().toLowerCase();
    state.shown = state.episodes.filter((e) => (!attack || e.attack === attack) && (!out || e.outcome === out) &&
      (!text || e.key.toLowerCase().includes(text)));
    q("#shown").textContent = `${state.shown.length} of ${state.episodes.length} episodes`;
    q("#episodes").innerHTML = state.shown.map((e, i) => `<li data-i="${i}">
        <div class="ep-key">${escape(e.user_task.replace("user_task_", "task "))}${e.goal ? ` × ${escape(e.goal.replace("injection_task_", "goal "))}` : ""}
          <span class="muted">· ${escape(e.attack)}</span></div>
        <div class="ep-tags"><span class="tag ${TONE[e.outcome] || ""}">${escape(e.outcome)}</span>
          <span class="tag">${e.task_done ? "task ✓" : "task ✗"}</span>${e.blocks ? `<span class="tag bad">${e.blocks} blocked</span>` : ""}
          ${e.redactions ? `<span class="tag warn">${e.redactions} redacted</span>` : ""}${e.traced ? "" : `<span class="tag">no trace</span>`}</div></li>`).join("");
    const at = key ? state.shown.findIndex((e) => e.key === key) : -1;
    select(at >= 0 ? at : state.shown.length ? 0 : -1);
  }

  async function select(index, animate = false) {
    if (index < 0 || index >= state.shown.length) return;
    state.index = index;
    document.querySelectorAll("#episodes li").forEach((li) => li.classList.toggle("on", Number(li.dataset.i) === index));
    q(`#episodes li[data-i="${index}"]`)?.scrollIntoView({ block: "nearest" });
    const e = state.shown[index], name = q("#file").value;
    history.replaceState(null, "", `#file=${encodeURIComponent(name)}&key=${encodeURIComponent(e.key)}`);
    q("#ep-title").textContent = e.key;
    q("#ep-title").classList.remove("muted");
    q("#ep-meta").textContent = `${e.outcome} · user task ${e.task_done ? "done" : "not done"} · guard ${(e.guard_ms / 1000).toFixed(2)} s · ` +
      `${e.judge_calls} d3 calls · ${e.wall_s ?? "?"} s total · episode ${index + 1} of ${state.shown.length}`;
    state.events = (await (await fetch(`/api/results/${encodeURIComponent(name)}/events?key=${encodeURIComponent(e.key)}`)).json()).events;
    window.toolGuardViewer.show(state.events, animate ? 300 : 0);
  }

  q("#file").addEventListener("change", () => openFile());
  ["#f-attack", "#f-outcome"].forEach((s) => q(s).addEventListener("change", () => applyFilters()));
  q("#f-text").addEventListener("input", () => applyFilters());
  q("#episodes").addEventListener("click", (ev) => { const li = ev.target.closest("li"); if (li) select(Number(li.dataset.i)); });
  q("#prev").addEventListener("click", () => select(state.index - 1));
  q("#next").addEventListener("click", () => select(state.index + 1));
  q("#replay-btn").addEventListener("click", () => state.events && window.toolGuardViewer.show(state.events, 300));
  q("#refresh").addEventListener("click", () => openFile(state.shown[state.index]?.key));
  document.addEventListener("keydown", (ev) => {
    if (ev.target.matches("input, select, textarea")) return;
    if (ev.key === "ArrowRight" || ev.key === "j") { ev.preventDefault(); select(state.index + 1); }
    if (ev.key === "ArrowLeft" || ev.key === "k") { ev.preventDefault(); select(state.index - 1); }
    if (ev.key === " ") { ev.preventDefault(); q("#replay-btn").click(); }
  });

  // app.js loads the shared options first; wait until its viewer hook exists.
  const ready = () => (window.toolGuardViewer ? load() : setTimeout(ready, 50));
  ready();
})();
