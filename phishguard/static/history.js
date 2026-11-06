"use strict";
(() => {
  const { api, h, chip, ago } = PG;
  const rows = document.getElementById("rows");
  const q = document.getElementById("q"), level = document.getElementById("level");
  const DECISION = { pending: "–", opened: "Opened", blocked: "Blocked", ignored: "Kept locked" };
  const colour = (v) => (v >= 50 ? "var(--danger)" : v >= 20 ? "var(--caution)" : "var(--line-2)");

  async function load() {
    const p = new URLSearchParams({ q: q.value, level: level.value, limit: 200 });
    const { scans } = await api(`/api/scans?${p}`);
    if (!scans.length) { rows.replaceChildren(h("tr", {}, h("td", { colspan: 5, class: "empty" }, "No links match."))); return; }
    rows.replaceChildren(...scans.map((s) => {
      const g = h("div", { class: "mini-gauges", "aria-label": `phishing ${s.s_phishing}, malware ${s.s_malware}, tracking ${s.s_tracking}, tricks ${s.s_abuse}` });
      for (const v of [s.s_phishing, s.s_malware, s.s_tracking, s.s_abuse]) {
        const bar = h("i");
        bar.style.height = `${Math.max(3, v * 0.18)}px`;
        bar.style.background = colour(v);
        g.append(bar);
      }
      const tr = h("tr", { class: "click", tabindex: 0 },
        h("td", {}, chip(s.level)),
        h("td", { class: "url" }, s.url, s.title ? h("div", { class: "muted" }, s.title) : null),
        h("td", {}, g), h("td", {}, DECISION[s.decision] || s.decision), h("td", { class: "muted" }, ago(s.created_at)));
      const go = () => { location.href = `/check/${s.id}`; };
      tr.addEventListener("click", go);
      tr.addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });
      return tr;
    }));
  }
  let t;
  q.addEventListener("input", () => { clearTimeout(t); t = setTimeout(load, 250); });
  level.addEventListener("change", load);
  load();
})();
