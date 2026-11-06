"use strict";
(() => {
  const { api, h, chip, ago } = PG;
  const $ = (id) => document.getElementById(id);

  $("inspect").addEventListener("submit", async (e) => {
    e.preventDefault();
    const url = $("url").value.trim();
    if (!url) return;
    $("inspect-msg").textContent = "Sending it into the airlock…";
    try {
      const r = await api("/api/scan", { method: "POST", body: { url } });
      location.href = `/check/${r.id}`;
    } catch (err) {
      $("inspect-msg").textContent = err.message;
      $("inspect-msg").className = "notice bad";
    }
  });

  async function load() {
    const [s, list] = await Promise.all([api("/api/stats"), api("/api/scans?limit=8")]);
    $("t-today").textContent = s.today;
    $("t-stopped").textContent = s.stopped_today;
    $("t-trackers").textContent = s.trackers_today;
    if (s.today) {
      const parts = [`Today PhishGuard checked ${s.today} link${s.today > 1 ? "s" : ""}`];
      if (s.stopped_today) parts.push(`stopped ${s.stopped_today}`);
      if (s.trackers_today) parts.push(`spotted ${s.trackers_today} tracker${s.trackers_today > 1 ? "s" : ""}`);
      $("summary").textContent = parts.join(", ").replace(/, ([^,]*)$/, " and $1") + ".";
    }

    if (list.scans.length) {
      $("recent").replaceChildren(...list.scans.map((x) =>
        h("a", { class: "ticket", href: `/check/${x.id}` },
          h("div", { class: "row" }, chip(x.level), h("span", { class: "when" }, ago(x.created_at))),
          h("div", { class: "dom" }, x.domain),
          h("div", { class: "muted" }, x.title || (x.status === "failed" ? "Could not be opened" : "")))));
    }

    // a small stacked bar per day, last 7 days
    const byDay = Object.fromEntries(s.days.map((d) => [d.day, d]));
    const days = [...Array(7)].map((_, i) => {
      const d = new Date(Date.now() - (6 - i) * 86400000);
      return d.toISOString().slice(0, 10);
    });
    const max = Math.max(1, ...days.map((k) => byDay[k] ? byDay[k].clear + byDay[k].caution + byDay[k].danger : 0));
    $("week").replaceChildren(...days.map((k) => {
      const d = byDay[k] || { clear: 0, caution: 0, danger: 0 };
      const bar = h("div", { class: "bar" });
      const total = d.clear + d.caution + d.danger;
      bar.style.height = `${(total / max) * 110 + 4}px`;
      for (const lv of ["clear", "caution", "danger"]) {
        if (!d[lv]) continue;
        const seg = h("i", { class: lv, title: `${d[lv]} ${lv}` });
        seg.style.height = `${(d[lv] / total) * 100}%`;
        bar.append(seg);
      }
      const label = new Date(k + "T00:00:00").toLocaleDateString(undefined, { weekday: "short" });
      return h("div", { class: "day" }, h("span", {}, total || ""), bar, h("span", {}, label));
    }));

    if (s.top_dangerous.length) {
      $("top").replaceChildren(h("table", { class: "list" }, h("tbody", {}, s.top_dangerous.map((t) =>
        h("tr", {}, h("td", { class: "url" }, t.domain), h("td", {}, `${t.n}×`))))));
    }
  }
  load().catch(() => {});
})();
