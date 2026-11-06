// The Airlock: watches one check, then shows the stamp, gauges, reasons and actions.
"use strict";
(() => {
  const { api, h, urlParts, toast } = PG;
  const root = document.getElementById("airlock");
  const sid = root.dataset.sid;
  const $ = (id) => document.getElementById(id);
  let data = null, landed = false, polls = 0, settledPolls = 0;

  const HEAD = {
    pending: "Inspecting the link…",
    clear: "This link looks safe.",
    caution: "Be careful with this link.",
    danger: "Stop. This link is dangerous.",
  };
  const GAUGES = [["phishing", "Phishing"], ["malware", "Malware"], ["tracking", "Tracking"], ["abuse", "Tricks"]];
  const band = (v) => (v >= 50 ? "danger" : v >= 20 ? "caution" : "clear");

  async function poll() {
    try {
      data = await api(`/api/scan/${sid}`);
    } catch (e) {
      $("headline").textContent = e.status === 401 ? "Please log in to see this check." : "Could not load this check.";
      return;
    }
    render();
    polls++;
    const busy = data.status === "queued" || data.status === "running";
    if (!busy) settledPolls++;
    // Keep listening briefly after the verdict: the optional AI second opinion may raise it.
    if (busy && polls < 120) setTimeout(poll, 700);
    else if (!busy && settledPolls < 6) setTimeout(poll, 2500);
  }

  function render() {
    const d = data;
    const busy = d.status === "queued" || d.status === "running";
    const level = busy ? "pending" : d.level;

    let head = HEAD[level] || HEAD.pending;
    if (!busy && d.status === "failed") head = "PhishGuard could not look inside.";
    $("headline").textContent = head;

    // the luggage tag
    const [pre, main, rest] = urlParts(d.url, d.domain);
    $("tag-url").replaceChildren(pre, h("b", {}, main), rest);

    // the glass case
    $("sweep").hidden = !busy;
    if (d.screenshot_url && !document.getElementById("shot")) {
      const img = h("img", { id: "shot", src: d.screenshot_url, alt: `Screenshot of "${d.title || d.domain}" taken inside the sandbox` });
      $("glass").prepend(img);
      $("placeholder").hidden = true;
    } else if (!busy && !d.screenshot_url) {
      $("placeholder").textContent = d.error || "No picture was taken: the page was never opened.";
    }
    const t = d.page && d.page.timings;
    $("timing").textContent = t && t.total ? `inspected in ${t.total.toFixed(1)} s` : "";

    // stamp and score
    const stamp = $("stamp");
    stamp.className = `stamp ${level}`;
    stamp.textContent = busy ? "…" : PG.WORD[level].toUpperCase();
    if (!busy && !landed) { stamp.classList.add("land"); landed = true; }
    $("score").textContent = busy ? "–" : d.score;

    // gauges
    const g = $("gauges");
    if (!g.childElementCount) {
      for (const [key, name] of GAUGES) {
        g.append(h("div", { class: "gauge" },
          h("span", { class: "gauge-name" }, name),
          h("div", { class: "gauge-track", role: "meter", "aria-label": `${name} risk`, "aria-valuemin": "0", "aria-valuemax": "100" },
            h("div", { class: "gauge-fill", id: `g-${key}` })),
          h("span", { class: "gauge-num", id: `n-${key}` }, "0")));
      }
    }
    for (const [key] of GAUGES) {
      const v = busy ? 0 : d[`s_${key}`];
      const fill = $(`g-${key}`);
      fill.className = `gauge-fill ${band(v)}`;
      fill.style.width = `${Math.max(v, busy ? 0 : 1.5)}%`;
      fill.parentElement.setAttribute("aria-valuenow", v);
      $(`n-${key}`).textContent = busy ? "·" : v;
    }

    // reasons
    const items = (d.findings || []).filter((f) => f.weight > 0);
    const list = $("reasons");
    if (busy) list.replaceChildren(h("li", {}, "The page is being opened in the sandbox and watched…"));
    else if (!items.length) list.replaceChildren(h("li", {}, d.error || "Nothing suspicious was found."));
    else list.replaceChildren(...items.slice(0, 7).map((f) =>
      h("li", { class: f.weight >= 50 ? "w-high" : f.weight >= 20 ? "w-mid" : "" }, f.message)));

    renderActions(level, busy);
    renderTabs();
  }

  function renderActions(level, busy) {
    const open = $("open"), clean = $("open-clean"), block = $("block");
    open.disabled = clean.disabled = block.disabled = busy;
    if (level === "danger") {
      open.textContent = "Keep it locked";
      open.dataset.mode = "lock";
      clean.textContent = "Open anyway…";
      clean.dataset.mode = "anyway";
    } else {
      open.textContent = level === "caution" ? "Open with care" : "Open safely";
      open.dataset.mode = "open";
      const n = (data.params_removed || []).length;
      clean.textContent = n ? `Open clean link (−${n} tracker tag${n > 1 ? "s" : ""})` : "Open clean link";
      clean.dataset.mode = "clean";
    }
    if (data.decision === "blocked") { block.textContent = "Blocked"; block.disabled = true; }
  }

  async function decide(action, confirm = false) {
    try {
      await api(`/api/scan/${sid}/decision`, { method: "POST", body: { action, confirm } });
      const msg = { open: "Opened in your browser.", open_clean: "Opened the clean link in your browser.",
        open_direct: "Opened directly in your browser.", block: "Blocked. PhishGuard will stop this site next time.",
        ignore: "Good call. Nothing was opened." }[action];
      toast(msg, action === "block" || action === "ignore" ? "good" : "");
      if (action === "block") { data.decision = "blocked"; renderActions(data.level, false); }
    } catch (e) {
      if (e.status === 409 && action !== "open_direct") showConfirm(action);
      else toast(e.message, "bad");
    }
  }

  function showConfirm(action) {
    const box = $("confirm");
    box.classList.add("show");
    $("confirm-yes").onclick = () => { box.classList.remove("show"); decide(action, true); };
    $("confirm-no").onclick = () => { box.classList.remove("show"); decide("ignore"); };
    $("confirm-yes").focus();
  }

  $("open").addEventListener("click", (e) => {
    const mode = e.currentTarget.dataset.mode;
    if (mode === "lock") decide("ignore");
    else decide("open");
  });
  $("open-clean").addEventListener("click", (e) => {
    if (e.currentTarget.dataset.mode === "anyway") showConfirm("open");
    else decide("open_clean");
  });
  $("block").addEventListener("click", () => decide("block"));
  $("open-direct").addEventListener("click", () => {
    if (data && data.level === "danger") showConfirm("open_direct");
    else decide("open_direct", true);
  });
  $("copy").addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(data ? data.url : ""); toast("Link copied."); }
    catch (e) { toast("Could not copy.", "bad"); }
  });

  // ---- tabs ------------------------------------------------------------------
  for (const b of document.querySelectorAll(".tabs button")) {
    b.addEventListener("click", () => {
      for (const o of document.querySelectorAll(".tabs button")) o.setAttribute("aria-selected", o === b);
      for (const p of document.querySelectorAll(".tab-panel")) p.hidden = p.id !== `tab-${b.dataset.tab}`;
    });
  }

  function kv(pairs) {
    return h("dl", { class: "kv" }, pairs.filter(Boolean).flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));
  }
  const pills = (xs) => (xs && xs.length ? h("div", { class: "pill-list" }, xs.map((x) => h("span", { class: "pill" }, x))) : "None");

  function renderTabs() {
    const d = data, p = d.page || {};
    // Journey
    const hops = d.redirects && d.redirects.length ? d.redirects : [{ url: d.url, kind: "final", status: null }];
    const j = h("div", { class: "journey" });
    hops.forEach((hop, i) => {
      if (i) j.append(h("span", { class: "arrow", "aria-hidden": "true" }, "→"));
      const label = hop.kind === "final" ? "where it ended" : hop.kind === "script" ? "script redirect" : `redirect ${hop.status || ""}`;
      j.append(h("div", { class: `hop ${hop.kind === "final" ? "final" : ""}` }, h("small", {}, i === 0 ? "you clicked" : label), hop.url));
    });
    $("tab-journey").replaceChildren(j);

    // Privacy
    const pv = p.privacy || {};
    $("tab-privacy").replaceChildren(kv([
      ["IP logger", pv.ip_logger ? "Yes: opening this link records your IP address" : "Not detected"],
      ["Fingerprinting", pills(pv.fingerprinting)],
      ["WebRTC (local IP leak)", pv.webrtc ? "Used by the page" : "Not used"],
      ["Known trackers", pills(pv.trackers)],
      ["Tracking tags in the link", pills(d.params_removed)],
      ["Clean link", d.clean_url],
    ]));

    // Downloads
    const files = p.downloads || [];
    $("tab-files").replaceChildren(files.length
      ? h("table", { class: "list" },
          h("thead", {}, h("tr", {}, ["File name", "Really is", "Size", "SHA-256"].map((x) => h("th", {}, x)))),
          h("tbody", {}, files.map((f) => h("tr", {},
            h("td", { class: "url" }, f.filename), h("td", {}, (f.real_type || "unknown").replace(/-/g, " ")),
            h("td", {}, f.size ? `${(f.size / 1024).toFixed(1)} KB` : "–"),
            h("td", { class: "url" }, f.sha256 || "–")))))
      : h("p", { class: "muted" }, "The page did not try to download anything."));
    if (files.length) $("tab-files").append(h("p", { class: "muted" }, "Each file was caught in quarantine and renamed to .bin. It was never opened or run."));

    // AI Guard and the AI second opinion
    const gr = p.guard;
    const ai = [];
    if (gr) {
      ai.push(kv([["Prompt-injection score", `${Math.round(gr.score * 100)} / 100 (${gr.label})`],
                  gr.keywords && gr.keywords.length ? ["Phrases spotted", pills(gr.keywords)] : null]));
      if (gr.label === "injection" && gr.chunk) ai.push(h("p", {}, "Hidden sentence aimed at AI assistants:"), h("div", { class: "quote" }, gr.chunk));
    } else ai.push(h("p", { class: "muted" }, "AI Guard has not looked at this page."));
    if (d.llm) ai.push(h("h3", {}, "AI second opinion"), kv([["Risk", `${d.llm.risk} / 100 (${d.llm.category})`],
                                                               ["Reasons", d.llm.reasons.join(" ")], ["Model", d.llm.provider]]));
    $("tab-ai").replaceChildren(...ai);

    // Technical
    const tls = p.tls || {};
    $("tab-tech").replaceChildren(kv([
      ["Final address", d.final_url],
      ["Page title", d.title || "–"],
      ["HTTP status", p.http_status || "–"],
      ["Certificate", tls.issuer ? `${tls.subjectName} · issued by ${tls.issuer}` : "–"],
      ["Blocked by PhishGuard", pills((p.blocked || []).map((b) => `${b.url}  (${b.reason})`))],
      ["Websites contacted", pills(p.request_domains)],
      ["Status", d.status + (d.error ? ` · ${d.error}` : "")],
    ]));
  }

  poll();
})();
