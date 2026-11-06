// Shared helpers. Untrusted text (titles, URLs, page text) is only ever placed with
// textContent, never innerHTML, so a malicious page title cannot run code here.
"use strict";

const PG = (() => {
  const csrf = () => document.querySelector('meta[name="csrf"]').content;

  async function api(path, opts = {}) {
    const init = { method: opts.method || "GET", headers: { "Accept": "application/json" }, credentials: "same-origin" };
    if (opts.body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(opts.body);
    }
    if (init.method !== "GET") init.headers["X-CSRF-Token"] = csrf();
    const res = await fetch(path, init);
    let data = null;
    try { data = await res.json(); } catch (e) { data = {}; }
    if (!res.ok) {
      const err = new Error((data && data.error) || `Request failed (${res.status})`);
      err.status = res.status;
      throw err;
    }
    return data;
  }

  // h("div", {class: "x"}, "text", child) -> element
  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") el.className = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : v);
    }
    for (const kid of kids.flat()) {
      if (kid === null || kid === undefined || kid === false) continue;
      el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    }
    return el;
  }

  const WORD = { clear: "Clear", caution: "Caution", danger: "Danger", pending: "Checking" };
  const chip = (level) => h("span", { class: `chip ${level}` }, WORD[level] || level);

  function ago(ts) {
    if (!ts) return "";
    const t = new Date(ts.replace(" ", "T") + "Z").getTime();
    const s = Math.max(0, (Date.now() - t) / 1000);
    if (s < 60) return "just now";
    if (s < 3600) return `${Math.floor(s / 60)} min ago`;
    if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
    return new Date(t).toLocaleDateString(undefined, { day: "numeric", month: "short" });
  }

  // Split a URL so the real website (registrable domain) can be highlighted.
  function urlParts(url, domain) {
    try {
      const u = new URL(url);
      const host = u.hostname;
      const i = domain ? host.lastIndexOf(domain) : -1;
      const before = i > 0 ? host.slice(0, i) : "";
      const main = i >= 0 ? host.slice(i) : host;
      const rest = (u.port ? ":" + u.port : "") + u.pathname + u.search + u.hash;
      return [u.protocol + "//" + before, main, rest];
    } catch (e) { return ["", url, ""]; }
  }

  function toast(msg, kind = "") {
    let box = document.getElementById("toast");
    if (!box) {
      box = h("div", { id: "toast", role: "status", class: "notice" });
      box.classList.add("toast");
      document.body.append(box);
    }
    box.className = `notice toast ${kind}`;
    box.textContent = msg;
    box.hidden = false;
    clearTimeout(box._t);
    box._t = setTimeout(() => { box.hidden = true; }, 3200);
  }

  return { api, h, chip, ago, urlParts, toast, WORD };
})();
