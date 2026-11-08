// Shared by every page: download links, the header, the docs contents list; plus the link
// checker, its report popup, the visitor's own check history and the struck-out lines.
(() => {
  const $ = (id) => document.getElementById(id)
  const still = matchMedia("(prefers-reduced-motion: reduce)").matches
  const DOWNLOAD = "https://github.com/nikylogic/PhishGuard/releases/latest"
  let installer = DOWNLOAD

  // --- download links point straight at the latest installer --------------------------------
  fetch("https://api.github.com/repos/nikylogic/PhishGuard/releases/latest", { headers: { Accept: "application/vnd.github+json" } })
    .then((r) => (r.ok ? r.json() : null))
    .then((rel) => {
      const exe = rel && (rel.assets || []).find((a) => /^PhishGuard-Setup-[\d.]+\.exe$/.test(a.name))
      if (!exe) return
      installer = exe.browser_download_url
      document.querySelectorAll("[data-dl]").forEach((a) => (a.href = installer))
      document.querySelectorAll("[data-version]").forEach((s) => (s.textContent = `Free · v${rel.tag_name.replace(/^v/, "")}`))
    })
    .catch(() => {}) // the links already lead to the releases page

  // --- header gets its rule once the page scrolls ---------------------------------------------
  const top = document.querySelector(".top")
  const onScroll = () => top && top.classList.toggle("scrolled", scrollY > 8)
  addEventListener("scroll", onScroll, { passive: true })
  onScroll()

  // --- docs: highlight the section being read --------------------------------------------------
  const tocLinks = [...document.querySelectorAll(".toc a")]
  if (tocLinks.length && "IntersectionObserver" in window) {
    const byId = new Map(tocLinks.map((a) => [a.getAttribute("href").slice(1), a]))
    const io = new IntersectionObserver((entries) => {
      for (const e of entries) if (e.isIntersecting) {
        tocLinks.forEach((a) => a.classList.remove("on"))
        byId.get(e.target.id)?.classList.add("on")
      }
    }, { rootMargin: "-90px 0px -70% 0px" })
    byId.forEach((_, id) => { const h = $(id); if (h) io.observe(h) })
  }

  // --- home: struck-out lines draw themselves ------------------------------------------------
  const lines = document.querySelectorAll(".strike")
  if (still || !("IntersectionObserver" in window)) lines.forEach((l) => l.classList.add("in"))
  else {
    const io = new IntersectionObserver((seen) => {
      for (const s of seen) if (s.isIntersecting) { s.target.classList.add("in"); io.unobserve(s.target) }
    }, { threshold: 0.6 })
    lines.forEach((l) => io.observe(l))
  }

  // --- home: the link checker -----------------------------------------------------------------
  const form = $("check")
  if (!form || !window.PhishGuardCheck) return
  const input = $("link"), btn = $("check-btn"), report = $("report"), dialog = $("report-dialog")
  let engine = null, sources = [], current = ""
  const load = () => (engine ||= Promise.all([
    fetch("data/engine.json").then((r) => r.json()),
    fetch("data/meta.json").then((r) => (r.ok ? r.json() : {})).catch(() => ({})),
  ]).then(([data, meta]) => {
    sources = (meta.feeds && meta.feeds.sources) || []
    return new PhishGuardCheck.Engine(data)
  }))
  input.addEventListener("focus", load, { once: true })
  if ("requestIdleCallback" in window) requestIdleCallback(() => load())

  // Small DOM builder; every piece of text goes in as text, never as HTML.
  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag)
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "class") el.className = v
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v)
      else el.setAttribute(k, v)
    }
    for (const k of kids.flat()) if (k != null && k !== false) el.append(k instanceof Node ? k : String(k))
    return el
  }

  // --- history: kept in this browser only (localStorage), never sent anywhere ----------------
  const KEY = "pg-history"
  const MAX = 50
  const readHistory = () => {
    try { const v = JSON.parse(localStorage.getItem(KEY) || "[]"); return Array.isArray(v) ? v : [] } catch (e) { return [] }
  }
  const writeHistory = (items) => { try { localStorage.setItem(KEY, JSON.stringify(items.slice(0, MAX))) } catch (e) {} }
  function remember(link, v, host) {
    const items = readHistory().filter((x) => x.link !== link)
    items.unshift({ link, host, level: v.level, score: v.score, at: Date.now() })
    writeHistory(items)
    drawHistory()
  }
  const ago = (t) => {
    const s = Math.round((Date.now() - t) / 1000)
    if (s < 60) return "just now"
    if (s < 3600) return `${Math.floor(s / 60)} min ago`
    if (s < 86400) return `${Math.floor(s / 3600)} h ago`
    return new Date(t).toLocaleDateString(undefined, { day: "numeric", month: "short" })
  }
  const LEVEL = { danger: "Danger", caution: "Caution", clear: "Clear" }
  function drawHistory() {
    const items = readHistory()
    const box = $("history")
    if (!box) return
    box.hidden = !items.length
    $("history-list").replaceChildren(...items.map((x) =>
      h("li", {},
        h("button", { type: "button", class: "hist", title: `Check ${x.link} again`, onclick: () => run(x.link) },
          h("span", { class: `badge ${x.level}` }, LEVEL[x.level] || x.level, h("b", {}, String(x.score))),
          h("span", { class: "hist-link" }, x.link),
          h("span", { class: "hist-time" }, ago(x.at))),
        h("button", { type: "button", class: "hist-del", "aria-label": `Remove ${x.link} from history`, onclick: () => {
          writeHistory(readHistory().filter((y) => y.link !== x.link)); drawHistory()
        } }, "×"))))
  }
  $("history-clear")?.addEventListener("click", () => { writeHistory([]); drawHistory() })
  drawHistory()

  // --- the report popup ------------------------------------------------------------------------
  const HEAD = {
    danger: ["Danger", "Stop. This link is dangerous."],
    caution: ["Caution", "Be careful with this link."],
    clear: ["Clear", "Nothing wrong with the address."],
  }
  const BARS = [["phishing", "Phishing"], ["tracking", "Tracking"], ["abuse", "Tricks"]]

  function render(res) {
    const { parsed: p, findings, verdict: v, age, ageSkip, listed } = res
    const [tag, title] = HEAD[v.level]
    const ageText = age === -1 ? "Not registered (dead link)"
      : age === 0 ? "Registered today"
      : age != null ? `${age.toLocaleString()} day${age === 1 ? "" : "s"} old`
      : ageSkip || "Registry did not answer"
    const at = p.url.indexOf(p.host)
    const shown = at >= 0 ? [p.url.slice(0, at), h("b", {}, p.host), p.url.slice(at + p.host.length)] : [p.url]
    const counted = new Set(v.counted)
    const why = findings.length
      ? h("ul", { class: "why" }, findings.map((x) => h("li", { class: counted.has(x.code) ? "hit" : "note" }, x.message)))
      : h("p", { class: "none" }, "No warning signs in the address.")
    report.replaceChildren(
      h("div", { class: `rep ${v.level}` },
        h("div", { class: "rep-head" },
          h("div", {}, h("span", { class: "lvl" }, tag), h("h2", { id: "rep-title" }, title)),
          h("div", { class: "score" }, h("b", {}, String(v.score)), " / 100")),
        h("p", { class: "rep-url" }, shown),
        h("div", { class: "rep-body" }, h("div", {}, h("h3", {}, "Why"), why),
          h("div", {}, h("h3", {}, "Risk"), h("div", { class: "bars" }, BARS.map(([k, label]) =>
            h("div", { class: "barrow" }, h("span", {}, label), h("b", {}, String(v.subs[k] || 0)),
              h("i", { style: `--w:${v.subs[k] || 0}%` })))))),
        h("dl", { class: "facts" },
          h("div", {}, h("dt", {}, "Phishing lists"), h("dd", {}, listed ? `Reported (${listed})` : "Not reported")),
          h("div", {}, h("dt", {}, "Website age"), h("dd", {}, ageText)),
          h("div", {}, h("dt", {}, "Really goes to"), h("dd", {}, p.registrable))),
        h("div", { class: "limit" },
          h("p", {}, "This looked at the address. The app also opens the page in a hidden browser, so it catches fake logins, downloads and pop-ups an address cannot show."),
          h("a", { class: "go small", href: installer }, "Download for Windows"))))
  }

  function fail(msg) {
    report.replaceChildren(h("div", { class: "rep error" }, h("h2", { id: "rep-title" }, "Could not check that link"), h("p", {}, msg)))
  }

  function open() {
    $("report-copy").textContent = "Copy link to this report"
    $("report-copy").hidden = !current
    if (!dialog.open) {
      if (typeof dialog.showModal === "function") dialog.showModal()
      else dialog.setAttribute("open", "")
    }
    dialog.scrollTop = 0
  }
  function close() {
    if (typeof dialog.close === "function") dialog.close()
    else dialog.removeAttribute("open")
  }
  dialog.addEventListener("close", () => {
    if (location.hash.startsWith("#check=")) history.replaceState(null, "", location.pathname + location.search)
    input.focus({ preventScroll: true })
  })
  $("report-close").addEventListener("click", close)
  dialog.addEventListener("click", (e) => { if (e.target === dialog) close() })   // click outside the card
  $("report-copy").addEventListener("click", async (e) => {
    const url = location.origin + location.pathname + "#check=" + encodeURIComponent(current)
    try { await navigator.clipboard.writeText(url); e.target.textContent = "Link copied" }
    catch (err) { e.target.textContent = "Copy failed" }
  })

  async function run(link, push = true) {
    input.value = link
    btn.disabled = true
    btn.textContent = "Checking…"
    try {
      const E = await load()
      const res = await E.check(link, { base: "data", sources })
      current = link
      render(res)
      remember(link, res.verdict, res.parsed.host)
      if (push) history.replaceState(null, "", "#check=" + encodeURIComponent(link))
    } catch (e) {
      current = ""
      fail(e && e.message && !/fetch|json|network/i.test(e.message) ? e.message : "The checker could not load. Please try again.")
    } finally {
      btn.disabled = false
      btn.textContent = "Check link"
    }
    open()
  }

  form.addEventListener("submit", (e) => {
    e.preventDefault()
    if (input.value.trim()) run(input.value.trim())
    else input.focus()
  })
  document.querySelectorAll("[data-try]").forEach((b) => b.addEventListener("click", () => run(b.dataset.try)))

  // A shared report: #check=<link>. The part after # never reaches the web server.
  const shared = location.hash.match(/^#check=(.+)$/)
  if (shared) { try { run(decodeURIComponent(shared[1]), false) } catch (e) {} }

  // --- the empty box types example links into its placeholder -------------------------------
  if (still) return
  const examples = ["hdfc-login-kyc.top/verify", "paypal.com-secure-help.site", "amaz0n-prime-billing.com", "bit.ly/3xYz9", "Paste a link to check it"]
  const wait = (ms) => new Promise((r) => setTimeout(r, ms))
  ;(async () => {
    await wait(1200)
    for (let i = 0; ; i = (i + 1) % examples.length) {
      if (document.activeElement === input || input.value || dialog.open) { input.placeholder = "Paste a link to check it"; await wait(1500); continue }
      const t = examples[i]
      for (let n = 1; n <= t.length; n++) {
        if (document.activeElement === input || input.value) break
        input.placeholder = t.slice(0, n) + "▌"
        await wait(45)
      }
      input.placeholder = t
      await wait(1800)
    }
  })()
})()
