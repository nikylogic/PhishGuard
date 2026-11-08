// Point the download buttons straight at the latest installer, switch the tabs, and remember the theme.
(() => {
  const RELEASE = "https://api.github.com/repos/nikylogic/PhishGuard/releases/latest"

  fetch(RELEASE, { headers: { Accept: "application/vnd.github+json" } })
    .then((r) => (r.ok ? r.json() : null))
    .then((rel) => {
      if (!rel) return
      const exe = (rel.assets || []).find((a) => /^PhishGuard-Setup-[\d.]+\.exe$/.test(a.name))
      if (!exe) return
      const mb = Math.round(exe.size / 1048576)
      for (const id of ["dl", "dl2"]) {
        const a = document.getElementById(id)
        if (a) a.href = exe.browser_download_url
      }
      const v = document.getElementById("dl-version")
      if (v) v.textContent = `Version ${rel.tag_name.replace(/^v/, "")}`
      const meta = document.querySelector(".dl-meta")
      if (meta) meta.innerHTML = meta.innerHTML.replace(/about \d+ MB/, `${mb} MB`)
      const f = document.getElementById("dl-file")
      if (f) f.textContent = exe.name
    })
    .catch(() => {}) // the buttons already lead to the releases page

  // A row of role="tab" buttons; `show(button)` does the switching. Arrow keys move along the row.
  function tablist(buttons, show) {
    buttons.forEach((b, i) => {
      b.addEventListener("click", () => {
        buttons.forEach((t) => {
          t.setAttribute("aria-selected", String(t === b))
          t.tabIndex = t === b ? 0 : -1
        })
        show(b)
      })
      b.addEventListener("keydown", (e) => {
        if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return
        const next = buttons[(i + (e.key === "ArrowRight" ? 1 : buttons.length - 1)) % buttons.length]
        next.focus()
        next.click()
      })
    })
  }

  const img = document.getElementById("shot-img")
  const cap = document.getElementById("shot-cap")
  tablist([...document.querySelectorAll(".tabs button")], (b) => {
    img.src = b.dataset.src
    img.alt = b.dataset.alt
    cap.textContent = b.dataset.cap
  })

  const logs = [...document.querySelectorAll(".term-tabs button")]
  tablist(logs, (b) => {
    for (const t of logs) document.getElementById(t.getAttribute("aria-controls")).hidden = t !== b
  })

  const root = document.documentElement
  document.querySelector(".theme")?.addEventListener("click", () => {
    const dark = root.dataset.theme
      ? root.dataset.theme === "dark"
      : matchMedia("(prefers-color-scheme: dark)").matches
    root.dataset.theme = dark ? "light" : "dark"
    try { localStorage.setItem("pg-theme", root.dataset.theme) } catch (e) {}
  })
})()
