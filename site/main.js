// Point the download buttons straight at the latest installer, and switch screenshots.
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

  const tabs = document.querySelectorAll(".tabs button")
  const img = document.getElementById("shot-img")
  const cap = document.getElementById("shot-cap")
  tabs.forEach((b, i) => {
    b.addEventListener("click", () => {
      tabs.forEach((t) => t.setAttribute("aria-selected", String(t === b)))
      img.src = b.dataset.src
      img.alt = b.dataset.alt
      cap.textContent = b.dataset.cap
    })
    b.addEventListener("keydown", (e) => {
      if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return
      const next = tabs[(i + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length]
      next.focus()
      next.click()
    })
  })
})()
