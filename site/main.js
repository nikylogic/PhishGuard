// Download links point at the latest installer; the address bar types example links and shows each verdict.
(() => {
  fetch("https://api.github.com/repos/nikylogic/PhishGuard/releases/latest", { headers: { Accept: "application/vnd.github+json" } })
    .then((r) => (r.ok ? r.json() : null))
    .then((rel) => {
      const exe = rel && (rel.assets || []).find((a) => /^PhishGuard-Setup-[\d.]+\.exe$/.test(a.name))
      if (!exe) return
      for (const id of ["dl", "dl2", "dl3"]) {
        const a = document.getElementById(id)
        if (a) a.href = exe.browser_download_url
      }
      const v = document.getElementById("dl-version")
      if (v) v.textContent = `Free · v${rel.tag_name.replace(/^v/, "")}`
    })
    .catch(() => {}) // the links already lead to the releases page

  const still = matchMedia("(prefers-reduced-motion: reduce)").matches

  // The strike-through lines draw themselves when they scroll into view.
  const lines = document.querySelectorAll(".strike")
  if (still || !("IntersectionObserver" in window)) lines.forEach((l) => l.classList.add("in"))
  else {
    const io = new IntersectionObserver((seen) => {
      for (const s of seen) if (s.isIntersecting) { s.target.classList.add("in"); io.unobserve(s.target) }
    }, { threshold: 0.6 })
    lines.forEach((l) => io.observe(l))
  }

  if (still) return
  const url = document.getElementById("url")
  const verdict = document.getElementById("verdict")
  const examples = [
    ["hdfc-login-kyc.top/verify", "bad", "Fake. Stopped."],
    ["en.wikipedia.org/wiki/Tea", "ok", "Real. Opened."],
    ["files-share.example/invoice.pdf.exe", "hold", "Hidden program. Held."],
    ["paypal.com-secure-help.site", "bad", "Fake. Stopped."],
    ["github.com/nikylogic", "ok", "Real. Opened."],
  ]
  const wait = (ms) => new Promise((r) => setTimeout(r, ms))
  const show = (kind, text) => { verdict.className = `verdict ${kind}`; verdict.textContent = text }

  ;(async () => {
    let i = 0
    await wait(2600)
    for (;;) {
      i = (i + 1) % examples.length
      const [link, kind, text] = examples[i]
      for (let n = url.textContent.length; n >= 0; n -= 2) { url.textContent = url.textContent.slice(0, n); await wait(14) }
      show("wait", "Checking…")
      for (let n = 1; n <= link.length; n++) { url.textContent = link.slice(0, n); await wait(38) }
      await wait(900)
      show(kind, text)
      await wait(2600)
    }
  })()
})()
