// PhishGuard's address check, in the browser. A port of phishguard/urltools.py, rules.py
// (url_findings, verdict) and the list and domain-age checks, driven by data/engine.json, which
// scripts/build_site_data.py exports from the engine itself. tests/test_site_checker.py runs the
// same links through both and requires the same findings.
//
// Nothing here sends the link anywhere. The phishing-list lookup fetches one of 256 shards by
// the first byte of a SHA-256 hash; the age lookup sends only the domain name to its registry.
;(function (root) {
  "use strict"

  // --- punycode (RFC 3492), decoding only: what a person sees for xn-- labels ---------------
  function punyDecode(input) {
    const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700
    const out = []
    let i = 0, n = 128, bias = 72
    const basic = input.lastIndexOf("-")
    for (let j = 0; j < Math.max(basic, 0); j++) out.push(input.charCodeAt(j))
    const adapt = (delta, num, first) => {
      delta = first ? Math.floor(delta / damp) : delta >> 1
      delta += Math.floor(delta / num)
      let k = 0
      while (delta > ((base - tMin) * tMax) >> 1) { delta = Math.floor(delta / (base - tMin)); k += base }
      return k + Math.floor(((base - tMin + 1) * delta) / (delta + skew))
    }
    for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length;) {
      const oldi = i
      for (let w = 1, k = base; ; k += base) {
        if (idx >= input.length) throw new Error("bad punycode")
        const c = input.charCodeAt(idx++)
        const digit = c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : base
        if (digit >= base) throw new Error("bad punycode")
        i += digit * w
        const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias
        if (digit < t) break
        w *= base - t
      }
      bias = adapt(i - oldi, out.length + 1, oldi === 0)
      n += Math.floor(i / (out.length + 1))
      i %= out.length + 1
      out.splice(i++, 0, n)
    }
    return String.fromCodePoint(...out)
  }

  function toUnicodeHost(host) {
    return host.split(".").map((l) => {
      if (!l.startsWith("xn--")) return l
      try { return punyDecode(l.slice(4)) } catch (e) { return l }
    }).join(".")
  }

  // --- the engine ------------------------------------------------------------------------------
  function Engine(data) {
    const E = this
    E.data = data
    const set = (a) => new Set(a)
    E.brands = data.brands.map(([t, d]) => [t, set(d)])
    E.allBrandDomains = new Set(data.brands.flatMap(([, d]) => d))
    E.noFuzz = set(data.noFuzz)
    E.popular = set(data.popular)
    E.freeHosts = set(data.freeHosts)
    E.freeHostNames = set(data.freeHostNames)
    E.shorteners = set(data.shorteners)
    E.riskyTlds = set(data.riskyTlds)
    E.ipLoggers = data.ipLoggers
    E.lureWords = set(data.lureWords)
    E.trackingParams = set(data.trackingParams)
    E.suffixes = set(data.suffixes)
    E.supporting = set(data.supporting)
    E.threatTracking = set(data.threatTracking)
  }

  Engine.prototype.make = function (code, fmt, weight) {
    const [category, w, message] = this.data.rules[code]
    const text = fmt ? message.replace(/\{(\w+)\}/g, (_, k) => (k in fmt ? String(fmt[k]) : `{${k}}`)) : message
    return { code, category, weight: weight == null ? w : weight, message: text }
  }

  // tldextract over the bundled ICANN public-suffix rules (urltools._extract).
  Engine.prototype.split = function (host) {
    const labels = host.split(".")
    for (let i = 0; i < labels.length; i++) {
      const cand = labels.slice(i).join(".")
      let suffixAt = -1
      if (this.suffixes.has("!" + cand)) suffixAt = i + 1
      else if (this.suffixes.has(cand)) suffixAt = i
      else if (i + 1 < labels.length && this.suffixes.has("*." + labels.slice(i + 1).join("."))) suffixAt = i
      if (suffixAt >= 0) {
        const suffix = labels.slice(suffixAt).join(".")
        if (suffixAt === 0) return { sub: "", name: "", suffix }
        return { sub: labels.slice(0, suffixAt - 1).join("."), name: labels[suffixAt - 1], suffix }
      }
    }
    return { sub: labels.slice(0, -1).join("."), name: labels[labels.length - 1], suffix: "" }
  }

  const SCHEME = /^([a-zA-Z][a-zA-Z0-9+.\-]*):/

  // urltools.normalise + parse. Throws an Error with a plain message for anything that is not a
  // web link. The browser's own URL parser already reads backslashes, numeric IPs and
  // international names the way the browser will open them, which is what the engine emulates.
  Engine.prototype.parse = function (raw) {
    let s = String(raw == null ? "" : raw).trim().replace(/^[<>"']+|[<>"']+$/g, "").trim()
    if (!s) throw new Error("Paste a link to check.")
    if (s.length > 4096) throw new Error("That link is too long to check.")
    if (/[\u0000-\u001f]/.test(s)) throw new Error("That link contains control characters.")
    const m = SCHEME.exec(s)
    if (m && !["http", "https"].includes(m[1].toLowerCase()))
      throw new Error(`'${m[1].toLowerCase()}:' links are not web pages. PhishGuard never opens them.`)
    if (!m) s = s.startsWith("//") ? "https:" + s : "https://" + s
    let u
    try { u = new URL(s) } catch (e) { throw new Error("That does not look like a web address.") }
    if (!u.hostname) throw new Error("That link has no website address.")
    const host = u.hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase()
    const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":")
    let sub = "", name = host, suffix = "", reg = host
    if (!isIp) {
      ;({ sub, name, suffix } = this.split(host))
      reg = suffix && name ? `${name}.${suffix}` : host
    }
    return {
      url: u.href, scheme: u.protocol.slice(0, -1), host, hostUnicode: toUnicodeHost(host),
      port: u.port ? Number(u.port) : null, path: u.pathname, query: u.search.replace(/^\?/, ""),
      hasUserinfo: !!(u.username || u.password), subdomain: sub, domainName: name, suffix,
      registrable: reg, isIp,
    }
  }

  const matches = (host, listed) => host === listed || host.endsWith("." + listed)

  Engine.prototype.deconfuse = function (text) {
    let t = text.toLowerCase().normalize("NFKC")
    t = Array.from(t, (c) => this.data.confusables[c] || c).join("")
    for (const [a, b] of this.data.leet) t = t.split(a).join(b)
    return t
  }

  const SCRIPTS = ["Latin", "Cyrillic", "Greek", "Armenian", "Georgian", "Hebrew", "Arabic", "Devanagari",
    "Bengali", "Tamil", "Telugu", "Kannada", "Malayalam", "Gujarati", "Gurmukhi", "Thai", "Hangul",
    "Hiragana", "Katakana", "Han", "Cherokee", "Ethiopic", "Khmer", "Lao", "Myanmar", "Sinhala", "Tifinagh"]
  const SCRIPT_RE = SCRIPTS.map((s) => [s, new RegExp(`\\p{Script=${s}}`, "u")])
  function scriptsIn(label) {
    const out = new Set()
    for (const ch of label) {
      if (!/\p{L}/u.test(ch)) continue
      const hit = SCRIPT_RE.find(([, re]) => re.test(ch))
      out.add(hit ? hit[0] : "Other")
    }
    return out
  }

  function editDistance(a, b) {
    if (a === b) return 0
    a = Array.from(a); b = Array.from(b)
    if (a.length < b.length) [a, b] = [b, a]
    let prev = Array.from({ length: b.length + 1 }, (_, i) => i)
    for (let i = 1; i <= a.length; i++) {
      const cur = [i]
      for (let j = 1; j <= b.length; j++)
        cur.push(Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] !== b[j - 1] ? 1 : 0)))
      prev = cur
    }
    return prev[prev.length - 1]
  }

  Engine.prototype.isFreeHost = function (host, reg) {
    host = (host || "").toLowerCase().replace(/^www\./, "")
    if (this.freeHosts.has(reg) || this.freeHostNames.has(host)) return true
    for (const h of this.freeHosts) if (host.endsWith("." + h)) return true
    return false
  }
  Engine.prototype.isRestricted = function (reg) {
    return this.data.restricted.some((z) => reg === z || reg.endsWith("." + z))
  }
  Engine.prototype.isEstablished = function (host, reg) {
    return this.popular.has(reg) && !this.isFreeHost(host, reg)
  }
  Engine.prototype.brandName = function (t) { return this.data.brandNames[t] || t.charAt(0).toUpperCase() + t.slice(1) }

  Engine.prototype.brandFindings = function (p) {
    if (p.isIp || this.allBrandDomains.has(p.registrable) || this.isRestricted(p.registrable)) return []
    if (this.isEstablished(p.host, p.registrable)) return []
    const nameU = toUnicodeHost(p.domainName.toLowerCase())
    const tokens = [...new Set([nameU, ...nameU.split("-")])].filter(Boolean).map((t) => [t, this.deconfuse(t)])
    const subTokens = new Set()
    for (const part of p.subdomain.toLowerCase().split(".")) for (const t of part.split("-")) if (t) subTokens.add(t)
    const subDc = new Set([...subTokens, ...[...subTokens].map((t) => this.deconfuse(t))])
    for (const [brand, homes] of this.brands) {
      if (homes.has(p.registrable)) continue
      const len = Array.from(brand).length
      const limit = this.noFuzz.has(brand) ? 0 : len >= 9 ? 2 : len >= 6 ? 1 : 0
      let hit = null
      for (const [tok, dc] of tokens) {
        if (tok === brand) hit = "BRAND_IMPERSONATION"
        else if (dc === brand) hit = "BRAND_LOOKALIKE"
        else if (limit && Math.abs(Array.from(dc).length - len) <= limit) {
          const d = editDistance(dc, brand)
          if (d > 0 && d <= limit) hit = "BRAND_LOOKALIKE"
        }
        if (hit) break
      }
      if (hit) return [this.make(hit, { brand: this.brandName(brand) })]
      if (subDc.has(brand)) return [this.make("BRAND_IN_SUBDOMAIN", { brand: this.brandName(brand), reg: p.registrable })]
    }
    return this.brandInside(p)
  }

  Engine.prototype.brandInside = function (p) {
    const labels = [...p.subdomain.toLowerCase().split("."), p.domainName.toLowerCase()].filter(Boolean).map(toUnicodeHost)
    for (const [brand, homes] of this.brands) {
      if (this.noFuzz.has(brand) || brand.length < 4 || homes.has(p.registrable)) continue
      for (const label of labels) {
        for (const part of new Set([label, this.deconfuse(label)])) {
          const at = part.indexOf(brand)
          if (at < 0 || part === brand) continue
          if (brand.length >= 5 || at === 0)
            return [this.make("BRAND_IN_NAME", { brand: this.brandName(brand), name: label })]
        }
      }
    }
    return []
  }

  const unquote = (s) => { try { return decodeURIComponent(s.replace(/\+/g, "%20")) } catch (e) { return s } }
  const unquotePath = (s) => { try { return decodeURIComponent(s) } catch (e) { return s } }
  function queryPairs(q) {
    if (!q) return []
    return q.split(/[&;]/).filter(Boolean).map((part) => {
      const i = part.indexOf("=")
      return i < 0 ? [unquote(part), ""] : [unquote(part.slice(0, i)), unquote(part.slice(i + 1))]
    })
  }

  Engine.prototype.urlFindings = function (p) {
    const f = []
    if (p.isIp) f.push(this.make("IP_HOST"))
    if (p.hasUserinfo) f.push(this.make("USERINFO_AT"))
    if (p.host.includes("xn--")) {
      const labels = p.hostUnicode.split(".")
      f.push(this.make(labels.some((l) => scriptsIn(l).size > 1) ? "MIXED_SCRIPT" : "PUNYCODE"))
    }
    f.push(...this.brandFindings(p))
    if (!p.isIp && p.subdomain && p.subdomain.split(".").length > 3) f.push(this.make("MANY_SUBDOMAINS"))
    const tld = p.suffix ? p.suffix.split(".").pop() : ""
    if (tld && this.riskyTlds.has(tld)) f.push(this.make("RISKY_TLD", { tld }))
    if (this.shorteners.has(p.registrable)) f.push(this.make("SHORTENER"))
    if (p.scheme === "http") f.push(this.make("NO_HTTPS"))
    if (p.url.length > 100) f.push(this.make("LONG_URL"))
    if (p.port != null && p.port !== 80 && p.port !== 443) f.push(this.make("UNUSUAL_PORT", { port: p.port }))
    if ((p.domainName.match(/-/g) || []).length >= 3) f.push(this.make("MANY_HYPHENS"))
    if (!this.allBrandDomains.has(p.registrable)) {
      const hay = `${p.subdomain} ${p.domainName} ${unquotePath(p.path)} ${unquote(p.query)}`.toLowerCase()
      const words = [...new Set(hay.split(/[^a-z0-9]+/))].filter((w) => this.lureWords.has(w)).sort()
      if (words.length) f.push(this.make("LURE_WORDS", { words: words.slice(0, 3).join("', '") }))
    }
    if (this.ipLoggers.some((d) => matches(p.host, d))) f.push(this.make("IP_LOGGER"))
    const pairs = queryPairs(p.query)
    const tracked = [...new Set(pairs.map(([k]) => k).filter((k) => {
      const n = k.toLowerCase()
      return n.startsWith("utm_") || this.trackingParams.has(n)
    }))].sort()
    if (tracked.length) f.push(this.make("TRACKING_PARAMS", { params: tracked.slice(0, 4).join(", ") }))
    for (const [, v0] of pairs) {
      const v = v0.trim().toLowerCase()
      if (!/^(https?:\/\/|\/\/)/.test(v)) continue
      let target
      try { target = this.parse(v.includes("://") ? v : "https:" + v).registrable } catch (e) { continue }
      if (target !== p.registrable) { f.push(this.make("REDIRECT_PARAM", { target })); break }
    }
    return f
  }

  // --- scoring (rules.verdict) -------------------------------------------------------------
  const CATEGORIES = ["phishing", "malware", "tracking", "abuse"]
  function subScores(findings) {
    const s = Object.fromEntries(CATEGORIES.map((c) => [c, 0]))
    const seen = new Set()
    for (const x of findings) {
      if (seen.has(x.code)) continue
      seen.add(x.code)
      s[x.category] += x.weight
    }
    for (const c of CATEGORIES) s[c] = Math.min(100, s[c])
    return s
  }
  const levelFor = (score) => (score >= 50 ? "danger" : score >= 20 ? "caution" : "clear")
  Engine.prototype.role = function (x) {
    if (x.category === "tracking" && !this.threatTracking.has(x.code)) return "privacy"
    return this.supporting.has(x.code) ? "supporting" : "threat"
  }
  Engine.prototype.verdict = function (findings) {
    const subs = subScores(findings)
    const threats = findings.filter((x) => this.role(x) === "threat")
    const started = threats.length > 0 && Math.max(...Object.values(subScores(threats))) >= 20
    const counted = started ? [...threats, ...findings.filter((x) => this.role(x) === "supporting")] : threats
    const score = Math.max(...Object.values(subScores(counted)))
    return { score, level: levelFor(score), subs, counted: [...new Set(counted.map((x) => x.code))].sort() }
  }

  // --- phishing lists (feeds.Feeds.check, over hashed shards) --------------------------------
  function urlKey(p) {
    const host = p.host.replace(/^www\./, "")
    const path = p.path.replace(/\/+$/, "")
    return host + path + (p.query ? "?" + p.query : "")
  }
  async function sha16(text) {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))
    return Array.from(new Uint8Array(buf).slice(0, 8), (b) => b.toString(16).padStart(2, "0")).join("")
  }
  Engine.prototype.listed = async function (p, base, sources) {
    const key = urlKey(p)
    const host = key.split("/")[0].split("?")[0]
    const labels = host.split(".")
    const cands = []
    for (let i = 0; i < labels.length - 1; i++) cands.push("h:" + labels.slice(i).join("."))
    cands.push("u:" + key)
    const parts = key.split("?")[0].split("/")
    for (let i = parts.length; i > 1; i--) cands.push("u:" + parts.slice(0, i).join("/"))
    const hashes = await Promise.all(cands.map(sha16))
    const shards = {}
    for (const h of hashes) {
      const s = h.slice(0, 2)
      if (!shards[s]) shards[s] = fetch(`${base}/feed/${s}.json`).then((r) => (r.ok ? r.json() : {}))
    }
    for (const h of hashes) {
      const shard = await shards[h.slice(0, 2)]
      if (h in shard) return sources[shard[h]] || "a public list"
    }
    return null
  }

  // --- domain age (domaininfo.py: RDAP via the IANA bootstrap) -----------------------------
  Engine.prototype.worthAsking = function (p) {
    const reg = p.registrable
    if (!reg || !reg.includes(".") || p.isIp) return false
    if (this.allBrandDomains.has(reg) || this.isRestricted(reg) || this.isEstablished(p.host, reg)) return false
    return !this.isFreeHost(p.host, reg)
  }
  let bootstrap = null
  async function rdapBase(tld) {
    if (!bootstrap) bootstrap = fetch("https://data.iana.org/rdap/dns.json").then((r) => r.json()).then((d) => {
      const m = {}
      for (const [tlds, urls] of d.services || []) {
        const u = urls.find((x) => x.startsWith("https://")) || urls[0] || ""
        for (const t of tlds) m[t.toLowerCase()] = u.endsWith("/") ? u : u + "/"
      }
      return m
    }).catch(() => ({}))
    return (await bootstrap)[tld] || "https://rdap.org/"
  }
  // Why no age was looked up, in words for the report; null when it is worth asking.
  Engine.prototype.ageSkip = function (p) {
    const reg = p.registrable
    if (p.isIp) return "An IP address"
    if (!reg || !reg.includes(".")) return "Not a public website"
    if (this.allBrandDomains.has(reg)) return "The brand's own website"
    if (this.isRestricted(reg)) return "Verified-only domain"
    if (this.isFreeHost(p.host, reg)) return "Free hosting: anyone can publish"
    if (this.isEstablished(p.host, reg)) return "Well-known website"
    return null
  }
  // Days since registration, -1 when the registry has no such domain, null when unknown.
  Engine.prototype.ageDays = async function (p) {
    if (!this.worthAsking(p)) return null
    const reg = p.registrable
    const ctl = new AbortController()
    const timer = setTimeout(() => ctl.abort(), 6000)
    try {
      const base = await rdapBase(reg.split(".").pop())
      const r = await fetch(`${base}domain/${reg}`, { signal: ctl.signal, headers: { Accept: "application/rdap+json" } })
      if (r.status === 404) return -1
      if (!r.ok) return null
      const d = await r.json()
      const ev = (d.events || []).find((e) => (e.eventAction || "").toLowerCase() === "registration")
      const t = ev && Date.parse(ev.eventDate)
      return t ? Math.max(0, Math.floor((Date.now() - t) / 86400000)) : null
    } catch (e) {
      return null
    } finally {
      clearTimeout(timer)
    }
  }

  // The whole check: address rules, then the lists and the website's age in parallel.
  Engine.prototype.check = async function (raw, opts = {}) {
    const p = this.parse(raw)
    const findings = this.urlFindings(p)
    const [listed, age] = await Promise.all([
      opts.base ? this.listed(p, opts.base, opts.sources || []).catch(() => null) : null,
      opts.age === false ? null : this.ageDays(p),
    ])
    if (listed) findings.unshift(this.make("PHISH_LISTED", { source: listed }))
    if (age != null && age >= 0 && age < 30)
      findings.push(this.make("DOMAIN_NEW", { reg: p.registrable, days: age, how: "registered" }, age < 7 ? 20 : 10))
    return { parsed: p, findings, verdict: this.verdict(findings), age, ageSkip: this.ageSkip(p), listed }
  }

  const api = { Engine, toUnicodeHost }
  if (typeof module !== "undefined" && module.exports) module.exports = api
  else root.PhishGuardCheck = api
})(typeof self !== "undefined" ? self : this)
