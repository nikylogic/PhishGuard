// The page's boot data from Flask, the JSON API client and small formatters.
// Untrusted text (titles, URLs, page text) is only ever rendered as React text, never as HTML.

export type Role = "admin" | "analyst"
export type User = { id: number; username: string; role: Role }
export type Level = "clear" | "caution" | "danger" | "pending"

const root = document.getElementById("root") as HTMLElement

export const boot = {
  page: root.dataset.page ?? "home",
  sid: Number(root.dataset.sid ?? 0),
  user: root.dataset.user ? (JSON.parse(root.dataset.user) as User) : null,
  standalone: root.dataset.standalone === "1",
  next: root.dataset.next ?? "/",
  nonce: root.dataset.nonce ?? "",
  title: root.dataset.title ?? "",
  text: root.dataset.text ?? "",
  // "personal": one person, no passwords. "accounts": usernames, passwords and roles.
  mode: (root.dataset.mode ?? "accounts") as "personal" | "accounts" | "unset",
}

let csrf = root.dataset.csrf ?? ""

export class ApiError extends Error {
  status: number
  constructor(message: string, status: number) {
    super(message)
    this.status = status
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function api<T = any>(path: string, opts: { method?: string; body?: unknown } = {}): Promise<T> {
  const method = opts.method ?? "GET"
  const headers: Record<string, string> = { Accept: "application/json" }
  const init: RequestInit = { method, headers, credentials: "same-origin" }
  if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json"
    init.body = JSON.stringify(opts.body)
  }
  if (method !== "GET") headers["X-CSRF-Token"] = csrf
  const res = await fetch(path, init)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let data: any = {}
  try {
    data = await res.json()
  } catch {
    data = {}
  }
  if (!res.ok) throw new ApiError(data?.error || `Request failed (${res.status})`, res.status)
  if (data && typeof data.csrf === "string") csrf = data.csrf // login rotates the token
  return data as T
}

export const WORD: Record<Level, string> = { clear: "Clear", caution: "Caution", danger: "Danger", pending: "Checking" }

// Tailwind classes for each verdict (text / background / soft background).
export const TONE: Record<Level, { text: string; bg: string; soft: string; hero: string }> = {
  clear: { text: "text-clear", bg: "bg-clear", soft: "bg-clear/10", hero: "from-clear/15" },
  caution: { text: "text-caution", bg: "bg-caution", soft: "bg-caution/10", hero: "from-caution/15" },
  danger: { text: "text-danger", bg: "bg-danger", soft: "bg-danger/10", hero: "from-danger/15" },
  pending: { text: "text-muted-foreground", bg: "bg-muted-foreground", soft: "bg-muted", hero: "from-primary/5" },
}

export const band = (v: number): Level => (v >= 50 ? "danger" : v >= 20 ? "caution" : "clear")

// SQLite stores UTC as "YYYY-MM-DD HH:MM:SS": turn it into a Date.
// The database stores UTC as "YYYY-MM-DD HH:MM:SS"; ISO strings that already carry a zone are used as they are.
export const when = (ts: string | null | undefined) =>
  ts ? new Date(/(Z|[+-]\d\d:\d\d)$/.test(ts) ? ts : ts.replace(" ", "T") + "Z") : null

const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto", style: "short" })
export function ago(ts: string | null | undefined): string {
  const d = when(ts)
  if (!d) return "never"
  const s = Math.round((d.getTime() - Date.now()) / 1000)
  const a = Math.abs(s)
  if (a < 45) return "just now"
  if (a < 3600) return rtf.format(Math.round(s / 60), "minute")
  if (a < 86400) return rtf.format(Math.round(s / 3600), "hour")
  if (a < 86400 * 30) return rtf.format(Math.round(s / 86400), "day")
  return d.toLocaleDateString()
}

// Split a URL so the real website (registrable domain) can be shown on its own.
export function urlParts(url: string, domain?: string): [string, string, string] {
  try {
    const u = new URL(url)
    const host = u.hostname
    const i = domain ? host.lastIndexOf(domain) : -1
    const before = i > 0 ? host.slice(0, i) : ""
    const main = i >= 0 ? host.slice(i) : host
    const rest = (u.port ? ":" + u.port : "") + u.pathname + u.search + u.hash
    return [u.protocol + "//" + before, main, rest]
  } catch {
    return ["", url, ""]
  }
}

export const go = (href: string) => {
  window.location.href = href
}

export const errText = (e: unknown) => (e instanceof Error ? e.message : String(e))
