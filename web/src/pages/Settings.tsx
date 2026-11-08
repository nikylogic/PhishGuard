import * as React from "react"
import { toast } from "sonner"
import { Trash2Icon, UserPlusIcon } from "lucide-react"

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Progress } from "@/components/ui/progress"
import { Spinner } from "@/components/ui/spinner"
import { Switch } from "@/components/ui/switch"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { ago, api, boot, errText, go } from "@/lib/api"

type SettingsData = {
  browsers: { name: string; path: string }[]
  browser_path: string
  llm_provider: string
  llm_model: string
  llm_api_key: string
}
type UserRow = { id: number; username: string; role: string; last_login: string | null }
type AuditRow = { id: number; created_at: string; username: string | null; action: string; detail: string | null }

const PROVIDERS = [
  { value: "none", label: "Off" },
  { value: "gemini", label: "Google Gemini (free tier)" },
  { value: "groq", label: "Groq (free tier)" },
  { value: "ollama", label: "Ollama (offline, on this PC)" },
]

// One column per tab, grouped by what people look for: how PhishGuard runs, how it decides,
// what it keeps, and who can use it.
export function Settings() {
  const personal = boot.mode === "personal"
  return (
    <Tabs defaultValue="general" className="gap-4 px-4 lg:px-6">
      <TabsList>
        <TabsTrigger value="general">General</TabsTrigger>
        <TabsTrigger value="detection">Detection</TabsTrigger>
        <TabsTrigger value="privacy">Privacy</TabsTrigger>
        <TabsTrigger value="accounts">{personal ? "Accounts" : "People"}</TabsTrigger>
        <TabsTrigger value="audit">Audit log</TabsTrigger>
      </TabsList>
      <TabsContent value="general">
        <Column>
          <Startup />
          <DefaultBrowser />
          <RealBrowser />
          <Updates />
          <About />
        </Column>
      </TabsContent>
      <TabsContent value="detection">
        <Column>
          <PhishingLists />
          <AiOpinion />
        </Column>
      </TabsContent>
      <TabsContent value="privacy">
        <Column>
          <HideMyIp />
          <History />
        </Column>
      </TabsContent>
      <TabsContent value="accounts">
        <Column>
          <AccountMode />
          {!personal && <Users />}
        </Column>
      </TabsContent>
      <TabsContent value="audit">
        <Audit />
      </TabsContent>
    </Tabs>
  )
}

function Column({ children }: { children: React.ReactNode }) {
  return <div className="grid max-w-3xl gap-4">{children}</div>
}

async function save(body: object, note = "Saved.") {
  try {
    await api("/api/settings", { method: "POST", body })
    toast.success(note)
    return true
  } catch (e) {
    toast.error(errText(e))
    return false
  }
}

function useSettings() {
  const [s, setS] = React.useState<SettingsData | null>(null)
  React.useEffect(() => {
    api<SettingsData>("/api/settings").then(setS).catch(() => null)
  }, [])
  return [s, setS] as const
}

// --- General ---------------------------------------------------------------------------------

type WinStatus = { supported: boolean; registered: boolean; default: boolean; shortcut: boolean; startup: boolean }

// Start with Windows: the engine starts quietly at sign-in, so the first link is checked at once.
function Startup() {
  const [st, setSt] = React.useState<WinStatus | null>(null)
  const [busy, setBusy] = React.useState(false)
  React.useEffect(() => {
    api<WinStatus>("/api/windows").then(setSt).catch(() => null)
  }, [])
  if (!st?.supported) return null
  const change = async (on: boolean) => {
    setBusy(true)
    try {
      setSt(await api<WinStatus>("/api/windows/startup", { method: "POST", body: { on } }))
    } catch (e) {
      toast.error(errText(e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-6">
        <div className="grid gap-1.5">
          <CardTitle>
            <label htmlFor="startup">Start with Windows</label>
          </CardTitle>
          <CardDescription>
            PhishGuard gets ready in the background when you sign in, so the first link you click is checked straight away. No window opens.
          </CardDescription>
        </div>
        <Switch id="startup" checked={st.startup} disabled={busy} onCheckedChange={change} />
      </CardHeader>
    </Card>
  )
}

// Windows only lets the Settings app change the default browser, so this registers PhishGuard and
// opens Settings on PhishGuard's own page. The user presses "Set default" there.
function DefaultBrowser() {
  const [st, setSt] = React.useState<WinStatus | null>(null)
  const [busy, setBusy] = React.useState(false)
  const load = React.useCallback(() => api<WinStatus>("/api/windows").then(setSt).catch(() => null), [])
  React.useEffect(() => {
    load()
  }, [load])
  // While Windows Settings is open, check every two seconds for a minute.
  const watch = () => {
    let n = 0
    const t = window.setInterval(async () => {
      n += 1
      const s = await api<WinStatus>("/api/windows").catch(() => null)
      if (s) setSt(s)
      if (s?.default || n >= 30) window.clearInterval(t)
    }, 2000)
  }
  const run = async (path: string, note: string) => {
    setBusy(true)
    try {
      setSt(await api<WinStatus>(path, { method: "POST" }))
      toast.success(note)
      watch()
    } catch (e) {
      toast.error(errText(e))
    } finally {
      setBusy(false)
    }
  }
  if (!st?.supported) return null
  return (
    <Card>
      <CardHeader>
        <CardTitle>Default browser</CardTitle>
        <CardDescription>
          {st.default
            ? "PhishGuard is your default browser. Links you click anywhere in Windows are checked first."
            : "Make PhishGuard your default browser so links you click anywhere in Windows are checked first."}
        </CardDescription>
      </CardHeader>
      {!st.default && (
        <CardContent className="text-sm text-muted-foreground">
          Windows will open its Settings on PhishGuard's page. Press <span className="font-medium text-foreground">Set default</span> there.
        </CardContent>
      )}
      <CardFooter className="gap-2">
        {st.default ? (
          <Button variant="outline" disabled={busy} onClick={() => run("/api/windows/remove", "Removed. Choose your old browser in Windows Settings.")}>
            Stop using PhishGuard for links
          </Button>
        ) : (
          <Button disabled={busy} onClick={() => run("/api/windows/default", "Windows Settings is open. Press Set default.")}>
            Make PhishGuard my default browser
          </Button>
        )}
      </CardFooter>
    </Card>
  )
}

function RealBrowser() {
  const [s, setS] = useSettings()
  if (!s) return null
  const change = async (v: string) => {
    const path = v === "auto" ? "" : v
    setS({ ...s, browser_path: path })
    await save({ browser_path: path }, "Safe links now open in this browser.")
  }
  return (
    <Card>
      <CardHeader>
        <CardTitle>Your real browser</CardTitle>
        <CardDescription>Safe links are handed to this browser. PhishGuard starts it directly, so links never loop back into PhishGuard.</CardDescription>
      </CardHeader>
      <CardContent>
        <Field>
          <FieldLabel htmlFor="browser">Browser</FieldLabel>
          <Select value={s.browser_path || "auto"} onValueChange={change}>
            <SelectTrigger id="browser" className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="auto">Detect automatically</SelectItem>
              {s.browsers.map((b) => (
                <SelectItem key={b.path} value={b.path}>
                  {b.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {s.browser_path && <FieldDescription className="font-mono text-xs break-all">{s.browser_path}</FieldDescription>}
        </Field>
      </CardContent>
    </Card>
  )
}

type UpdateStatus = {
  supported: boolean
  state: "idle" | "checking" | "downloading" | "ready" | "installing" | "up_to_date" | "error" | "unsupported"
  current: string
  latest: string | null
  mode: "auto" | "ask" | "off"
  checked_at: number | null
  error: string
  progress: number
  size: number
  last_result: { ok: boolean; version: string; from: string; at: number } | null
}

const UPDATE_MODES = [
  { value: "auto", label: "Install updates automatically" },
  { value: "ask", label: "Download, then ask me" },
  { value: "off", label: "Do not look for updates" },
]

// Updates come from PhishGuard's GitHub releases, signed with the PhishGuard release key.
function Updates() {
  const [st, setSt] = React.useState<UpdateStatus | null>(null)
  const [busy, setBusy] = React.useState(false)
  const load = React.useCallback(() => api<UpdateStatus>("/api/update").then(setSt).catch(() => null), [])
  React.useEffect(() => {
    load()
  }, [load])
  // Follow a check or download while it runs.
  React.useEffect(() => {
    if (st?.state !== "checking" && st?.state !== "downloading") return
    const t = window.setTimeout(load, 1500)
    return () => window.clearTimeout(t)
  }, [st, load])
  if (!st) return null
  const admin = boot.user?.role === "admin"
  const mode = async (v: string) => {
    setSt({ ...st, mode: v as UpdateStatus["mode"] })
    await save(
      { update_mode: v },
      v === "auto" ? "Updates install by themselves." : v === "ask" ? "PhishGuard will ask before installing." : "PhishGuard will not look for updates.",
    )
  }
  const check = async () => {
    setBusy(true)
    try {
      setSt(await api<UpdateStatus>("/api/update/check", { method: "POST" }))
    } catch (e) {
      toast.error(errText(e))
    } finally {
      setBusy(false)
    }
  }
  const install = async () => {
    setBusy(true)
    try {
      setSt(await api<UpdateStatus>("/api/update/install", { method: "POST" }))
      toast.success("Installing the update. PhishGuard restarts in about half a minute.")
    } catch (e) {
      toast.error(errText(e))
      setBusy(false)
    }
  }
  const pct = st.size ? Math.round((st.progress / st.size) * 100) : 0
  let line = ""
  if (!st.supported) line = "Updates are installed by the installed app. This copy runs from source."
  else if (st.state === "checking") line = "Looking for updates…"
  else if (st.state === "downloading") line = `Downloading PhishGuard ${st.latest}: ${pct}%`
  else if (st.state === "ready")
    line =
      st.mode === "auto"
        ? `PhishGuard ${st.latest} is downloaded and checked. It installs as soon as no link is being checked.`
        : `PhishGuard ${st.latest} is downloaded and checked.`
  else if (st.state === "installing") line = `Installing PhishGuard ${st.latest}…`
  else if (st.state === "up_to_date") line = "PhishGuard is up to date."
  else if (st.state === "error") line = st.error
  else if (st.mode !== "off") line = "PhishGuard looks for updates ten minutes after it starts and then twice a day."
  return (
    <Card>
      <CardHeader>
        <CardTitle>Updates</CardTitle>
        <CardDescription>
          You have PhishGuard {st.current}. Updates come from PhishGuard's GitHub page and are installed only if they carry
          PhishGuard's digital signature. Your history and settings are kept.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        {st.supported && (
          <Field>
            <FieldLabel htmlFor="update-mode">When an update comes out</FieldLabel>
            <Select value={st.mode} onValueChange={mode} disabled={!admin}>
              <SelectTrigger id="update-mode" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {UPDATE_MODES.map((m) => (
                  <SelectItem key={m.value} value={m.value}>
                    {m.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
        )}
        {line && <p className={st.state === "error" ? "text-sm text-danger" : "text-sm text-muted-foreground"}>{line}</p>}
        {st.state === "downloading" && <Progress value={pct} />}
        {st.last_result && (
          <p className="text-xs text-muted-foreground">
            {st.last_result.ok
              ? `Updated from ${st.last_result.from} to ${st.last_result.version} ${ago(new Date(st.last_result.at * 1000).toISOString())}.`
              : `The update to ${st.last_result.version} did not finish ${ago(new Date(st.last_result.at * 1000).toISOString())}; the installer's log is in the data folder (updates\install.log).`}
          </p>
        )}
        {st.supported && st.checked_at && (
          <p className="text-xs text-muted-foreground">Last checked {ago(new Date(st.checked_at * 1000).toISOString())}.</p>
        )}
      </CardContent>
      {admin && st.supported && (
        <CardFooter className="gap-2">
          <Button variant="outline" disabled={busy || st.state === "checking" || st.state === "downloading" || st.state === "installing"} onClick={check}>
            {(busy || st.state === "checking") && <Spinner />}
            Check now
          </Button>
          {st.state === "ready" && (
            <Button disabled={busy} onClick={install}>
              Install {st.latest} now
            </Button>
          )}
        </CardFooter>
      )}
    </Card>
  )
}

type HistoryStatus = { keep_days: number; checks: number; bytes: number; folder: string }

function About() {
  const [v, setV] = React.useState<{ version: string } | null>(null)
  const [h, setH] = React.useState<HistoryStatus | null>(null)
  React.useEffect(() => {
    api<{ version: string }>("/api/about").then(setV).catch(() => null)
    api<HistoryStatus>("/api/history").then(setH).catch(() => null)
  }, [])
  if (!v) return null
  return (
    <p className="px-1 text-xs text-muted-foreground">
      PhishGuard {v.version}
      {h && (
        <>
          {" · Data folder "}
          <span className="font-mono break-all">{h.folder}</span>
        </>
      )}
    </p>
  )
}

// --- Detection -------------------------------------------------------------------------------

type ListsStatus = {
  enabled: boolean
  ready: boolean
  sources: { name: string; count: number; updated: number | null; error: string | null }[]
}

// The public phishing lists, downloaded every six hours and checked on this PC.
function PhishingLists() {
  const [st, setSt] = React.useState<ListsStatus | null>(null)
  const [busy, setBusy] = React.useState(false)
  const load = React.useCallback(() => api<ListsStatus>("/api/feeds").then(setSt).catch(() => null), [])
  React.useEffect(() => {
    load()
  }, [load])
  const update = async () => {
    setBusy(true)
    try {
      await api("/api/feeds/update", { method: "POST" })
      toast.success("Updating the lists…")
      // The biggest list is about 11 MB; check back a few times.
      for (const ms of [3000, 8000, 20000]) window.setTimeout(load, ms)
    } catch (e) {
      toast.error(errText(e))
    } finally {
      window.setTimeout(() => setBusy(false), 3000)
    }
  }
  if (!st?.enabled) return null
  return (
    <Card>
      <CardHeader>
        <CardTitle>Phishing lists</CardTitle>
        <CardDescription>
          Public lists of reported phishing sites, updated every six hours. Links are checked against them on this PC; nothing is sent anywhere.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>List</TableHead>
              <TableHead className="text-right">Entries</TableHead>
              <TableHead className="text-right">Updated</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {st.sources.map((s) => (
              <TableRow key={s.name}>
                <TableCell>
                  {s.name}
                  {s.error && <div className="text-xs text-danger">Last update failed: {s.error}</div>}
                </TableCell>
                <TableCell className="text-right tabular-nums">{s.count.toLocaleString()}</TableCell>
                <TableCell className="text-right text-muted-foreground">
                  {s.updated ? ago(new Date(s.updated * 1000).toISOString()) : "not yet"}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
      {boot.user?.role === "admin" && (
        <CardFooter>
          <Button variant="outline" disabled={busy} onClick={update}>
            {busy && <Spinner />}
            Update now
          </Button>
        </CardFooter>
      )}
    </Card>
  )
}

function AiOpinion() {
  const [s, setS] = useSettings()
  if (!s) return null
  const set = (k: keyof SettingsData) => (v: string) => setS({ ...s, [k]: v })
  const on = !!s.llm_provider && s.llm_provider !== "none"
  return (
    <Card>
      <CardHeader>
        <CardTitle>AI second opinion</CardTitle>
        <CardDescription>Optional. An AI model reads the page and may raise the risk. It can never lower it.</CardDescription>
      </CardHeader>
      <CardContent>
        <FieldGroup>
          <Field>
            <FieldLabel htmlFor="provider">Provider</FieldLabel>
            <Select value={s.llm_provider || "none"} onValueChange={set("llm_provider")}>
              <SelectTrigger id="provider" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {PROVIDERS.map((p) => (
                  <SelectItem key={p.value} value={p.value}>
                    {p.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          {on && (
            <Field>
              <FieldLabel htmlFor="model">Model name</FieldLabel>
              <Input id="model" placeholder="leave empty for the default" value={s.llm_model} onChange={(e) => set("llm_model")(e.target.value)} />
            </Field>
          )}
          {on && s.llm_provider !== "ollama" && (
            <Field>
              <FieldLabel htmlFor="apikey">API key</FieldLabel>
              <Input id="apikey" type="password" autoComplete="off" value={s.llm_api_key} onChange={(e) => set("llm_api_key")(e.target.value)} />
            </Field>
          )}
        </FieldGroup>
      </CardContent>
      <CardFooter>
        <Button onClick={() => save({ llm_provider: s.llm_provider, llm_model: s.llm_model, llm_api_key: s.llm_api_key })}>Save</Button>
      </CardFooter>
    </Card>
  )
}

// --- Privacy ---------------------------------------------------------------------------------

type Privacy = {
  mode: "off" | "tor" | "warp" | "custom"
  proxy: string
  tor: { state: string; message: string; progress: number; version: string; installed: boolean }
  warp: { installed: boolean; ready: boolean; port: number | null; message: string }
}
type Seen = { ip: string; is_tor: boolean }
type TestResult = { route: string; seen: Seen | null; direct: Seen | null; error: string }

const ROUTES = [
  { value: "off", label: "Off" },
  { value: "tor", label: "Tor (built in, free)" },
  { value: "warp", label: "Cloudflare WARP (app on this PC)" },
  { value: "custom", label: "My own proxy" },
]

// Hide my IP: the sandbox reaches websites through Tor, WARP or a proxy, so they never see this PC's address.
function HideMyIp() {
  const [st, setSt] = React.useState<Privacy | null>(null)
  const [mode, setMode] = React.useState<Privacy["mode"]>("off")
  const [proxy, setProxy] = React.useState("")
  const [test, setTest] = React.useState<TestResult | null>(null)
  const [busy, setBusy] = React.useState(false)
  const load = React.useCallback(
    () =>
      api<Privacy>("/api/privacy")
        .then((s) => {
          setSt(s)
          return s
        })
        .catch(() => null),
    [],
  )
  React.useEffect(() => {
    load().then((s) => {
      if (s) {
        setMode(s.mode)
        setProxy(s.proxy)
      }
    })
  }, [load])
  // While Tor downloads or connects, refresh once a second.
  const torBusy = st?.tor.state === "downloading" || st?.tor.state === "starting"
  React.useEffect(() => {
    if (!torBusy) return
    const t = window.setInterval(load, 1000)
    return () => window.clearInterval(t)
  }, [torBusy, load])

  if (!st) return null
  const saveMode = async () => {
    setBusy(true)
    setTest(null)
    try {
      setSt(await api<Privacy>("/api/privacy", { method: "POST", body: { mode, proxy } }))
      toast.success(mode === "off" ? "Hide my IP is off." : "Saved. New checks use this route.")
    } catch (e) {
      toast.error(errText(e))
    } finally {
      setBusy(false)
    }
  }
  const download = async () => {
    try {
      setSt(await api<Privacy>("/api/privacy/tor", { method: "POST" }))
    } catch (e) {
      toast.error(errText(e))
    }
  }
  const runTest = async () => {
    setBusy(true)
    setTest(null)
    try {
      setTest(await api<TestResult>("/api/privacy/test", { method: "POST" }))
    } catch (e) {
      toast.error(errText(e))
    } finally {
      setBusy(false)
    }
  }
  const tor = st.tor
  const saved = st.mode === mode && (mode !== "custom" || st.proxy === proxy)
  return (
    <Card>
      <CardHeader>
        <CardTitle>Hide my IP</CardTitle>
        <CardDescription>
          While PhishGuard checks a link, the site sees another network's address instead of yours. Links you then open in your own browser use
          your normal connection.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <FieldGroup>
          <Field>
            <FieldLabel htmlFor="route">Route</FieldLabel>
            <Select value={mode} onValueChange={(v) => setMode(v as Privacy["mode"])}>
              <SelectTrigger id="route" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {ROUTES.map((r) => (
                  <SelectItem key={r.value} value={r.value}>
                    {r.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {mode === "tor" && (
              <FieldDescription>
                {tor.state === "downloading"
                  ? `Downloading Tor ${tor.version} from torproject.org: ${tor.progress}%`
                  : tor.state === "starting"
                    ? `Connecting to the Tor network: ${tor.progress}%`
                    : tor.state === "running"
                      ? "Connected to the Tor network. Each check uses its own Tor circuit."
                      : tor.installed
                        ? `Tor ${tor.version} is downloaded.`
                        : tor.state === "error"
                          ? tor.message
                          : `PhishGuard downloads the official Tor ${tor.version} (about 24 MB) once and checks its fingerprint.`}
              </FieldDescription>
            )}
            {mode === "warp" && <FieldDescription>{st.warp.message}</FieldDescription>}
          </Field>
          {torBusy && <Progress value={tor.progress} aria-label="Tor progress" />}
          {mode === "custom" && (
            <Field>
              <FieldLabel htmlFor="proxy">Proxy address</FieldLabel>
              <Input id="proxy" placeholder="socks5://127.0.0.1:1080" autoComplete="off" value={proxy} onChange={(e) => setProxy(e.target.value)} />
              <FieldDescription>SOCKS5 or HTTP. Use only a proxy you trust: it can see which sites are checked.</FieldDescription>
            </Field>
          )}
          {test && (
            <div className="grid gap-1 rounded-lg border p-3 text-sm">
              {test.error ? (
                <p className="text-danger">{test.error}</p>
              ) : (
                <>
                  <p>
                    Sites see <span className="font-mono font-medium">{test.seen?.ip}</span>
                    {test.seen?.is_tor ? " (a Tor address)" : ""}
                  </p>
                  {test.direct && (
                    <p className="text-muted-foreground">
                      Without Hide my IP they would see <span className="font-mono">{test.direct.ip}</span>
                    </p>
                  )}
                </>
              )}
            </div>
          )}
        </FieldGroup>
      </CardContent>
      <CardFooter className="flex-wrap gap-2">
        {mode === "tor" && !tor.installed && tor.state !== "downloading" ? (
          <Button onClick={download}>Download Tor</Button>
        ) : (
          <Button disabled={busy || saved} onClick={saveMode}>
            Save
          </Button>
        )}
        {saved && st.mode !== "off" && (
          <Button variant="outline" disabled={busy || torBusy} onClick={runTest}>
            {busy && <Spinner />}
            Test
          </Button>
        )}
      </CardFooter>
    </Card>
  )
}

const KEEP = [
  { value: "30", label: "30 days" },
  { value: "90", label: "90 days" },
  { value: "365", label: "1 year" },
  { value: "0", label: "Keep everything" },
]

function size(bytes: number) {
  if (bytes < 1024 * 1024) return `${Math.max(1, Math.round(bytes / 1024))} KB`
  if (bytes < 1024 ** 3) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
  return `${(bytes / 1024 ** 3).toFixed(2)} GB`
}

// History: how long checks, screenshots and quarantined downloads are kept on this PC.
function History() {
  const [st, setSt] = React.useState<HistoryStatus | null>(null)
  const [busy, setBusy] = React.useState(false)
  const load = React.useCallback(() => api<HistoryStatus>("/api/history").then(setSt).catch(() => null), [])
  React.useEffect(() => {
    load()
  }, [load])
  if (!st) return null
  const keep = async (v: string) => {
    setSt({ ...st, keep_days: Number(v) })
    if (await save({ keep_days: v }, v === "0" ? "Checks are kept until you delete them." : "Saved. Older checks were deleted.")) load()
  }
  const clear = async () => {
    setBusy(true)
    try {
      const r = await api<HistoryStatus & { deleted: number }>("/api/history/clear", { method: "POST" })
      setSt(r)
      toast.success(r.deleted === 1 ? "1 check deleted." : `${r.deleted} checks deleted.`)
    } catch (e) {
      toast.error(errText(e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Card>
      <CardHeader>
        <CardTitle>History</CardTitle>
        <CardDescription>
          Each check keeps its verdict, a screenshot and any file the site tried to download (quarantined, never run). They stay on this PC.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Field>
          <FieldLabel htmlFor="keep">Keep checks for</FieldLabel>
          <Select value={String(st.keep_days)} onValueChange={keep}>
            <SelectTrigger id="keep" className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {KEEP.map((k) => (
                <SelectItem key={k.value} value={k.value}>
                  {k.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <FieldDescription>
            {st.checks.toLocaleString()} {st.checks === 1 ? "check" : "checks"}, {size(st.bytes)}. Trusted and blocked sites and the audit log are
            kept.
          </FieldDescription>
        </Field>
      </CardContent>
      <CardFooter>
        <AlertDialog>
          <AlertDialogTrigger asChild>
            <Button variant="outline" disabled={busy || st.checks === 0}>
              Delete all history
            </Button>
          </AlertDialogTrigger>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>Delete all history?</AlertDialogTitle>
              <AlertDialogDescription>Every finished check, its screenshot and its quarantined files are deleted. This cannot be undone.</AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <AlertDialogAction variant="destructive" onClick={clear}>
                Delete
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </CardFooter>
    </Card>
  )
}

// --- Accounts --------------------------------------------------------------------------------

// Personal mode (just me, no password) or accounts (usernames, passwords, roles).
function AccountMode() {
  const personal = boot.mode === "personal"
  const [open, setOpen] = React.useState(false)
  const [username, setUsername] = React.useState("admin")
  const [password, setPassword] = React.useState("")
  const [password2, setPassword2] = React.useState("")
  const [busy, setBusy] = React.useState(false)
  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    try {
      const body = personal ? { mode: "accounts", username, password, password2 } : { mode: "personal", password }
      await api("/api/account-mode", { method: "POST", body })
      go("/settings")
    } catch (err) {
      toast.error(errText(err))
      setBusy(false)
    }
  }
  return (
    <Card>
      <form onSubmit={submit} className="contents">
        <CardHeader>
          <CardTitle>Who uses PhishGuard</CardTitle>
          <CardDescription>
            {personal
              ? "Just you. There is no password: PhishGuard opens from the Start menu."
              : "Several people. Each one logs in with a username and password."}
          </CardDescription>
        </CardHeader>
        {open && (
          <CardContent>
            <FieldGroup>
              {personal ? (
                <>
                  <Field>
                    <FieldLabel htmlFor="mode-user">Your username</FieldLabel>
                    <Input id="mode-user" autoComplete="username" required value={username} onChange={(e) => setUsername(e.target.value)} />
                  </Field>
                  <Field>
                    <FieldLabel htmlFor="mode-pw">New password</FieldLabel>
                    <Input id="mode-pw" type="password" autoComplete="new-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
                    <FieldDescription>At least 8 characters</FieldDescription>
                  </Field>
                  <Field>
                    <FieldLabel htmlFor="mode-pw2">Password again</FieldLabel>
                    <Input id="mode-pw2" type="password" autoComplete="new-password" required value={password2} onChange={(e) => setPassword2(e.target.value)} />
                  </Field>
                </>
              ) : (
                <Field>
                  <FieldLabel htmlFor="mode-pw">Your password</FieldLabel>
                  <Input id="mode-pw" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
                  <FieldDescription>Other accounts are kept but cannot log in until you switch back.</FieldDescription>
                </Field>
              )}
            </FieldGroup>
          </CardContent>
        )}
        <CardFooter className="gap-2">
          {open ? (
            <>
              <Button type="submit" disabled={busy}>
                {personal ? "Turn on accounts" : "Switch to just me"}
              </Button>
              <Button type="button" variant="ghost" onClick={() => setOpen(false)}>
                Cancel
              </Button>
            </>
          ) : (
            <Button type="button" variant="outline" onClick={() => setOpen(true)}>
              {personal ? "Set up accounts" : "Switch to just me"}
            </Button>
          )}
        </CardFooter>
      </form>
    </Card>
  )
}

function Users() {
  const [users, setUsers] = React.useState<UserRow[]>([])
  const [name, setName] = React.useState("")
  const [pw, setPw] = React.useState("")
  const [role, setRole] = React.useState("analyst")
  const load = React.useCallback(() => {
    api<{ users: UserRow[] }>("/api/users")
      .then((r) => setUsers(r.users))
      .catch(() => null)
  }, [])
  React.useEffect(load, [load])
  const del = async (u: UserRow) => {
    try {
      await api(`/api/users/${u.id}`, { method: "DELETE" })
      toast.success(`${u.username} removed.`)
      load()
    } catch (e) {
      toast.error(errText(e))
    }
  }
  const add = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      await api("/api/users", { method: "POST", body: { username: name, password: pw, role } })
      toast.success("Added.")
      setName("")
      setPw("")
      load()
    } catch (err) {
      toast.error(errText(err))
    }
  }
  return (
    <>
      <div className="overflow-hidden rounded-lg border">
        <Table>
          <TableHeader className="bg-muted">
            <TableRow>
              <TableHead>Person</TableHead>
              <TableHead>Role</TableHead>
              <TableHead>Last login</TableHead>
              <TableHead className="w-10" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {users.map((u) => (
              <TableRow key={u.id}>
                <TableCell className="font-medium">{u.username}</TableCell>
                <TableCell>
                  <Badge variant={u.role === "admin" ? "default" : "outline"}>{u.role === "admin" ? "Admin" : "Analyst"}</Badge>
                </TableCell>
                <TableCell className="text-muted-foreground">{ago(u.last_login)}</TableCell>
                <TableCell>
                  <Button variant="ghost" size="icon-sm" aria-label={`Remove ${u.username}`} onClick={() => del(u)}>
                    <Trash2Icon />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      <Card>
        <form onSubmit={add} className="contents">
          <CardHeader>
            <CardTitle>Add a person</CardTitle>
            <CardDescription>Analysts check links and edit the lists. Admins can also change settings and people.</CardDescription>
          </CardHeader>
          <CardContent>
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="new-user">Username</FieldLabel>
                <Input id="new-user" autoComplete="off" required value={name} onChange={(e) => setName(e.target.value)} />
              </Field>
              <Field>
                <FieldLabel htmlFor="new-pw">Password</FieldLabel>
                <Input id="new-pw" type="password" autoComplete="new-password" required value={pw} onChange={(e) => setPw(e.target.value)} />
                <FieldDescription>8 characters or more</FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="new-role">Role</FieldLabel>
                <Select value={role} onValueChange={setRole}>
                  <SelectTrigger id="new-role" className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="analyst">Analyst</SelectItem>
                    <SelectItem value="admin">Admin</SelectItem>
                  </SelectContent>
                </Select>
              </Field>
            </FieldGroup>
          </CardContent>
          <CardFooter>
            <Button type="submit">
              <UserPlusIcon />
              Add
            </Button>
          </CardFooter>
        </form>
      </Card>
    </>
  )
}

function Audit() {
  const [rows, setRows] = React.useState<AuditRow[]>([])
  React.useEffect(() => {
    api<{ items: AuditRow[] }>("/api/audit")
      .then((r) => setRows(r.items))
      .catch(() => null)
  }, [])
  return (
    <div className="overflow-hidden rounded-lg border">
      <Table>
        <TableHeader className="bg-muted">
          <TableRow>
            <TableHead className="w-28">When</TableHead>
            <TableHead className="w-28">Who</TableHead>
            <TableHead>What</TableHead>
            <TableHead>Details</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((a) => (
            <TableRow key={a.id}>
              <TableCell className="text-muted-foreground">{ago(a.created_at)}</TableCell>
              <TableCell>{a.username || "launcher"}</TableCell>
              <TableCell>{a.action.replace(/_/g, " ")}</TableCell>
              <TableCell className="max-w-[28rem] truncate font-mono text-xs">{a.detail || ""}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}
