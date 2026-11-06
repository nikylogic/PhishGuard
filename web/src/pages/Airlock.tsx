// The Airlock: watches one check, then shows the verdict, the four gauges, the reasons and the choices.
import * as React from "react"
import { toast } from "sonner"
import {
  ArrowDownIcon,
  CopyIcon,
  ExternalLinkIcon,
  ImageOffIcon,
  LockIcon,
  SparklesIcon,
} from "lucide-react"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { AspectRatio } from "@/components/ui/aspect-ratio"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardAction, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty"
import { Progress } from "@/components/ui/progress"
import { Skeleton } from "@/components/ui/skeleton"
import { Spinner } from "@/components/ui/spinner"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { GAUGES, VerdictBadge } from "@/components/verdict"
import { api, ApiError, band, errText, TONE, urlParts, type Level } from "@/lib/api"
import { cn } from "@/lib/utils"

type Finding = { code: string; message: string; weight: number; category: string }
type Scan = {
  id: number
  url: string
  final_url: string
  domain: string
  title: string | null
  status: string
  error: string | null
  level: Level
  score: number
  s_phishing: number
  s_malware: number
  s_tracking: number
  s_abuse: number
  decision: string
  screenshot_url: string | null
  clean_url: string
  params_removed: string[]
  redirects: { url: string; kind: string; status: number | null }[]
  findings: Finding[]
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  page: any
  llm: { risk: number; category: string; reasons: string[]; provider: string } | null
}

const HEAD: Record<Level, string> = {
  pending: "Inspecting the link…",
  clear: "This link looks safe.",
  caution: "Be careful with this link.",
  danger: "Stop. This link is dangerous.",
}
const DONE: Record<string, string> = {
  open: "Opened in your browser.",
  open_clean: "Opened the clean link in your browser.",
  open_direct: "Opened directly in your browser.",
  block: "Blocked. PhishGuard will stop this site next time.",
  ignore: "Good call. Nothing was opened.",
}

function useCheck(sid: number) {
  const [d, setD] = React.useState<Scan | null>(null)
  const [loadError, setLoadError] = React.useState("")
  React.useEffect(() => {
    let timer: number | undefined
    let alive = true
    let n = 0
    let settled = 0
    const poll = async () => {
      try {
        const s = await api<Scan>(`/api/scan/${sid}`)
        if (!alive) return
        setD(s)
        const busy = s.status === "queued" || s.status === "running"
        n++
        if (!busy) settled++
        // Keep listening briefly after the verdict: the optional AI second opinion may raise it.
        if (busy && n < 120) timer = window.setTimeout(poll, 700)
        else if (!busy && settled < 6) timer = window.setTimeout(poll, 2500)
      } catch (e) {
        setLoadError((e as ApiError).status === 401 ? "Please log in to see this check." : "Could not load this check.")
      }
    }
    poll()
    return () => {
      alive = false
      window.clearTimeout(timer)
    }
  }, [sid])
  return { d, loadError }
}

function CopyLink({ url }: { url?: string }) {
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(url ?? "")
      toast.success("Link copied.")
    } catch {
      toast.error("Could not copy.")
    }
  }
  return (
    <Button variant="outline" size="sm" onClick={copy} disabled={!url}>
      <CopyIcon />
      Copy link
    </Button>
  )
}

export function Airlock({ sid }: { sid: number }) {
  const { d, loadError } = useCheck(sid)
  const [zoom, setZoom] = React.useState(false)
  const [confirm, setConfirm] = React.useState<null | "open" | "open_direct">(null)
  const [blocked, setBlocked] = React.useState(false)

  const busy = !d || d.status === "queued" || d.status === "running"
  const level: Level = busy ? "pending" : d!.level
  let headline = loadError || HEAD[level]
  if (d && !busy && d.status === "failed") headline = "PhishGuard could not look inside."

  const decide = async (action: string, ok = false) => {
    try {
      await api(`/api/scan/${sid}/decision`, { method: "POST", body: { action, confirm: ok } })
      toast.success(DONE[action])
      if (action === "block") setBlocked(true)
    } catch (e) {
      if ((e as ApiError).status === 409 && action !== "ignore") setConfirm(action as "open" | "open_direct")
      else toast.error(errText(e))
    }
  }

  const [pre, main, rest] = d ? urlParts(d.url, d.domain) : ["", "loading…", ""]
  const reasons = (d?.findings ?? []).filter((f) => f.weight > 0).slice(0, 7)
  const danger = level === "danger"
  const removed = d?.params_removed?.length ?? 0
  const timing = d?.page?.timings?.total as number | undefined
  const isBlocked = blocked || d?.decision === "blocked"

  return (
    <div className="flex flex-col gap-4 px-4 md:gap-6 lg:px-6">
      {/* Verdict hero */}
      <Card className={cn("@container/card overflow-hidden shadow-xs", TONE[level].soft)}>
        <CardHeader>
          <CardDescription>
            <VerdictBadge level={level} />
          </CardDescription>
          <CardTitle className={cn("text-2xl font-semibold text-balance @[500px]/card:text-3xl", !busy && TONE[level].text)}>
            {headline}
          </CardTitle>
          <CardAction className="text-right">
            {busy ? (
              <Spinner className="size-6 text-muted-foreground" />
            ) : (
              <div className={cn("font-heading text-4xl font-semibold tabular-nums", TONE[level].text)}>
                {d!.score}
                <span className="text-base font-normal text-muted-foreground">/100</span>
              </div>
            )}
          </CardAction>
        </CardHeader>
        <CardFooter className="gap-2">
          <p className="min-w-0 flex-1 rounded-md border bg-background px-3 py-1.5 font-mono text-sm break-all" aria-label="The link">
            <span className="text-muted-foreground">{pre}</span>
            <strong className="font-semibold text-foreground">{main}</strong>
            <span className="text-muted-foreground">{rest}</span>
          </p>
          <CopyLink url={d?.url} />
        </CardFooter>
      </Card>

      <div className="grid grid-cols-1 items-start gap-4 md:gap-6 @4xl/main:grid-cols-2">
        {/* Screenshot from the sandbox */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Sandbox view</CardTitle>
            {timing ? <CardDescription>Opened in {timing.toFixed(1)} s</CardDescription> : null}
          </CardHeader>
          <CardContent>
            {d?.screenshot_url ? (
              <button
                type="button"
                onClick={() => setZoom(true)}
                className="block w-full overflow-hidden rounded-lg border transition hover:ring-2 hover:ring-ring/40 focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                aria-label="Enlarge the screenshot"
              >
                <AspectRatio ratio={1366 / 768}>
                  <img
                    src={d.screenshot_url}
                    alt={`Screenshot of "${d.title || d.domain}" taken inside the sandbox`}
                    className="size-full object-cover object-top"
                  />
                </AspectRatio>
              </button>
            ) : busy ? (
              <AspectRatio ratio={1366 / 768}>
                <Skeleton className="size-full rounded-lg" />
              </AspectRatio>
            ) : (
              <Empty className="border border-dashed">
                <EmptyHeader>
                  <EmptyMedia variant="icon">
                    <ImageOffIcon />
                  </EmptyMedia>
                  <EmptyTitle>No picture was taken</EmptyTitle>
                  <EmptyDescription>{d?.error || "The page was never opened."}</EmptyDescription>
                </EmptyHeader>
              </Empty>
            )}
          </CardContent>
        </Card>

        {/* Gauges, reasons and the choices */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Risk breakdown</CardTitle>
            {busy && <CardDescription>Opening the page in the sandbox…</CardDescription>}
          </CardHeader>
          <CardContent className="flex flex-col gap-5">
            <div className="grid gap-3">
              {GAUGES.map(([key, name]) => {
                const v = busy ? 0 : (d![key] as number)
                return (
                  <div key={key} className="grid gap-1.5">
                    <div className="flex items-center justify-between text-sm">
                      <span id={`g-${key}`}>{name}</span>
                      <span className="font-mono text-muted-foreground tabular-nums">{busy ? "…" : v}</span>
                    </div>
                    <Progress
                      aria-labelledby={`g-${key}`}
                      value={v}
                      className="h-2"
                      indicatorClassName={busy ? "animate-pulse bg-muted-foreground/40" : TONE[band(v)].bg}
                    />
                  </div>
                )
              })}
            </div>
            <div className="grid gap-2">
              <h2 className="text-sm font-medium">Why</h2>
              <ul className="grid gap-2 text-sm">
                {busy ? (
                  <li className="text-muted-foreground">Waiting for the sandbox…</li>
                ) : reasons.length ? (
                  reasons.map((f) => (
                    <li key={f.code + f.message} className="flex gap-2.5">
                      <span
                        aria-label={`weight ${f.weight}`}
                        role="img"
                        className={cn(
                          "mt-1.5 size-2 shrink-0 rounded-full",
                          f.weight >= 50 ? "bg-danger" : f.weight >= 20 ? "bg-caution" : "bg-muted-foreground/40"
                        )}
                      />
                      <span>{f.message}</span>
                    </li>
                  ))
                ) : (
                  <li className="text-muted-foreground">{d?.error || "Nothing suspicious was found."}</li>
                )}
              </ul>
            </div>
          </CardContent>
          <CardFooter className="flex-col items-stretch gap-2">
            {danger ? (
              <Button size="lg" className="h-10" disabled={busy} onClick={() => decide("ignore")}>
                <LockIcon />
                Keep it locked
              </Button>
            ) : (
              <Button size="lg" className="h-10" disabled={busy} onClick={() => decide("open")}>
                <ExternalLinkIcon />
                {level === "caution" ? "Open with care" : "Open safely"}
              </Button>
            )}
            <div className="flex flex-wrap gap-2">
              {danger ? (
                <Button variant="outline" disabled={busy} onClick={() => setConfirm("open")}>
                  Open anyway…
                </Button>
              ) : (
                <Button variant="outline" disabled={busy} onClick={() => decide("open_clean")}>
                  {removed ? `Open clean link (−${removed} tracker tag${removed > 1 ? "s" : ""})` : "Open clean link"}
                </Button>
              )}
              <Button variant="outline" disabled={busy || isBlocked} onClick={() => decide("block")}>
                {isBlocked ? "Blocked" : "Block this site"}
              </Button>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button variant="ghost" onClick={() => (danger ? setConfirm("open_direct") : decide("open_direct", true))}>
                    Open directly
                  </Button>
                </TooltipTrigger>
                <TooltipContent>For one-time links like password resets</TooltipContent>
              </Tooltip>
            </div>
          </CardFooter>
        </Card>
      </div>

      <Tabs defaultValue="journey" className="gap-4">
        <TabsList className="h-auto flex-wrap justify-start">
          <TabsTrigger value="journey">Journey</TabsTrigger>
          <TabsTrigger value="privacy">Privacy report</TabsTrigger>
          <TabsTrigger value="files">Downloads</TabsTrigger>
          <TabsTrigger value="ai">AI Guard</TabsTrigger>
          <TabsTrigger value="tech">Technical</TabsTrigger>
        </TabsList>
        {d && <Panels d={d} />}
      </Tabs>

      {d?.screenshot_url && (
        <Dialog open={zoom} onOpenChange={setZoom}>
          <DialogContent className="sm:max-w-5xl">
            <DialogHeader>
              <DialogTitle>{d.title || d.domain}</DialogTitle>
              <DialogDescription>Seen inside the sandbox</DialogDescription>
            </DialogHeader>
            <img src={d.screenshot_url} alt={`Screenshot of "${d.title || d.domain}"`} className="w-full rounded-lg border" />
          </DialogContent>
        </Dialog>
      )}
      <AlertDialog open={confirm !== null} onOpenChange={(o) => !o && setConfirm(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Open a dangerous link?</AlertDialogTitle>
            <AlertDialogDescription>
              This link is marked DANGER. Opening it may put your accounts or computer at risk.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Keep it locked</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              onClick={() => {
                const a = confirm!
                setConfirm(null)
                decide(a, true)
              }}
            >
              Open anyway
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

function Tags({ items }: { items?: string[] }) {
  return items && items.length ? (
    <div className="flex flex-wrap gap-1">
      {items.map((x) => (
        <Badge key={x} variant="secondary" className="font-mono font-normal">
          {x}
        </Badge>
      ))}
    </div>
  ) : (
    <span className="text-muted-foreground">None</span>
  )
}

function Facts({ rows }: { rows: [string, React.ReactNode][] }) {
  return (
    <Card className="py-0">
      <dl className="divide-y">
        {rows.map(([k, v]) => (
          <div key={k} className="grid gap-1 px-4 py-3 text-sm sm:grid-cols-[14rem_1fr] sm:gap-4">
            <dt className="text-muted-foreground">{k}</dt>
            <dd className="min-w-0 break-words">{v}</dd>
          </div>
        ))}
      </dl>
    </Card>
  )
}

const Mono = ({ children }: { children: React.ReactNode }) => <code className="font-mono text-[0.8rem] break-all">{children}</code>

type FileRow = { filename: string; real_type: string; size: number; sha256: string }

function Panels({ d }: { d: Scan }) {
  const p = d.page || {}
  const pv = p.privacy || {}
  const tls = p.tls || {}
  const g = p.guard
  const files: FileRow[] = p.downloads || []
  const hops = d.redirects?.length ? d.redirects : [{ url: d.url, kind: "final", status: null }]
  return (
    <>
      <TabsContent value="journey">
        <ol className="grid max-w-3xl gap-1">
          {hops.map((hop, i) => (
            <li key={i} className="grid gap-1">
              {i > 0 && <ArrowDownIcon aria-hidden className="ml-4 size-4 text-muted-foreground" />}
              <div className={cn("rounded-lg border px-4 py-3", hop.kind === "final" ? "bg-card shadow-xs" : "bg-muted/50")}>
                <div className="text-xs text-muted-foreground">
                  {i === 0
                    ? "you clicked"
                    : hop.kind === "final"
                      ? "where it ended"
                      : hop.kind === "script"
                        ? "script redirect"
                        : `redirect ${hop.status ?? ""}`}
                </div>
                <Mono>{hop.url}</Mono>
              </div>
            </li>
          ))}
        </ol>
      </TabsContent>
      <TabsContent value="privacy">
        <Facts
          rows={[
            ["IP logger", pv.ip_logger ? "Yes: opening this link records your IP address" : "Not detected"],
            ["Fingerprinting", <Tags items={pv.fingerprinting} />],
            ["WebRTC (local IP leak)", pv.webrtc ? "Used by the page" : "Not used"],
            ["Known trackers", <Tags items={pv.trackers} />],
            ["Tracking tags in the link", <Tags items={d.params_removed} />],
            ["Clean link", <Mono>{d.clean_url}</Mono>],
          ]}
        />
      </TabsContent>
      <TabsContent value="files">
        {files.length ? (
          <div className="grid gap-2">
            <div className="overflow-hidden rounded-lg border">
              <Table>
                <TableHeader className="bg-muted">
                  <TableRow>
                    <TableHead>File name</TableHead>
                    <TableHead>Really is</TableHead>
                    <TableHead>Size</TableHead>
                    <TableHead>SHA-256</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {files.map((f) => (
                    <TableRow key={f.sha256 + f.filename}>
                      <TableCell>
                        <Mono>{f.filename}</Mono>
                      </TableCell>
                      <TableCell>{(f.real_type || "unknown").replace(/-/g, " ")}</TableCell>
                      <TableCell className="tabular-nums">{f.size ? `${(f.size / 1024).toFixed(1)} KB` : "–"}</TableCell>
                      <TableCell className="max-w-[16rem] truncate font-mono text-xs">{f.sha256 || "–"}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            <p className="text-sm text-muted-foreground">Each file was caught in quarantine and renamed to .bin. It was never opened or run.</p>
          </div>
        ) : (
          <Empty className="border border-dashed">
            <EmptyHeader>
              <EmptyTitle>No downloads</EmptyTitle>
              <EmptyDescription>The page did not try to download anything.</EmptyDescription>
            </EmptyHeader>
          </Empty>
        )}
      </TabsContent>
      <TabsContent value="ai" className="grid gap-4">
        {g ? (
          <>
            <Facts
              rows={[
                ["Prompt-injection score", `${Math.round(g.score * 100)} / 100 (${g.label})`],
                ...(g.keywords?.length ? ([["Phrases spotted", <Tags items={g.keywords} />]] as [string, React.ReactNode][]) : []),
              ]}
            />
            {g.label === "injection" && g.chunk && (
              <Alert variant="destructive">
                <SparklesIcon />
                <AlertTitle>Hidden instruction aimed at AI assistants</AlertTitle>
                <AlertDescription>
                  <blockquote className="border-l-2 pl-3 italic">{g.chunk}</blockquote>
                </AlertDescription>
              </Alert>
            )}
          </>
        ) : (
          <p className="text-sm text-muted-foreground">AI Guard has not looked at this page.</p>
        )}
        {d.llm && (
          <div className="grid gap-2">
            <h3 className="flex items-center gap-2 text-sm font-medium">
              <SparklesIcon className="size-4" />
              AI second opinion
            </h3>
            <Facts
              rows={[
                ["Risk", `${d.llm.risk} / 100 (${d.llm.category})`],
                ["Reasons", d.llm.reasons.join(" ")],
                ["Model", d.llm.provider],
              ]}
            />
          </div>
        )}
      </TabsContent>
      <TabsContent value="tech">
        <Facts
          rows={[
            ["Final address", <Mono>{d.final_url}</Mono>],
            ["Page title", d.title || "–"],
            ["HTTP status", String(p.http_status || "–")],
            ["Certificate", tls.issuer ? `${tls.subjectName} · issued by ${tls.issuer}` : "–"],
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            ["Blocked by PhishGuard", <Tags items={(p.blocked || []).map((b: any) => `${b.url} (${b.reason})`)} />],
            ["Websites contacted", <Tags items={p.request_domains} />],
            ["Status", d.status + (d.error ? ` · ${d.error}` : "")],
          ]}
        />
      </TabsContent>
    </>
  )
}
