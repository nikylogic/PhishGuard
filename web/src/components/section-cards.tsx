import { TrendingUpIcon, TrendingDownIcon, ShieldAlertIcon, RadarIcon, ShieldCheckIcon, MinusIcon } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Card, CardAction, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"

export type Stats = {
  today: number
  stopped_today: number
  trackers_today: number
  total: number
  by_level: { clear: number; caution: number; danger: number }
  days: { day: string; clear: number; caution: number; danger: number }[]
  top_dangerous: { domain: string; n: number }[]
}

const utcDay = (offset: number) => new Date(Date.now() - offset * 86400000).toISOString().slice(0, 10)
const sumDay = (s: Stats, key: string) => {
  const d = s.days.find((x) => x.day === key)
  return d ? d.clear + d.caution + d.danger : 0
}

function Trend({ now, before }: { now: number; before: number }) {
  if (now === before) {
    return (
      <Badge variant="outline">
        <MinusIcon />
        same as yesterday
      </Badge>
    )
  }
  const up = now > before
  const pct = before ? `${up ? "+" : ""}${Math.round(((now - before) / before) * 100)}%` : `+${now}`
  return (
    <Badge variant="outline">
      {up ? <TrendingUpIcon /> : <TrendingDownIcon />}
      {pct}
    </Badge>
  )
}

function Stat({
  label,
  value,
  badge,
  line,
  icon,
  sub,
}: {
  label: string
  value: React.ReactNode
  badge: React.ReactNode
  line: string
  icon: React.ReactNode
  sub: string
}) {
  return (
    <Card className="@container/card">
      <CardHeader>
        <CardDescription>{label}</CardDescription>
        <CardTitle className="text-2xl font-semibold tabular-nums @[250px]/card:text-3xl">{value}</CardTitle>
        <CardAction>{badge}</CardAction>
      </CardHeader>
      <CardFooter className="flex-col items-start gap-1.5 text-sm">
        <div className="line-clamp-1 flex gap-2 font-medium [&_svg]:size-4">
          {line} {icon}
        </div>
        <div className="text-muted-foreground">{sub}</div>
      </CardFooter>
    </Card>
  )
}

export function SectionCards({ stats: s }: { stats: Stats | null }) {
  const wrap =
    "grid grid-cols-1 gap-4 px-4 *:data-[slot=card]:bg-gradient-to-t *:data-[slot=card]:from-primary/5 *:data-[slot=card]:to-card *:data-[slot=card]:shadow-xs lg:px-6 @xl/main:grid-cols-2 @5xl/main:grid-cols-4 dark:*:data-[slot=card]:bg-card"
  if (!s) {
    return (
      <div className={wrap}>
        {[0, 1, 2, 3].map((i) => (
          <Skeleton key={i} className="h-36 rounded-xl" />
        ))}
      </div>
    )
  }
  const yesterday = sumDay(s, utcDay(1))
  const ninety = s.days.reduce((a, d) => a + d.clear + d.caution + d.danger, 0)
  const clear90 = s.days.reduce((a, d) => a + d.clear, 0)
  const rate = ninety ? Math.round((clear90 / ninety) * 100) : 0
  return (
    <div className={wrap}>
      <Stat
        label="Checked today"
        value={s.today}
        badge={<Trend now={s.today} before={yesterday} />}
        line={s.today >= yesterday ? "More links than yesterday" : "Fewer links than yesterday"}
        icon={s.today >= yesterday ? <TrendingUpIcon /> : <TrendingDownIcon />}
        sub="Links that waited in the airlock"
      />
      <Stat
        label="Stopped today"
        value={s.stopped_today}
        badge={
          <Badge variant="outline" className="text-danger">
            <ShieldAlertIcon />
            Danger
          </Badge>
        }
        line={s.stopped_today ? "Dangerous links kept locked" : "Nothing dangerous today"}
        icon={<ShieldAlertIcon />}
        sub={`${s.by_level.danger} stopped since the start`}
      />
      <Stat
        label="Trackers spotted"
        value={s.trackers_today}
        badge={
          <Badge variant="outline">
            <RadarIcon />
            today
          </Badge>
        }
        line="Trackers and fingerprinting"
        icon={<RadarIcon />}
        sub="Seen inside the sandbox, not on your PC"
      />
      <Stat
        label="Clear rate"
        value={`${rate}%`}
        badge={
          <Badge variant="outline" className="text-clear">
            <ShieldCheckIcon />
            {clear90} clear
          </Badge>
        }
        line="Links that were safe to open"
        icon={<ShieldCheckIcon />}
        sub={`Of ${ninety} links in the last 3 months`}
      />
    </div>
  )
}
