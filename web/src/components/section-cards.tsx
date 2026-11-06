import { Card, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { cn } from "@/lib/utils"

export type Stats = {
  today: number
  stopped_today: number
  trackers_today: number
  total: number
  by_level: { clear: number; caution: number; danger: number }
  days: { day: string; clear: number; caution: number; danger: number }[]
  top_dangerous: { domain: string; n: number }[]
}

const yesterdayKey = () => new Date(Date.now() - 86400000).toISOString().slice(0, 10)

function Stat({ label, value, note, tone }: { label: string; value: React.ReactNode; note: string; tone?: string }) {
  return (
    <Card className="@container/card">
      <CardHeader>
        <CardDescription>{label}</CardDescription>
        <CardTitle className={cn("text-2xl font-semibold tabular-nums @[250px]/card:text-3xl", tone)}>{value}</CardTitle>
      </CardHeader>
      <CardFooter className="text-sm text-muted-foreground">{note}</CardFooter>
    </Card>
  )
}

export function SectionCards({ stats: s }: { stats: Stats | null }) {
  const wrap = "grid grid-cols-1 gap-4 px-4 *:data-[slot=card]:shadow-xs lg:px-6 @xl/main:grid-cols-2 @5xl/main:grid-cols-4"
  if (!s) {
    return (
      <div className={wrap}>
        {[0, 1, 2, 3].map((i) => (
          <Skeleton key={i} className="h-[7.5rem] rounded-xl" />
        ))}
      </div>
    )
  }
  const y = s.days.find((d) => d.day === yesterdayKey())
  const yesterday = y ? y.clear + y.caution + y.danger : 0
  const ninety = s.days.reduce((a, d) => a + d.clear + d.caution + d.danger, 0)
  const clear90 = s.days.reduce((a, d) => a + d.clear, 0)
  return (
    <div className={wrap}>
      <Stat label="Checked today" value={s.today} note={`${yesterday} yesterday`} />
      <Stat
        label="Stopped today"
        value={s.stopped_today}
        tone={s.stopped_today ? "text-danger" : undefined}
        note={`${s.by_level.danger} in total`}
      />
      <Stat label="Trackers spotted" value={s.trackers_today} note="in today's checks" />
      <Stat
        label="Clear rate"
        value={ninety ? `${Math.round((clear90 / ninety) * 100)}%` : "–"}
        note={`${clear90} of ${ninety} in 3 months`}
      />
    </div>
  )
}
