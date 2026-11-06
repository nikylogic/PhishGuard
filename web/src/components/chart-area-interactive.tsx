import * as React from "react"
import { Area, AreaChart, CartesianGrid, XAxis } from "recharts"

import { useIsMobile } from "@/hooks/use-mobile"
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { ChartContainer, ChartLegend, ChartLegendContent, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import type { Stats } from "@/components/section-cards"

const chartConfig = {
  checks: { label: "Checks" },
  clear: { label: "Clear", color: "var(--clear)" },
  caution: { label: "Caution", color: "var(--caution)" },
  danger: { label: "Danger", color: "var(--danger)" },
} satisfies ChartConfig

const RANGES = { "90d": ["Last 3 months", 90], "30d": ["Last 30 days", 30], "7d": ["Last 7 days", 7] } as const
type Range = keyof typeof RANGES

const fmt = (v: string) => new Date(v + "T00:00:00Z").toLocaleDateString(undefined, { month: "short", day: "numeric", timeZone: "UTC" })

export function ChartAreaInteractive({ stats }: { stats: Stats | null }) {
  const isMobile = useIsMobile()
  const [timeRange, setTimeRange] = React.useState<Range>("7d")

  React.useEffect(() => {
    if (isMobile) setTimeRange("7d")
  }, [isMobile])

  // One point per day (UTC, like the database), with empty days filled in as zero.
  const data = React.useMemo(() => {
    const n = RANGES[timeRange][1]
    const byDay = new Map((stats?.days ?? []).map((d) => [d.day, d]))
    return Array.from({ length: n }, (_, i) => {
      const day = new Date(Date.now() - (n - 1 - i) * 86400000).toISOString().slice(0, 10)
      const d = byDay.get(day)
      return { date: day, clear: d?.clear ?? 0, caution: d?.caution ?? 0, danger: d?.danger ?? 0 }
    })
  }, [stats, timeRange])
  const total = data.reduce((a, d) => a + d.clear + d.caution + d.danger, 0)
  const label = RANGES[timeRange][0]

  return (
    <Card className="@container/card">
      <CardHeader>
        <CardTitle>Links checked</CardTitle>
        <CardDescription>
          <span className="hidden @[540px]/card:block">
            {total} links in the airlock, {label.toLowerCase()}
          </span>
          <span className="@[540px]/card:hidden">{label}</span>
        </CardDescription>
        <CardAction>
          <ToggleGroup
            type="single"
            value={timeRange}
            onValueChange={(v) => v && setTimeRange(v as Range)}
            variant="outline"
            className="hidden *:data-[slot=toggle-group-item]:px-4! @[767px]/card:flex"
          >
            {(Object.keys(RANGES) as Range[]).map((r) => (
              <ToggleGroupItem key={r} value={r}>
                {RANGES[r][0]}
              </ToggleGroupItem>
            ))}
          </ToggleGroup>
          <Select value={timeRange} onValueChange={(v) => setTimeRange(v as Range)}>
            <SelectTrigger
              className="flex w-40 **:data-[slot=select-value]:block **:data-[slot=select-value]:truncate @[767px]/card:hidden"
              size="sm"
              aria-label="Time range"
            >
              <SelectValue placeholder="Last 3 months" />
            </SelectTrigger>
            <SelectContent className="rounded-xl">
              {(Object.keys(RANGES) as Range[]).map((r) => (
                <SelectItem key={r} value={r} className="rounded-lg">
                  {RANGES[r][0]}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </CardAction>
      </CardHeader>
      <CardContent className="px-2 pt-4 sm:px-6 sm:pt-6">
        <ChartContainer config={chartConfig} className="aspect-auto h-[250px] w-full">
          <AreaChart data={data}>
            <defs>
              {(["clear", "caution", "danger"] as const).map((k) => (
                <linearGradient key={k} id={`fill-${k}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={`var(--color-${k})`} stopOpacity={0.8} />
                  <stop offset="95%" stopColor={`var(--color-${k})`} stopOpacity={0.08} />
                </linearGradient>
              ))}
            </defs>
            <CartesianGrid vertical={false} />
            <XAxis dataKey="date" tickLine={false} axisLine={false} tickMargin={8} minTickGap={32} tickFormatter={fmt} />
            <ChartTooltip
              cursor={false}
              content={<ChartTooltipContent labelFormatter={(v) => fmt(String(v))} indicator="dot" />}
            />
            <Area dataKey="clear" type="monotone" fill="url(#fill-clear)" stroke="var(--color-clear)" stackId="a" />
            <Area dataKey="caution" type="monotone" fill="url(#fill-caution)" stroke="var(--color-caution)" stackId="a" />
            <Area dataKey="danger" type="monotone" fill="url(#fill-danger)" stroke="var(--color-danger)" stackId="a" />
            <ChartLegend content={<ChartLegendContent />} />
          </AreaChart>
        </ChartContainer>
      </CardContent>
    </Card>
  )
}
