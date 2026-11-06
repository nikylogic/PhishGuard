import { Badge } from "@/components/ui/badge"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { band, TONE, WORD, type Level } from "@/lib/api"
import { cn } from "@/lib/utils"

// The verdict, shown like dashboard-01's status badges: an outline badge with a coloured dot.
export function VerdictBadge({ level, className }: { level: Level; className?: string }) {
  return (
    <Badge variant="outline" className={cn("gap-1.5 px-1.5", className)}>
      <span aria-hidden className={cn("size-2 rounded-full", TONE[level].bg, level === "pending" && "animate-pulse")} />
      <span className={cn(level !== "pending" && TONE[level].text, "font-medium")}>{WORD[level]}</span>
    </Badge>
  )
}

export const GAUGES = [
  ["s_phishing", "Phishing"],
  ["s_malware", "Malware"],
  ["s_tracking", "Tracking"],
  ["s_abuse", "Tricks"],
] as const

type Gauged = { s_phishing: number; s_malware: number; s_tracking: number; s_abuse: number }

// Four small dots, one per gauge: grey when quiet, amber or red when it fired.
export function GaugeDots({ row }: { row: Gauged }) {
  return (
    <div className="flex items-center gap-1.5">
      {GAUGES.map(([k, name]) => {
        const v = row[k]
        return (
          <Tooltip key={k}>
            <TooltipTrigger asChild>
              <span
                role="img"
                aria-label={`${name} ${v}`}
                className={cn("size-2.5 rounded-full", v >= 20 ? TONE[band(v)].bg : "bg-muted-foreground/25")}
              />
            </TooltipTrigger>
            <TooltipContent>
              {name}: {v}
            </TooltipContent>
          </Tooltip>
        )
      })}
    </div>
  )
}
