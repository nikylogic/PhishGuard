import { Badge } from "@/components/ui/badge"
import { TONE, WORD, type Level } from "@/lib/api"
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
