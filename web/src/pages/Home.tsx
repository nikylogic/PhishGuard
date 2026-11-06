import * as React from "react"

import { ChartAreaInteractive } from "@/components/chart-area-interactive"
import { DataTable, type ScanRow } from "@/components/data-table"
import { SectionCards, type Stats } from "@/components/section-cards"
import { api } from "@/lib/api"

// The dashboard-01 layout: four cards, the interactive area chart, then the table.
export function Home() {
  const [stats, setStats] = React.useState<Stats | null>(null)
  const [rows, setRows] = React.useState<ScanRow[] | null>(null)
  React.useEffect(() => {
    api<Stats>("/api/stats").then(setStats).catch(() => null)
    api<{ scans: ScanRow[] }>("/api/scans?limit=200")
      .then((r) => setRows(r.scans))
      .catch(() => setRows([]))
  }, [])
  return (
    <>
      <SectionCards stats={stats} />
      <div className="px-4 lg:px-6">
        <ChartAreaInteractive stats={stats} />
      </div>
      <DataTable rows={rows} />
    </>
  )
}
