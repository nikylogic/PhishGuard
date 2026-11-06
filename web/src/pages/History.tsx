import * as React from "react"
import { SearchIcon } from "lucide-react"

import { DataTable, type ScanRow } from "@/components/data-table"
import { Input } from "@/components/ui/input"
import { api } from "@/lib/api"

export function History() {
  const [q, setQ] = React.useState("")
  const [rows, setRows] = React.useState<ScanRow[] | null>(null)

  React.useEffect(() => {
    const t = window.setTimeout(() => {
      const p = new URLSearchParams({ q, limit: "500" })
      api<{ scans: ScanRow[] }>(`/api/scans?${p}`)
        .then((r) => setRows(r.scans))
        .catch(() => setRows([]))
    }, 250)
    return () => window.clearTimeout(t)
  }, [q])

  return (
    <DataTable
      rows={rows}
      emptyText={q ? "No links match this search." : "No checks yet. Inspect a link to start."}
      toolbar={
        <div className="relative">
          <SearchIcon className="pointer-events-none absolute top-1/2 left-2 size-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            type="search"
            aria-label="Search links or page titles"
            placeholder="Search links or titles"
            className="h-7 w-56 pl-7 text-[0.8rem]"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
      }
    />
  )
}
