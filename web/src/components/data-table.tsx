import * as React from "react"
import {
  columnVisibilityFeature,
  createColumnHelper,
  createPaginatedRowModel,
  FlexRender,
  rowPaginationFeature,
  tableFeatures,
  useTable,
} from "@tanstack/react-table"
import { toast } from "sonner"
import { EllipsisVerticalIcon, ChevronsLeftIcon, ChevronLeftIcon, ChevronRightIcon, ChevronsRightIcon } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { VerdictBadge } from "@/components/verdict"
import { ago, api, errText, type Level } from "@/lib/api"
import { navigate } from "@/lib/router"

export type ScanRow = {
  id: number
  url: string
  domain: string
  title: string | null
  level: Level
  status: string
  decision: string
  created_at: string
  s_phishing: number
  s_malware: number
  s_tracking: number
  s_abuse: number
}

const DECISION: Record<string, string> = { pending: "–", opened: "Opened", blocked: "Blocked", ignored: "Kept locked" }

const features = tableFeatures({ columnVisibilityFeature, rowPaginationFeature, paginatedRowModel: createPaginatedRowModel() })
const columnHelper = createColumnHelper<typeof features, ScanRow>()

async function blockSite(domain: string) {
  try {
    await api("/api/lists", { method: "POST", body: { domain, kind: "block" } })
    toast.success(`${domain} is blocked.`)
  } catch (e) {
    toast.error(errText(e))
  }
}

async function copy(text: string) {
  try {
    await navigator.clipboard.writeText(text)
    toast.success("Link copied.")
  } catch {
    toast.error("Could not copy.")
  }
}

const busy = (r: ScanRow) => r.status === "queued" || r.status === "running"

const columns = columnHelper.columns([
  columnHelper.accessor("domain", {
    header: "Link",
    cell: ({ row }) => (
      <a href={`/check/${row.original.id}`} className="group block max-w-[26rem] min-w-0">
        <span className="block truncate font-mono text-[0.8rem] font-medium group-hover:underline">{row.original.domain}</span>
        <span className="block truncate text-xs text-muted-foreground">
          {row.original.title || (row.original.status === "failed" ? "Could not be opened" : row.original.url)}
        </span>
      </a>
    ),
  }),
  columnHelper.accessor("level", {
    header: "Verdict",
    cell: ({ row }) => <VerdictBadge level={busy(row.original) ? "pending" : row.original.level} />,
  }),
  columnHelper.accessor("decision", {
    header: "Decision",
    cell: ({ row }) => <span className="text-muted-foreground">{DECISION[row.original.decision] ?? row.original.decision}</span>,
  }),
  columnHelper.accessor("created_at", {
    header: () => <div className="w-full text-right">When</div>,
    cell: ({ row }) => <div className="text-right text-muted-foreground tabular-nums">{ago(row.original.created_at)}</div>,
  }),
  columnHelper.display({
    id: "actions",
    cell: ({ row }) => (
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" className="flex size-8 text-muted-foreground data-[state=open]:bg-muted" size="icon">
            <EllipsisVerticalIcon />
            <span className="sr-only">Actions for {row.original.domain}</span>
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-40">
          <DropdownMenuItem onSelect={() => navigate(`/check/${row.original.id}`)}>Open in airlock</DropdownMenuItem>
          <DropdownMenuItem onSelect={() => copy(row.original.url)}>Copy link</DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem variant="destructive" onSelect={() => blockSite(row.original.domain)}>
            Block this site
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    ),
  }),
])

const TABS = [
  { value: "all", label: "All" },
  { value: "danger", label: "Danger" },
  { value: "caution", label: "Caution" },
  { value: "clear", label: "Clear" },
] as const
type Tab = (typeof TABS)[number]["value"]

export function DataTable({
  rows,
  toolbar,
  emptyText = "No checks yet.",
}: {
  rows: ScanRow[] | null
  toolbar?: React.ReactNode
  emptyText?: string
}) {
  const [tab, setTab] = React.useState<Tab>("all")
  const [pagination, setPagination] = React.useState({ pageIndex: 0, pageSize: 10 })

  const all = React.useMemo(() => rows ?? [], [rows])
  const count = (l: Level) => all.filter((r) => r.level === l).length
  const data = React.useMemo(() => (tab === "all" ? all : all.filter((r) => r.level === tab)), [all, tab])

  const table = useTable({
    features,
    data,
    columns,
    state: { pagination },
    getRowId: (row) => row.id.toString(),
    onPaginationChange: setPagination,
  })

  const changeTab = (v: string) => {
    setTab(v as Tab)
    setPagination((p) => ({ ...p, pageIndex: 0 }))
  }
  const pages = Math.max(1, table.getPageCount())

  return (
    <Tabs value={tab} onValueChange={changeTab} className="w-full flex-col justify-start gap-4">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 lg:px-6">
        <TabsList className="**:data-[slot=badge]:size-5 **:data-[slot=badge]:rounded-full **:data-[slot=badge]:bg-muted-foreground/30 **:data-[slot=badge]:px-1">
          {TABS.map((t) => (
            <TabsTrigger key={t.value} value={t.value}>
              {t.label}
              {t.value !== "all" && count(t.value) > 0 && <Badge variant="secondary">{count(t.value)}</Badge>}
            </TabsTrigger>
          ))}
        </TabsList>
        {toolbar}
      </div>
      <div className="flex flex-col gap-4 px-4 lg:px-6">
        <div className="overflow-hidden rounded-lg border">
          <Table>
            <TableHeader className="bg-muted">
              {table.getHeaderGroups().map((headerGroup) => (
                <TableRow key={headerGroup.id}>
                  {headerGroup.headers.map((header) => (
                    <TableHead key={header.id} colSpan={header.colSpan}>
                      {header.isPlaceholder ? null : <FlexRender header={header} />}
                    </TableHead>
                  ))}
                </TableRow>
              ))}
            </TableHeader>
            <TableBody className="**:data-[slot=table-cell]:last:w-10">
              {table.getRowModel().rows?.length ? (
                table.getRowModel().rows.map((row) => (
                  <TableRow key={row.id}>
                    {row.getVisibleCells().map((cell) => (
                      <TableCell key={cell.id}>
                        <FlexRender cell={cell} />
                      </TableCell>
                    ))}
                  </TableRow>
                ))
              ) : (
                <TableRow>
                  <TableCell colSpan={columns.length} className="h-24 text-center text-muted-foreground">
                    {rows === null ? "Loading…" : emptyText}
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
        {pages > 1 || data.length > 10 ? (
          <div className="flex items-center justify-end gap-8 px-2">
            <div className="hidden items-center gap-2 lg:flex">
              <Label htmlFor="rows-per-page" className="text-sm font-medium">
                Rows per page
              </Label>
              <Select value={`${table.state.pagination.pageSize}`} onValueChange={(value) => table.setPageSize(Number(value))}>
                <SelectTrigger size="sm" className="w-20" id="rows-per-page">
                  <SelectValue placeholder={table.state.pagination.pageSize} />
                </SelectTrigger>
                <SelectContent side="top">
                  <SelectGroup>
                    {[10, 20, 50].map((pageSize) => (
                      <SelectItem key={pageSize} value={`${pageSize}`}>
                        {pageSize}
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
            </div>
            <div className="text-sm font-medium">
              Page {table.state.pagination.pageIndex + 1} of {pages}
            </div>
            <div className="flex items-center gap-2">
              <Button variant="outline" className="hidden size-8 lg:flex" size="icon" onClick={() => table.setPageIndex(0)} disabled={!table.getCanPreviousPage()}>
                <span className="sr-only">Go to first page</span>
                <ChevronsLeftIcon />
              </Button>
              <Button variant="outline" className="size-8" size="icon" onClick={() => table.previousPage()} disabled={!table.getCanPreviousPage()}>
                <span className="sr-only">Go to previous page</span>
                <ChevronLeftIcon />
              </Button>
              <Button variant="outline" className="size-8" size="icon" onClick={() => table.nextPage()} disabled={!table.getCanNextPage()}>
                <span className="sr-only">Go to next page</span>
                <ChevronRightIcon />
              </Button>
              <Button variant="outline" className="hidden size-8 lg:flex" size="icon" onClick={() => table.setPageIndex(pages - 1)} disabled={!table.getCanNextPage()}>
                <span className="sr-only">Go to last page</span>
                <ChevronsRightIcon />
              </Button>
            </div>
          </div>
        ) : null}
      </div>
    </Tabs>
  )
}
