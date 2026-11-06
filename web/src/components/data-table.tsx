import * as React from "react"
import {
  columnVisibilityFeature,
  createColumnHelper,
  createPaginatedRowModel,
  createSortedRowModel,
  FlexRender,
  rowPaginationFeature,
  rowSelectionFeature,
  rowSortingFeature,
  tableFeatures,
  useTable,
  type ColumnVisibilityState,
  type SortingState,
} from "@tanstack/react-table"
import { toast } from "sonner"
import {
  EllipsisVerticalIcon,
  Columns3Icon,
  ChevronDownIcon,
  ChevronsLeftIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  ChevronsRightIcon,
  ScanSearchIcon,
  ShieldBanIcon,
} from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { InspectDialog } from "@/components/inspect-dialog"
import { GaugeDots, VerdictBadge } from "@/components/verdict"
import { ago, api, errText, go, type Level } from "@/lib/api"

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

const DECISION: Record<string, string> = { pending: "Waiting", opened: "Opened", blocked: "Blocked", ignored: "Kept locked" }

const features = tableFeatures({
  columnVisibilityFeature,
  rowPaginationFeature,
  rowSelectionFeature,
  rowSortingFeature,
  paginatedRowModel: createPaginatedRowModel(),
  sortedRowModel: createSortedRowModel(),
})

const columnHelper = createColumnHelper<typeof features, ScanRow>()

async function blockSites(domains: string[]) {
  const unique = [...new Set(domains)]
  try {
    for (const domain of unique) await api("/api/lists", { method: "POST", body: { domain, kind: "block" } })
    toast.success(unique.length === 1 ? `${unique[0]} is blocked.` : `${unique.length} sites are blocked.`)
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

const columns = columnHelper.columns([
  columnHelper.display({
    id: "select",
    header: ({ table }) => (
      <div className="flex items-center justify-center">
        <Checkbox
          checked={table.getIsAllPageRowsSelected() || (table.getIsSomePageRowsSelected() && "indeterminate")}
          onCheckedChange={(value) => table.toggleAllPageRowsSelected(!!value)}
          aria-label="Select all"
        />
      </div>
    ),
    cell: ({ row }) => (
      <div className="flex items-center justify-center">
        <Checkbox
          checked={row.getIsSelected()}
          onCheckedChange={(value) => row.toggleSelected(!!value)}
          aria-label={`Select check ${row.original.id}`}
        />
      </div>
    ),
    enableSorting: false,
    enableHiding: false,
  }),
  columnHelper.accessor("domain", {
    header: "Link",
    cell: ({ row }) => (
      <a href={`/check/${row.original.id}`} className="group block max-w-[22rem] min-w-0">
        <span className="block truncate font-mono text-[0.8rem] font-medium group-hover:underline">{row.original.domain}</span>
        <span className="block truncate text-xs text-muted-foreground">
          {row.original.title || (row.original.status === "failed" ? "Could not be opened" : row.original.url)}
        </span>
      </a>
    ),
    enableHiding: false,
  }),
  columnHelper.accessor("level", {
    header: "Verdict",
    cell: ({ row }) => (
      <div className="w-24">
        <VerdictBadge level={row.original.status === "queued" || row.original.status === "running" ? "pending" : row.original.level} />
      </div>
    ),
  }),
  columnHelper.display({
    id: "gauges",
    header: "Gauges",
    cell: ({ row }) => <GaugeDots row={row.original} />,
  }),
  columnHelper.accessor("decision", {
    header: "Decision",
    cell: ({ row }) => (
      <Badge variant="outline" className="px-1.5 text-muted-foreground">
        {DECISION[row.original.decision] ?? row.original.decision}
      </Badge>
    ),
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
          <DropdownMenuItem onSelect={() => go(`/check/${row.original.id}`)}>Open in airlock</DropdownMenuItem>
          <DropdownMenuItem onSelect={() => copy(row.original.url)}>Copy link</DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem variant="destructive" onSelect={() => blockSites([row.original.domain])}>
            Block this site
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    ),
  }),
])

const COLUMN_NAMES: Record<string, string> = { level: "Verdict", gauges: "Gauges", decision: "Decision", created_at: "When" }

const TABS = [
  { value: "all", label: "All checks" },
  { value: "danger", label: "Danger" },
  { value: "caution", label: "Caution" },
  { value: "clear", label: "Clear" },
] as const
type Tab = (typeof TABS)[number]["value"]

export function DataTable({
  rows,
  toolbar,
  emptyText = "No checks yet. Inspect a link to start.",
}: {
  rows: ScanRow[] | null
  toolbar?: React.ReactNode
  emptyText?: string
}) {
  const [tab, setTab] = React.useState<Tab>("all")
  const [rowSelection, setRowSelection] = React.useState({})
  const [columnVisibility, setColumnVisibility] = React.useState<ColumnVisibilityState>({})
  const [sorting, setSorting] = React.useState<SortingState>([])
  const [pagination, setPagination] = React.useState({ pageIndex: 0, pageSize: 10 })
  const [inspect, setInspect] = React.useState(false)

  const all = rows ?? []
  const count = (l: Level) => all.filter((r) => r.level === l).length
  const data = React.useMemo(() => (tab === "all" ? all : all.filter((r) => r.level === tab)), [all, tab])

  const table = useTable({
    features,
    data,
    columns,
    state: { sorting, columnVisibility, rowSelection, pagination },
    getRowId: (row) => row.id.toString(),
    enableRowSelection: true,
    onRowSelectionChange: setRowSelection,
    onSortingChange: setSorting,
    onColumnVisibilityChange: setColumnVisibility,
    onPaginationChange: setPagination,
  })

  const changeTab = (v: string) => {
    setTab(v as Tab)
    setPagination((p) => ({ ...p, pageIndex: 0 }))
    setRowSelection({})
  }
  const selected = table.getSelectedRowModel().rows.map((r) => r.original.domain)

  return (
    <Tabs value={tab} onValueChange={changeTab} className="w-full flex-col justify-start gap-6">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 lg:px-6">
        <Label htmlFor="view-selector" className="sr-only">
          Verdict
        </Label>
        <Select value={tab} onValueChange={changeTab}>
          <SelectTrigger className="flex w-fit @4xl/main:hidden" size="sm" id="view-selector">
            <SelectValue placeholder="Select a view" />
          </SelectTrigger>
          <SelectContent>
            <SelectGroup>
              {TABS.map((t) => (
                <SelectItem key={t.value} value={t.value}>
                  {t.label}
                </SelectItem>
              ))}
            </SelectGroup>
          </SelectContent>
        </Select>
        <TabsList className="hidden **:data-[slot=badge]:size-5 **:data-[slot=badge]:rounded-full **:data-[slot=badge]:bg-muted-foreground/30 **:data-[slot=badge]:px-1 @4xl/main:flex">
          {TABS.map((t) => (
            <TabsTrigger key={t.value} value={t.value}>
              {t.label}
              {t.value !== "all" && count(t.value) > 0 && <Badge variant="secondary">{count(t.value)}</Badge>}
            </TabsTrigger>
          ))}
        </TabsList>
        <div className="flex flex-wrap items-center gap-2">
          {toolbar}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm">
                <Columns3Icon data-icon="inline-start" />
                Columns
                <ChevronDownIcon data-icon="inline-end" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-36">
              {table
                .getAllColumns()
                .filter((column) => column.getCanHide() && COLUMN_NAMES[column.id])
                .map((column) => (
                  <DropdownMenuCheckboxItem
                    key={column.id}
                    checked={column.getIsVisible()}
                    onCheckedChange={(value) => column.toggleVisibility(!!value)}
                  >
                    {COLUMN_NAMES[column.id]}
                  </DropdownMenuCheckboxItem>
                ))}
            </DropdownMenuContent>
          </DropdownMenu>
          <Button variant="outline" size="sm" onClick={() => setInspect(true)}>
            <ScanSearchIcon />
            <span className="hidden lg:inline">Inspect a link</span>
          </Button>
        </div>
      </div>
      <div className="relative flex flex-col gap-4 overflow-auto px-4 lg:px-6">
        <div className="overflow-hidden rounded-lg border">
          <Table>
            <TableHeader className="sticky top-0 z-10 bg-muted">
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
            <TableBody className="**:data-[slot=table-cell]:first:w-8">
              {table.getRowModel().rows?.length ? (
                table.getRowModel().rows.map((row) => (
                  <TableRow key={row.id} data-state={row.getIsSelected() && "selected"}>
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
        <div className="flex items-center justify-between px-4">
          <div className="hidden flex-1 items-center gap-3 text-sm text-muted-foreground lg:flex">
            {selected.length} of {data.length} row(s) selected.
            {selected.length > 0 && (
              <Button
                variant="outline"
                size="sm"
                className="text-destructive"
                onClick={() => blockSites(selected).then(() => setRowSelection({}))}
              >
                <ShieldBanIcon />
                Block {new Set(selected).size === 1 ? "this site" : `${new Set(selected).size} sites`}
              </Button>
            )}
          </div>
          <div className="flex w-full items-center gap-8 lg:w-fit">
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
                    {[10, 20, 30, 40, 50].map((pageSize) => (
                      <SelectItem key={pageSize} value={`${pageSize}`}>
                        {pageSize}
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
            </div>
            <div className="flex w-fit items-center justify-center text-sm font-medium">
              Page {table.state.pagination.pageIndex + 1} of {Math.max(1, table.getPageCount())}
            </div>
            <div className="ml-auto flex items-center gap-2 lg:ml-0">
              <Button variant="outline" className="hidden h-8 w-8 p-0 lg:flex" onClick={() => table.setPageIndex(0)} disabled={!table.getCanPreviousPage()}>
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
              <Button
                variant="outline"
                className="hidden size-8 lg:flex"
                size="icon"
                onClick={() => table.setPageIndex(table.getPageCount() - 1)}
                disabled={!table.getCanNextPage()}
              >
                <span className="sr-only">Go to last page</span>
                <ChevronsRightIcon />
              </Button>
            </div>
          </div>
        </div>
      </div>
      <InspectDialog open={inspect} onOpenChange={setInspect} />
    </Tabs>
  )
}
