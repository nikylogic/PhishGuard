// The PhishGuard window has no Windows title bar. Inside the app window (pywebview), these give it
// minimize / maximize / close buttons, a drag area and resize edges. In a normal browser tab
// `window.pywebview` does not exist and none of this renders.
import * as React from "react"
import { CopyIcon, MinusIcon, SquareIcon, XIcon } from "lucide-react"

import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

type DesktopApi = {
  minimize(): Promise<void>
  toggle_maximize(): Promise<boolean>
  is_maximized(): Promise<boolean>
  close(): Promise<void>
  resize(width: number, height: number, edge: string): Promise<void>
}

declare global {
  interface Window {
    pywebview?: { api?: Partial<DesktopApi> }
  }
}

const current = () => (window.pywebview?.api?.toggle_maximize ? (window.pywebview.api as DesktopApi) : null)

export function useDesktop(): DesktopApi | null {
  const [api, setApi] = React.useState<DesktopApi | null>(current)
  React.useEffect(() => {
    if (api) return
    const ready = () => setApi(current())
    window.addEventListener("pywebviewready", ready)
    return () => window.removeEventListener("pywebviewready", ready)
  }, [api])
  return api
}

function useMaximized(api: DesktopApi | null) {
  const [max, setMax] = React.useState(false)
  React.useEffect(() => {
    if (!api) return
    const check = () => {
      api.is_maximized().then(setMax).catch(() => null)
    }
    check()
    window.addEventListener("resize", check)
    return () => window.removeEventListener("resize", check)
  }, [api])
  return [max, setMax] as const
}

export const DRAG = "pywebview-drag-region"

// Double-clicking the header maximizes or restores, like a normal title bar.
export function useTitleBarDoubleClick() {
  const api = useDesktop()
  return (e: React.MouseEvent) => {
    if (!api || (e.target as HTMLElement).closest("button, a, input, [role=button]")) return
    api.toggle_maximize()
  }
}

export function WindowControls({ className }: { className?: string }) {
  const api = useDesktop()
  const [max, setMax] = useMaximized(api)
  if (!api) return null
  return (
    <div className={cn("flex items-center gap-0.5", className)}>
      <Button variant="ghost" size="icon-sm" aria-label="Minimize" onClick={() => api.minimize()}>
        <MinusIcon />
      </Button>
      <Button variant="ghost" size="icon-sm" aria-label={max ? "Restore" : "Maximize"} onClick={async () => setMax(await api.toggle_maximize())}>
        {max ? <CopyIcon className="size-3.5 -scale-x-100" /> : <SquareIcon className="size-3.5" />}
      </Button>
      <Button variant="ghost" size="icon-sm" aria-label="Close" className="hover:bg-danger hover:text-white" onClick={() => api.close()}>
        <XIcon />
      </Button>
    </div>
  )
}

// Thin invisible strips on every edge and corner that resize the window.
const EDGES: [string, string][] = [
  ["n", "top-0 inset-x-3 h-1.5 cursor-ns-resize"],
  ["s", "bottom-0 inset-x-3 h-1.5 cursor-ns-resize"],
  ["e", "right-0 inset-y-3 w-1.5 cursor-ew-resize"],
  ["w", "left-0 inset-y-3 w-1.5 cursor-ew-resize"],
  ["nw", "top-0 left-0 size-3 cursor-nwse-resize"],
  ["ne", "top-0 right-0 size-3 cursor-nesw-resize"],
  ["sw", "bottom-0 left-0 size-3 cursor-nesw-resize"],
  ["se", "bottom-0 right-0 size-3 cursor-nwse-resize"],
]

export function ResizeEdges() {
  const api = useDesktop()
  const [max] = useMaximized(api)
  if (!api || max) return null
  const start = (edge: string) => (e: React.PointerEvent<HTMLDivElement>) => {
    e.preventDefault()
    const el = e.currentTarget
    el.setPointerCapture(e.pointerId)
    const sx = e.screenX
    const sy = e.screenY
    const w0 = window.outerWidth
    const h0 = window.outerHeight
    let frame = 0
    let size = [w0, h0]
    const move = (ev: PointerEvent) => {
      const dx = ev.screenX - sx
      const dy = ev.screenY - sy
      size = [w0 + (edge.includes("e") ? dx : edge.includes("w") ? -dx : 0), h0 + (edge.includes("s") ? dy : edge.includes("n") ? -dy : 0)]
      if (!frame)
        frame = requestAnimationFrame(() => {
          frame = 0
          api.resize(Math.round(size[0]), Math.round(size[1]), edge)
        })
    }
    const up = () => {
      el.removeEventListener("pointermove", move)
      el.removeEventListener("pointerup", up)
      el.removeEventListener("pointercancel", up)
    }
    el.addEventListener("pointermove", move)
    el.addEventListener("pointerup", up)
    el.addEventListener("pointercancel", up)
  }
  return (
    <>
      {EDGES.map(([edge, pos]) => (
        <div key={edge} aria-hidden onPointerDown={start(edge)} className={cn("fixed z-[60]", pos)} />
      ))}
    </>
  )
}

// For pages without the app header (welcome, log in, the Airlock check window): an invisible drag strip
// across the top and the three buttons in the top-right corner. No extra visible bar.
export function FloatingWindowBar() {
  const api = useDesktop()
  const onDoubleClick = useTitleBarDoubleClick()
  if (!api) return null
  return (
    <div className={cn(DRAG, "fixed inset-x-0 top-0 z-50 flex h-10 items-center justify-end pr-2")} onDoubleClick={onDoubleClick}>
      <WindowControls />
    </div>
  )
}
