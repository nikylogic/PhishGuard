import { Separator } from "@/components/ui/separator"
import { SidebarTrigger } from "@/components/ui/sidebar"
import { DRAG, useTitleBarDoubleClick, WindowControls } from "@/components/window-controls"

// In the app window the header is also the title bar: drag it to move the window, double-click to
// maximize, and the window buttons sit on the right.
export function SiteHeader({ title }: { title: string }) {
  const onDoubleClick = useTitleBarDoubleClick()
  return (
    <header
      onDoubleClick={onDoubleClick}
      className={`${DRAG} flex h-(--header-height) shrink-0 items-center gap-2 border-b transition-[width,height] ease-linear group-has-data-[collapsible=icon]/sidebar-wrapper:h-(--header-height)`}
    >
      <div className="flex w-full items-center gap-1 px-4 lg:gap-2 lg:px-6">
        <SidebarTrigger className="-ml-1" />
        <Separator orientation="vertical" className="mx-2 data-[orientation=vertical]:h-4" />
        <h1 className="text-base font-medium">{title}</h1>
        <WindowControls className="-mr-2 ml-auto" />
      </div>
    </header>
  )
}
