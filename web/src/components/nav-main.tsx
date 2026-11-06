import * as React from "react"
import { ScanSearchIcon, HistoryIcon } from "lucide-react"

import { Button } from "@/components/ui/button"
import {
  SidebarGroup,
  SidebarGroupContent,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar"
import { InspectDialog } from "@/components/inspect-dialog"

export type NavItem = { title: string; url: string; icon?: React.ReactNode; isActive?: boolean }

export function NavMain({ items }: { items: NavItem[] }) {
  const [open, setOpen] = React.useState(false)
  return (
    <SidebarGroup>
      <SidebarGroupContent className="flex flex-col gap-2">
        <SidebarMenu>
          <SidebarMenuItem className="flex items-center gap-2">
            <SidebarMenuButton
              tooltip="Inspect a link"
              onClick={() => setOpen(true)}
              className="min-w-8 bg-primary text-primary-foreground duration-200 ease-linear hover:bg-primary/90 hover:text-primary-foreground active:bg-primary/90 active:text-primary-foreground"
            >
              <ScanSearchIcon />
              <span>Inspect a link</span>
            </SidebarMenuButton>
            <Button size="icon" className="size-8 group-data-[collapsible=icon]:opacity-0" variant="outline" asChild>
              <a href="/history">
                <HistoryIcon />
                <span className="sr-only">History</span>
              </a>
            </Button>
          </SidebarMenuItem>
        </SidebarMenu>
        <SidebarMenu>
          {items.map((item) => (
            <SidebarMenuItem key={item.title}>
              <SidebarMenuButton tooltip={item.title} isActive={item.isActive} asChild>
                <a href={item.url} aria-current={item.isActive ? "page" : undefined}>
                  {item.icon}
                  <span>{item.title}</span>
                </a>
              </SidebarMenuButton>
            </SidebarMenuItem>
          ))}
        </SidebarMenu>
      </SidebarGroupContent>
      <InspectDialog open={open} onOpenChange={setOpen} />
    </SidebarGroup>
  )
}
