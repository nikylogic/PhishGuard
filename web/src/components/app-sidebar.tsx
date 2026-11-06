import * as React from "react"
import {
  LayoutDashboardIcon,
  HistoryIcon,
  ListChecksIcon,
  ScanTextIcon,
  Settings2Icon,
  ShieldCheckIcon,
  SearchIcon,
} from "lucide-react"

import { NavDocuments } from "@/components/nav-documents"
import { NavMain } from "@/components/nav-main"
import { NavSecondary } from "@/components/nav-secondary"
import { NavUser } from "@/components/nav-user"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar"
import { boot } from "@/lib/api"

export function AppSidebar({ ...props }: React.ComponentProps<typeof Sidebar>) {
  const user = boot.user!
  const at = boot.page === "check" ? "history" : boot.page
  const main = [
    { title: "Dashboard", url: "/", icon: <LayoutDashboardIcon />, isActive: at === "home" },
    { title: "History", url: "/history", icon: <HistoryIcon />, isActive: at === "history" },
    { title: "Trusted & blocked", url: "/lists", icon: <ListChecksIcon />, isActive: at === "lists" },
  ]
  const tools = [{ title: "AI Guard lab", url: "/guard", icon: <ScanTextIcon />, isActive: at === "guard" }]
  const secondary = [
    ...(user.role === "admin"
      ? [{ title: "Settings", url: "/settings", icon: <Settings2Icon />, isActive: at === "settings" }]
      : []),
    { title: "Search", url: "/history", icon: <SearchIcon /> },
  ]
  return (
    <Sidebar collapsible="offcanvas" {...props}>
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton asChild className="data-[slot=sidebar-menu-button]:p-1.5!">
              <a href="/">
                <ShieldCheckIcon className="size-5!" />
                <span className="font-heading text-base font-semibold">PhishGuard</span>
              </a>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>
      <SidebarContent>
        <NavMain items={main} />
        <NavDocuments label="Tools" items={tools} />
        <NavSecondary items={secondary} className="mt-auto" />
      </SidebarContent>
      <SidebarFooter>
        <NavUser user={user} />
      </SidebarFooter>
    </Sidebar>
  )
}
