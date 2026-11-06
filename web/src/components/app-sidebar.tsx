import { Logo } from "@/components/logo"
import * as React from "react"
import { HistoryIcon, LayoutDashboardIcon, ListChecksIcon, ScanTextIcon, Settings2Icon } from "lucide-react"

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
import type { Route } from "@/lib/router"

export function AppSidebar({ route, ...props }: React.ComponentProps<typeof Sidebar> & { route: Route }) {
  const user = boot.user!
  const at = route.page === "check" ? "history" : route.page
  const main = [
    { title: "Dashboard", url: "/", icon: <LayoutDashboardIcon />, isActive: at === "home" },
    { title: "History", url: "/history", icon: <HistoryIcon />, isActive: at === "history" },
    { title: "Trusted & blocked", url: "/lists", icon: <ListChecksIcon />, isActive: at === "lists" },
    { title: "AI Guard lab", url: "/guard", icon: <ScanTextIcon />, isActive: at === "guard" },
  ]
  const secondary =
    user.role === "admin" ? [{ title: "Settings", url: "/settings", icon: <Settings2Icon />, isActive: at === "settings" }] : []
  return (
    <Sidebar collapsible="offcanvas" {...props}>
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton asChild className="data-[slot=sidebar-menu-button]:p-1.5!">
              <a href="/">
                <Logo className="size-6!" />
                <span className="font-heading text-base font-semibold">PhishGuard</span>
              </a>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>
      <SidebarContent>
        <NavMain items={main} />
        {secondary.length > 0 && <NavSecondary items={secondary} className="mt-auto" />}
      </SidebarContent>
      <SidebarFooter>
        <NavUser user={user} />
      </SidebarFooter>
    </Sidebar>
  )
}
