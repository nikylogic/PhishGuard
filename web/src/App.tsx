import * as React from "react"

import { AppSidebar } from "@/components/app-sidebar"
import { SiteHeader } from "@/components/site-header"
import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar"
import { Toaster } from "@/components/ui/sonner"
import { TooltipProvider } from "@/components/ui/tooltip"
import { boot } from "@/lib/api"
import { interceptLinks, TITLES, useRoute, type Route } from "@/lib/router"
import { Airlock } from "@/pages/Airlock"
import { GuardLab } from "@/pages/GuardLab"
import { History } from "@/pages/History"
import { Home } from "@/pages/Home"
import { Lists } from "@/pages/Lists"
import { Login, Setup } from "@/pages/Login"
import { Message } from "@/pages/Message"
import { Settings } from "@/pages/Settings"

function Page({ route }: { route: Route }) {
  switch (route.page) {
    case "home":
      return <Home />
    case "check":
      return <Airlock key={route.sid} sid={route.sid} />
    case "history":
      return <History />
    case "lists":
      return <Lists />
    case "guard":
      return <GuardLab />
    case "settings":
      return <Settings />
    default:
      return <Message />
  }
}

// dashboard-01: inset sidebar, site header, then the page in a container-query column.
// Only the page area changes when you move around; the sidebar and header stay mounted.
function Shell() {
  const route = useRoute()
  React.useEffect(() => {
    document.addEventListener("click", interceptLinks)
    return () => document.removeEventListener("click", interceptLinks)
  }, [])
  return (
    <SidebarProvider
      style={
        {
          "--sidebar-width": "calc(var(--spacing) * 64)",
          "--header-height": "calc(var(--spacing) * 12)",
        } as React.CSSProperties
      }
    >
      <AppSidebar variant="inset" route={route} />
      <SidebarInset>
        <SiteHeader title={TITLES[route.page] ?? boot.title ?? "PhishGuard"} />
        <div className="flex flex-1 flex-col">
          <div className="@container/main flex flex-1 flex-col gap-2">
            <div className="page-view flex flex-col gap-4 py-4 md:gap-6 md:py-6">
              <Page route={route} />
            </div>
          </div>
        </div>
      </SidebarInset>
    </SidebarProvider>
  )
}

function Body() {
  if (boot.page === "login") return <Login />
  if (boot.page === "setup") return <Setup />
  // The launcher's window shows one check without a login: no navigation around it.
  if (!boot.user) {
    return (
      <main className="@container/main mx-auto flex min-h-svh w-full max-w-6xl flex-col gap-4 py-6">
        {boot.page === "check" ? <Airlock sid={boot.sid} /> : <Message />}
      </main>
    )
  }
  return <Shell />
}

export default function App() {
  return (
    <TooltipProvider>
      <Body />
      <Toaster position="bottom-right" />
    </TooltipProvider>
  )
}
