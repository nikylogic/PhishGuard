// A tiny client-side router so moving between pages does not reload the whole app.
// Flask still serves every URL directly (refresh, bookmarks) and still decides who may see what;
// pages the client does not know, or may not show, fall back to a normal page load.
import * as React from "react"
import { flushSync } from "react-dom"

import { boot } from "@/lib/api"

export type Route = { page: string; sid: number }

export const TITLES: Record<string, string> = {
  home: "Dashboard",
  check: "Airlock",
  history: "History",
  lists: "Trusted & blocked",
  guard: "AI Guard lab",
  settings: "Settings",
}

export function match(pathname: string): Route | null {
  const isAdmin = boot.user?.role === "admin"
  if (pathname === "/") return { page: "home", sid: 0 }
  const check = /^\/check\/(\d+)$/.exec(pathname)
  if (check) return { page: "check", sid: Number(check[1]) }
  const name = pathname.slice(1)
  if (name === "history" || name === "lists" || name === "guard") return { page: name, sid: 0 }
  if (name === "settings" && isAdmin) return { page: name, sid: 0 }
  return null
}

const listeners = new Set<() => void>()
let current: Route = { page: boot.page, sid: boot.sid }

function setRoute(r: Route) {
  current = r
  document.title = `${TITLES[r.page] ?? "PhishGuard"} · PhishGuard`
  listeners.forEach((l) => l())
}

const reduceMotion = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches

function swap(r: Route) {
  const apply = () => {
    flushSync(() => setRoute(r))
    window.scrollTo(0, 0)
  }
  // A short cross-fade where the browser supports it; the sidebar stays still.
  if (document.startViewTransition && !reduceMotion()) document.startViewTransition(apply)
  else apply()
}

export function navigate(href: string) {
  const url = new URL(href, window.location.href)
  const r = url.origin === window.location.origin ? match(url.pathname) : null
  if (!r || !boot.user) {
    window.location.href = href
    return
  }
  if (url.pathname + url.search !== window.location.pathname + window.location.search) {
    history.pushState(null, "", url.pathname + url.search)
  }
  swap(r)
}

window.addEventListener("popstate", () => {
  const r = match(window.location.pathname)
  if (r) swap(r)
  else window.location.reload()
})

// Plain <a href> links inside the app go through the router.
export function interceptLinks(e: MouseEvent) {
  if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return
  const a = (e.target as HTMLElement).closest("a")
  if (!a || a.target || a.hasAttribute("download")) return
  const url = new URL(a.href, window.location.href)
  if (url.origin !== window.location.origin || !match(url.pathname)) return
  e.preventDefault()
  navigate(url.pathname + url.search)
}

export function useRoute(): Route {
  return React.useSyncExternalStore(
    (l) => {
      listeners.add(l)
      return () => listeners.delete(l)
    },
    () => current
  )
}
