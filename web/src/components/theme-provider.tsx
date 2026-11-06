import * as React from "react"

// Follows the system light/dark setting by toggling the .dark class.
// (The stock shadcn provider injects a <style> tag, which our CSP does not allow.)
const QUERY = "(prefers-color-scheme: dark)"

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  React.useEffect(() => {
    const mq = window.matchMedia(QUERY)
    const apply = () => document.documentElement.classList.toggle("dark", mq.matches)
    apply()
    mq.addEventListener("change", apply)
    return () => mq.removeEventListener("change", apply)
  }, [])
  return <>{children}</>
}

export function useTheme() {
  const [dark, setDark] = React.useState(() => window.matchMedia(QUERY).matches)
  React.useEffect(() => {
    const mq = window.matchMedia(QUERY)
    const on = () => setDark(mq.matches)
    mq.addEventListener("change", on)
    return () => mq.removeEventListener("change", on)
  }, [])
  return { theme: dark ? "dark" : "light" }
}
