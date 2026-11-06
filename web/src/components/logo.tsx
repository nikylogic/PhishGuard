import { cn } from "cn"

// PhishGuard's mark: the same shield-and-tick drawn by packaging/make_icon.py for the taskbar,
// Start menu and installer, so the app looks the same everywhere. Keep the two in step.
export function Logo({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" aria-hidden="true" className={cn("size-6 shrink-0", className)}>
      <rect x="0" y="0" width="32" height="32" rx="6.4" fill="#171717" />
      <path d="M16 6.4 25.6 9.6V16L16 26.24 6.4 16V9.6Z" fill="none" stroke="#fff" strokeWidth="2" strokeLinejoin="miter" />
      <path d="M12.16 16 15.04 18.88 20.16 13.12" fill="none" stroke="#fff" strokeWidth="2.3" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}
