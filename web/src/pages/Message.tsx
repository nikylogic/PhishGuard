import { LockIcon, SearchXIcon, ShieldXIcon } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty"
import { boot } from "@/lib/api"

// The 403 and 404 pages. Flask puts the title and text on the root element.
export function Message() {
  const title = boot.title || "Nothing here"
  const text = boot.text || "This page does not exist."
  // Personal mode, opened without the Start menu shortcut: "Go home" would only lead back here.
  const lockedOut = boot.mode === "personal" && !boot.user
  const Icon = lockedOut ? LockIcon : title === "Not allowed" ? ShieldXIcon : SearchXIcon
  return (
    <div className="px-4 lg:px-6">
      <Empty className="min-h-[60svh] border border-dashed">
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <Icon />
          </EmptyMedia>
          <EmptyTitle>
            <h2 className="text-lg">{title}</h2>
          </EmptyTitle>
          <EmptyDescription>{text}</EmptyDescription>
        </EmptyHeader>
        {!lockedOut && (
          <EmptyContent>
            <Button asChild>
              <a href="/">Go home</a>
            </Button>
          </EmptyContent>
        )}
      </Empty>
    </div>
  )
}
