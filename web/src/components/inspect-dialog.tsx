import * as React from "react"
import { Link2Icon } from "lucide-react"
import { toast } from "sonner"

import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Spinner } from "@/components/ui/spinner"
import { api, errText } from "@/lib/api"
import { navigate } from "@/lib/router"

// The URL box: sends a pasted link to the airlock and opens its check page.
export function InspectForm({ autoFocus, onDone }: { autoFocus?: boolean; onDone?: () => void }) {
  const [url, setUrl] = React.useState("")
  const [busy, setBusy] = React.useState(false)
  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!url.trim()) return
    setBusy(true)
    try {
      const r = await api<{ id: number }>("/api/scan", { method: "POST", body: { url } })
      onDone?.()
      navigate(`/check/${r.id}`)
    } catch (err) {
      toast.error(errText(err))
      setBusy(false)
    }
  }
  return (
    <form onSubmit={submit} className="grid gap-3">
      <Label htmlFor="inspect-url" className="sr-only">
        Link to inspect
      </Label>
      <div className="flex gap-2">
        <div className="relative flex-1">
          <Link2Icon className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            id="inspect-url"
            name="url"
            autoFocus={autoFocus}
            autoComplete="off"
            placeholder="https://…"
            className="h-9 pl-8 font-mono"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
        </div>
        <Button type="submit" size="lg" disabled={busy || !url.trim()}>
          {busy && <Spinner />}
          Inspect
        </Button>
      </div>
    </form>
  )
}

export function InspectDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>Inspect a link</DialogTitle>
          <DialogDescription>It opens in the sandbox first. You decide after the verdict.</DialogDescription>
        </DialogHeader>
        <InspectForm autoFocus onDone={() => onOpenChange(false)} />
      </DialogContent>
    </Dialog>
  )
}
