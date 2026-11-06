import * as React from "react"
import { toast } from "sonner"
import { Trash2Icon } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Empty, EmptyDescription, EmptyHeader } from "@/components/ui/empty"
import { Input } from "@/components/ui/input"
import { Item, ItemActions, ItemContent, ItemDescription, ItemGroup, ItemTitle } from "@/components/ui/item"
import { Label } from "@/components/ui/label"
import { api, errText } from "@/lib/api"

type Entry = { id: number; domain: string; kind: "allow" | "block"; note: string | null; added_by: string | null; created_at: string }

export function Lists() {
  const [items, setItems] = React.useState<Entry[] | null>(null)
  const load = React.useCallback(() => {
    api<{ items: Entry[] }>("/api/lists")
      .then((r) => setItems(r.items))
      .catch(() => setItems([]))
  }, [])
  React.useEffect(load, [load])

  const remove = async (i: Entry) => {
    try {
      await api(`/api/lists/${i.id}`, { method: "DELETE" })
      toast.success(`${i.domain} removed.`)
      load()
    } catch (e) {
      toast.error(errText(e))
    }
  }

  return (
    <div className="grid grid-cols-1 gap-4 px-4 md:gap-6 lg:px-6 @4xl/main:grid-cols-2">
      <Column
        kind="allow"
        title="Trusted"
        text="Links to these sites skip the airlock and open straight away."
        example="wikipedia.org"
        items={items?.filter((i) => i.kind === "allow")}
        onAdded={load}
        onRemove={remove}
      />
      <Column
        kind="block"
        title="Blocked"
        text="Links to these sites are stopped at once. They are never opened, not even in the sandbox."
        example="paypa1-secure.top"
        items={items?.filter((i) => i.kind === "block")}
        onAdded={load}
        onRemove={remove}
      />
    </div>
  )
}

function Column(props: {
  kind: "allow" | "block"
  title: string
  text: string
  example: string
  items?: Entry[]
  onAdded: () => void
  onRemove: (i: Entry) => void
}) {
  const [domain, setDomain] = React.useState("")
  const add = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!domain.trim()) return
    try {
      const r = await api<{ domain: string }>("/api/lists", { method: "POST", body: { domain, kind: props.kind } })
      toast.success(`${r.domain} added.`)
      setDomain("")
      props.onAdded()
    } catch (err) {
      toast.error(errText(err))
    }
  }
  const id = `add-${props.kind}`
  return (
    <Card className="shadow-xs">
      <CardHeader>
        <CardTitle className="text-lg">{props.title}</CardTitle>
        <CardDescription>{props.text}</CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        <form onSubmit={add} className="flex gap-2">
          <Label htmlFor={id} className="sr-only">
            {props.kind === "allow" ? "Trusted site" : "Blocked site"}
          </Label>
          <Input id={id} placeholder={`e.g. ${props.example}`} className="font-mono" value={domain} onChange={(e) => setDomain(e.target.value)} />
          <Button type="submit" variant="outline">
            Add
          </Button>
        </form>
        {props.items && props.items.length ? (
          <ItemGroup className="gap-2">
            {props.items.map((i) => (
              <Item key={i.id} variant="outline" size="sm">
                <ItemContent>
                  <ItemTitle className="font-mono">{i.domain}</ItemTitle>
                  {(i.note || i.added_by) && (
                    <ItemDescription>{[i.note, i.added_by && `added by ${i.added_by}`].filter(Boolean).join(" · ")}</ItemDescription>
                  )}
                </ItemContent>
                <ItemActions>
                  <Button variant="ghost" size="icon-sm" aria-label={`Remove ${i.domain}`} onClick={() => props.onRemove(i)}>
                    <Trash2Icon />
                  </Button>
                </ItemActions>
              </Item>
            ))}
          </ItemGroup>
        ) : (
          <Empty className="border border-dashed py-8">
            <EmptyHeader>
              <EmptyDescription>No sites yet.</EmptyDescription>
            </EmptyHeader>
          </Empty>
        )}
      </CardContent>
    </Card>
  )
}
