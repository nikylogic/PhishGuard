import * as React from "react"
import { toast } from "sonner"
import { Trash2Icon, UserPlusIcon } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { ago, api, errText } from "@/lib/api"

type SettingsData = { browsers: { name: string; path: string }[]; browser_path: string; llm_provider: string; llm_model: string; llm_api_key: string }
type UserRow = { id: number; username: string; role: string; last_login: string | null }
type AuditRow = { id: number; created_at: string; username: string | null; action: string; detail: string | null }

const PROVIDERS = [
  { value: "none", label: "Off" },
  { value: "gemini", label: "Google Gemini (free tier)" },
  { value: "groq", label: "Groq (free tier)" },
  { value: "ollama", label: "Ollama (offline, on this PC)" },
]

export function Settings() {
  return (
    <Tabs defaultValue="general" className="gap-4 px-4 lg:px-6">
      <TabsList>
        <TabsTrigger value="general">General</TabsTrigger>
        <TabsTrigger value="users">Users</TabsTrigger>
        <TabsTrigger value="audit">Audit log</TabsTrigger>
      </TabsList>
      <TabsContent value="general">
        <General />
      </TabsContent>
      <TabsContent value="users">
        <Users />
      </TabsContent>
      <TabsContent value="audit">
        <Audit />
      </TabsContent>
    </Tabs>
  )
}

async function save(body: object) {
  try {
    await api("/api/settings", { method: "POST", body })
    toast.success("Saved.")
  } catch (e) {
    toast.error(errText(e))
  }
}

function General() {
  const [s, setS] = React.useState<SettingsData | null>(null)
  React.useEffect(() => {
    api<SettingsData>("/api/settings").then(setS).catch(() => null)
  }, [])
  if (!s) return null
  const set = (k: keyof SettingsData) => (v: string) => setS({ ...s, [k]: v })
  return (
    <div className="grid grid-cols-1 items-start gap-4 @4xl/main:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>Your real browser</CardTitle>
          <CardDescription>Safe links are handed to this browser. PhishGuard starts it directly, so links never loop back into PhishGuard.</CardDescription>
        </CardHeader>
        <CardContent>
          <Field>
            <FieldLabel htmlFor="browser">Browser</FieldLabel>
            <Select value={s.browser_path || "auto"} onValueChange={(v) => set("browser_path")(v === "auto" ? "" : v)}>
              <SelectTrigger id="browser" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="auto">Detect automatically</SelectItem>
                {s.browsers.map((b) => (
                  <SelectItem key={b.path} value={b.path}>
                    {b.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {s.browser_path && <FieldDescription className="font-mono text-xs break-all">{s.browser_path}</FieldDescription>}
          </Field>
        </CardContent>
        <CardFooter>
          <Button onClick={() => save({ browser_path: s.browser_path })}>Save</Button>
        </CardFooter>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>AI second opinion</CardTitle>
          <CardDescription>Optional. An AI model reads the page and may raise the risk. It can never lower it.</CardDescription>
        </CardHeader>
        <CardContent>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="provider">Provider</FieldLabel>
              <Select value={s.llm_provider || "none"} onValueChange={set("llm_provider")}>
                <SelectTrigger id="provider" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {PROVIDERS.map((p) => (
                    <SelectItem key={p.value} value={p.value}>
                      {p.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
            <Field>
              <FieldLabel htmlFor="model">Model name</FieldLabel>
              <Input id="model" placeholder="leave empty for the default" value={s.llm_model} onChange={(e) => set("llm_model")(e.target.value)} />
            </Field>
            <Field>
              <FieldLabel htmlFor="apikey">API key</FieldLabel>
              <Input
                id="apikey"
                type="password"
                autoComplete="off"
                placeholder="not needed for Ollama"
                value={s.llm_api_key}
                onChange={(e) => set("llm_api_key")(e.target.value)}
              />
            </Field>
          </FieldGroup>
        </CardContent>
        <CardFooter>
          <Button onClick={() => save({ llm_provider: s.llm_provider, llm_model: s.llm_model, llm_api_key: s.llm_api_key })}>Save</Button>
        </CardFooter>
      </Card>
    </div>
  )
}

function Users() {
  const [users, setUsers] = React.useState<UserRow[]>([])
  const [name, setName] = React.useState("")
  const [pw, setPw] = React.useState("")
  const [role, setRole] = React.useState("analyst")
  const load = React.useCallback(() => {
    api<{ users: UserRow[] }>("/api/users")
      .then((r) => setUsers(r.users))
      .catch(() => null)
  }, [])
  React.useEffect(load, [load])
  const del = async (u: UserRow) => {
    try {
      await api(`/api/users/${u.id}`, { method: "DELETE" })
      toast.success(`${u.username} removed.`)
      load()
    } catch (e) {
      toast.error(errText(e))
    }
  }
  const add = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      await api("/api/users", { method: "POST", body: { username: name, password: pw, role } })
      toast.success("Added.")
      setName("")
      setPw("")
      load()
    } catch (err) {
      toast.error(errText(err))
    }
  }
  return (
    <div className="grid grid-cols-1 items-start gap-4 @4xl/main:grid-cols-2">
      <div className="overflow-hidden rounded-lg border">
        <Table>
          <TableHeader className="bg-muted">
            <TableRow>
              <TableHead>Person</TableHead>
              <TableHead>Role</TableHead>
              <TableHead>Last login</TableHead>
              <TableHead className="w-10" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {users.map((u) => (
              <TableRow key={u.id}>
                <TableCell className="font-medium">{u.username}</TableCell>
                <TableCell>
                  <Badge variant={u.role === "admin" ? "default" : "outline"}>{u.role === "admin" ? "Admin" : "Analyst"}</Badge>
                </TableCell>
                <TableCell className="text-muted-foreground">{ago(u.last_login)}</TableCell>
                <TableCell>
                  <Button variant="ghost" size="icon-sm" aria-label={`Remove ${u.username}`} onClick={() => del(u)}>
                    <Trash2Icon />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      <Card>
        <form onSubmit={add} className="contents">
          <CardHeader>
            <CardTitle>Add a person</CardTitle>
            <CardDescription>Analysts check links and edit the lists. Admins can also change settings and people.</CardDescription>
          </CardHeader>
          <CardContent>
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="new-user">Username</FieldLabel>
                <Input id="new-user" autoComplete="off" required value={name} onChange={(e) => setName(e.target.value)} />
              </Field>
              <Field>
                <FieldLabel htmlFor="new-pw">Password</FieldLabel>
                <Input id="new-pw" type="password" autoComplete="new-password" required value={pw} onChange={(e) => setPw(e.target.value)} />
                <FieldDescription>8 characters or more</FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="new-role">Role</FieldLabel>
                <Select value={role} onValueChange={setRole}>
                  <SelectTrigger id="new-role" className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="analyst">Analyst</SelectItem>
                    <SelectItem value="admin">Admin</SelectItem>
                  </SelectContent>
                </Select>
              </Field>
            </FieldGroup>
          </CardContent>
          <CardFooter>
            <Button type="submit">
              <UserPlusIcon />
              Add
            </Button>
          </CardFooter>
        </form>
      </Card>
    </div>
  )
}

function Audit() {
  const [rows, setRows] = React.useState<AuditRow[]>([])
  React.useEffect(() => {
    api<{ items: AuditRow[] }>("/api/audit")
      .then((r) => setRows(r.items))
      .catch(() => null)
  }, [])
  return (
    <div className="overflow-hidden rounded-lg border">
      <Table>
        <TableHeader className="bg-muted">
          <TableRow>
            <TableHead className="w-28">When</TableHead>
            <TableHead className="w-28">Who</TableHead>
            <TableHead>What</TableHead>
            <TableHead>Details</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((a) => (
            <TableRow key={a.id}>
              <TableCell className="text-muted-foreground">{ago(a.created_at)}</TableCell>
              <TableCell>{a.username || "launcher"}</TableCell>
              <TableCell>{a.action.replace(/_/g, " ")}</TableCell>
              <TableCell className="max-w-[28rem] truncate font-mono text-xs">{a.detail || ""}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}
