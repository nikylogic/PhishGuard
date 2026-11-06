import * as React from "react"
import { AlertCircleIcon, ShieldCheckIcon } from "lucide-react"

import { Alert, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { api, boot, errText, go } from "@/lib/api"

// The shadcn login-block layout: form on the left, a story panel on the right.
function Frame({ title, text, children }: { title: string; text: string; children: React.ReactNode }) {
  return (
    <div className="flex min-h-svh flex-col items-center justify-center bg-muted p-6 md:p-10">
      <div className="w-full max-w-sm md:max-w-4xl">
        <Card className="overflow-hidden p-0">
          <CardContent className="grid p-0 md:grid-cols-2">
            <div className="flex flex-col gap-6 p-6 md:p-8">
              <a href="/" className="flex items-center gap-2 font-heading font-semibold">
                <ShieldCheckIcon className="size-5" />
                PhishGuard
              </a>
              <div className="grid gap-1">
                <h1 className="text-2xl font-bold">{title}</h1>
                <p className="text-balance text-muted-foreground">{text}</p>
              </div>
              {children}
            </div>
            <div className="hidden flex-col justify-end gap-4 bg-primary p-8 text-primary-foreground md:flex">
              <h2 className="text-3xl leading-tight font-semibold text-balance">Every link waits in the airlock first.</h2>
              <p className="text-primary-foreground/75">
                PhishGuard opens links in a throwaway browser and checks them for phishing, malware, trackers and hidden AI instructions
                before they reach you.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

function useSubmit(fn: () => Promise<void>) {
  const [error, setError] = React.useState("")
  const [busy, setBusy] = React.useState(false)
  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError("")
    try {
      await fn()
    } catch (err) {
      setError(errText(err))
      setBusy(false)
    }
  }
  return { error, busy, submit }
}

function Problem({ error }: { error: string }) {
  return error ? (
    <Alert variant="destructive">
      <AlertCircleIcon />
      <AlertTitle>{error}</AlertTitle>
    </Alert>
  ) : null
}

export function Login() {
  const [username, setUsername] = React.useState("")
  const [password, setPassword] = React.useState("")
  const { error, busy, submit } = useSubmit(async () => {
    await api("/api/login", { method: "POST", body: { username, password } })
    go(boot.next.startsWith("/") && !boot.next.startsWith("//") ? boot.next : "/")
  })
  return (
    <Frame title="Log in" text="Use the account your PhishGuard admin gave you.">
      <form onSubmit={submit}>
        <FieldGroup>
          <Problem error={error} />
          <Field>
            <FieldLabel htmlFor="username">Username</FieldLabel>
            <Input id="username" name="username" autoComplete="username" autoFocus required value={username} onChange={(e) => setUsername(e.target.value)} />
          </Field>
          <Field>
            <FieldLabel htmlFor="password">Password</FieldLabel>
            <Input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </Field>
          <Field>
            <Button type="submit" disabled={busy}>
              {busy && <Spinner />}
              Log in
            </Button>
          </Field>
        </FieldGroup>
      </form>
    </Frame>
  )
}

export function Setup() {
  const [accounts, setAccounts] = React.useState(false)
  const personal = useSubmit(async () => {
    await api("/api/setup", { method: "POST", body: { mode: "personal" } })
    go("/")
  })
  if (accounts) return <AccountsSetup back={() => setAccounts(false)} />
  return (
    <Frame title="Welcome" text="Who uses PhishGuard on this PC?">
      <form onSubmit={personal.submit}>
        <FieldGroup>
          <Problem error={personal.error} />
          <Field>
            <Button type="submit" disabled={personal.busy}>
              {personal.busy && <Spinner />}
              Just me
            </Button>
            <FieldDescription>No password. Open PhishGuard from the Start menu.</FieldDescription>
          </Field>
          <Field>
            <Button type="button" variant="outline" onClick={() => setAccounts(true)}>
              Several people
            </Button>
            <FieldDescription>Each person logs in with a username and password. You can switch later in Settings.</FieldDescription>
          </Field>
        </FieldGroup>
      </form>
    </Frame>
  )
}

function AccountsSetup({ back }: { back: () => void }) {
  const [username, setUsername] = React.useState("admin")
  const [password, setPassword] = React.useState("")
  const [password2, setPassword2] = React.useState("")
  const { error, busy, submit } = useSubmit(async () => {
    await api("/api/setup", { method: "POST", body: { mode: "accounts", username, password, password2 } })
    go("/")
  })
  return (
    <Frame title="Create the admin account" text="You can add more people later in Settings.">
      <form onSubmit={submit}>
        <FieldGroup>
          <Problem error={error} />
          <Field>
            <FieldLabel htmlFor="username">Username</FieldLabel>
            <Input id="username" name="username" autoComplete="username" required value={username} onChange={(e) => setUsername(e.target.value)} />
          </Field>
          <Field>
            <FieldLabel htmlFor="password">Password</FieldLabel>
            <Input id="password" name="password" type="password" autoComplete="new-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
            <FieldDescription>At least 8 characters</FieldDescription>
          </Field>
          <Field>
            <FieldLabel htmlFor="password2">Password again</FieldLabel>
            <Input id="password2" name="password2" type="password" autoComplete="new-password" required value={password2} onChange={(e) => setPassword2(e.target.value)} />
          </Field>
          <Field>
            <Button type="submit" disabled={busy}>
              {busy && <Spinner />}
              Create admin account
            </Button>
            <Button type="button" variant="ghost" onClick={back}>
              Back
            </Button>
          </Field>
        </FieldGroup>
      </form>
    </Frame>
  )
}
