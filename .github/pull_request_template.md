## What this changes

<!-- One or two sentences. Link the issue if there is one: "Fixes #12". -->

## How it was tested

- [ ] `python -m pytest` passes
- [ ] Added or updated a test for this change
- [ ] Dashboard changes: `npx tsc --noEmit` and `npm run build` pass, and the built files in `phishguard/static/app` are included
- [ ] Detection changes: a test shows the attack caught **and** a real site not flagged (benchmark table below if you have one)

## Checklist

- [ ] No live phishing or malware links anywhere (defanged: `hxxps://example[.]com`)
- [ ] No security guard was weakened (CSP, CSRF, egress gatekeeper, refusing non-web links)
- [ ] `proof/` files rewritten by the test run were undone
- [ ] I have signed the [CLA](../CLA.md) (the bot asks on your first pull request)
