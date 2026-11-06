# Security Policy

PhishGuard opens dangerous links on purpose, so a flaw in PhishGuard itself could put its users at risk. Thank you for reporting one responsibly.

## Report a vulnerability privately

Use **[Report a vulnerability](https://github.com/nikylogic/PhishGuard/security/advisories/new)** on this repository (the Security tab). Only the maintainer can see it.

**Do not** open a public issue, pull request or discussion about a vulnerability before it is fixed.

Please include:

- what an attacker could do (for example: escape the sandbox, run a program, read PhishGuard's data, make a dangerous link open unchecked, or bypass the warning);
- the PhishGuard version (Settings → General, at the bottom);
- step-by-step instructions or a proof of concept. A local test page is ideal. Please don't send live phishing or malware.

## What happens next

- You get a reply within **7 days**.
- We confirm the problem, fix it and publish a release, keeping you informed.
- You are credited in the release notes unless you'd rather not be.

## In scope

- The engine (`phishguard/`), the launcher (`launcher/`), the dashboard (`web/`) and the installer.
- Ways a link can reach your real browser without being checked or warned about.
- Ways a web page in the sandbox can affect your PC, your data or PhishGuard's settings.

## Not a vulnerability

- A phishing page that PhishGuard **does not detect**. That is a detection gap; please [report it as an issue](https://github.com/nikylogic/PhishGuard/issues/new?template=missed-phishing.yml), with the link defanged.
- Problems that need an attacker who already controls your Windows account.

## Supported versions

Only the latest release gets security fixes.
