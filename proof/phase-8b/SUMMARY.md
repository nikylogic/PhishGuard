# Phase 8b: optional accounts and the default-browser button

**Goal:** one person can use PhishGuard without ever making an account, and making PhishGuard the default browser should not need a script.

## What was built

### Two modes, chosen on first run

- **Just me (the default).** There is no password. A built-in owner account is used, and its password is random and never shown, so nobody can log in with it.
  - **How you get in:** through the PhishGuard **Start menu shortcut**. The shortcut runs the launcher with `--dashboard`. The launcher holds the secret `launcher.token`, asks the engine for a **one-time code** that lasts 60 seconds, and opens `/enter/<code>`. The code signs the window in and is then used up.
  - **What a stranger sees:** a web page, another program, or someone opening `127.0.0.1:5157` in a browser gets nothing but "Open PhishGuard from the Start menu". A web page cannot read the token, and a guessed or reused code gets nothing.
  - **Staying signed in:** the session lasts 30 days.
- **Several people (accounts).** This is the same as before: usernames, passwords, admin and analyst roles, and login rate limiting.
- **Switching:** you can switch at any time in **Settings → Who uses PhishGuard** (admins only).
  - **Just me → accounts:** you choose a username and password for your own account.
  - **Accounts → just me:** you need your current password. Other accounts are kept, but they cannot log in until accounts are turned back on.
- **Older databases** that already have users and no saved mode count as "accounts", so nothing changes for them.

### "Make PhishGuard my default browser"

Windows does not let any program make itself the default browser. The choice is stored with a check value that only the Settings app can produce, and since 2024 a Windows driver also blocks direct writes to the http/https choice. Tools that get around this are flagged by antivirus software as browser hijacking, so PhishGuard does not use them.

The button in **Settings → Default browser** does the two things a program is allowed to do:

1. It registers PhishGuard for the current user and adds the Start menu shortcut. This writes only under HKCU and needs no admin rights. The keys are the same ones `register_windows.py` writes.
2. It opens Windows Settings directly on PhishGuard's own page (`ms-settings:defaultapps?registeredAppUser=PhishGuard`). The user presses **Set default** there.

The card then checks Windows' own record (`UserChoice`) every 2 seconds and shows when PhishGuard has become the default. **Stop using PhishGuard for links** removes everything and opens Default apps, so you can choose your old browser again.

Because the user confirms in Windows itself, nothing can quietly take over their browser.

## Tests (`tests/test_phase8b_accounts.py`, 20 passed)

- **First run:**
  - The setup page offers both choices.
  - "Just me" signs you in with no password.
  - Setup cannot be run twice.
  - The owner account cannot be logged into with a password.
  - The session cookie lasts beyond closing the window.
- **Strangers:**
  - A new browser in personal mode gets a 401 from the API and the "Start menu" page.
  - Only the real launcher token gets an entry code.
  - A code works once and expires after 60 seconds.
  - In accounts mode the launcher gets no code.
- **Switching:**
  - Personal → accounts → personal works end to end.
  - A wrong password is refused.
  - Other accounts are locked out in personal mode.
  - Analysts cannot switch.
  - Old databases count as accounts.
- **Real launcher:** `pg_open.pyw --dashboard`, run as its own process:
  - It starts the engine and shows first-run setup.
  - After setup, it hands over an `/enter/` code that signs a cookie-less browser in once.
  - If the engine cannot start, it shows a message box.
- **Default-browser button (throwaway HKCU key, temporary shortcut, Windows Settings replaced by a recorder):**
  - It registers PhishGuard and opens exactly the PhishGuard Settings page.
  - The shortcut runs `pg_open.pyw --dashboard`.
  - It detects when Windows' `UserChoice` points at PhishGuard.
  - Remove undoes everything.
  - Only logged-in admins with a CSRF token can use it.

**Full suite after this phase:** 349 passed, 1 skipped (the live-LLM test, which needs an API key).

## Screenshots

`scripts/shots_phase8b.py` takes these with a throwaway instance. There were no console errors.

- `first-run.png`, `first-run-accounts.png`: the two first-run choices.
- `settings-personal.png`: Settings in personal mode. There is no Users tab and no Log out.
- `settings-default-clicked.png`: after pressing the button.
- `stranger-locked-out.png`: what anyone else sees.

## Honest limits

- The instance folder is on drive D:, which other Windows accounts on the same PC may be able to read. Someone with another account on this PC who can read `launcher.token` could open the dashboard. Personal mode is meant for a PC used by one person. Shared PCs should use accounts.
