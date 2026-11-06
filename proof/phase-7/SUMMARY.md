# Phase 7: the user interface

**Goal:** a simple, calm interface. It shows the dangerous page safely behind glass, gives a verdict anyone can understand, and makes the safe choice the easy one.

The UI is built with **shadcn/ui** and copies the layout of its `dashboard-01` block: an inset sidebar, a site header, four section cards, an interactive area chart and a tabbed data table. The source is in `web/` (Vite, React 19, Tailwind CSS v4, Radix). `npm run build` writes it into `phishguard/static/app/`, and Flask finds the files through Vite's manifest. Who may see which page is still decided by Flask on the server.

## What was built

- **Shell (dashboard-01):**
  - **Sidebar:** the PhishGuard brand, and "Inspect a link" in the Quick Create spot, which opens a dialog. Below that: Dashboard, History, Trusted & blocked, AI Guard lab, and Settings (admins only). The account menu at the bottom has Log out.
  - **Smooth navigation:** moving between pages does not reload the app. A small client-side router (`web/src/lib/router.ts`) swaps only the page area, and the sidebar and header stay in place. Where the browser supports it, the page area cross-fades in 140 ms; there is no animation if the user asks for reduced motion. Flask still serves every URL directly, for refresh and bookmarks, and still decides who may see what. A page the client may not show (for example Settings for an analyst) falls back to a normal page load.
- **Dashboard (`/`):**
  - **Four cards:** checked today (and yesterday), stopped today, trackers spotted, and the clear rate over 3 months. Each card is a label, a number and one short line.
  - **Chart:** a stacked area chart of Clear / Caution / Danger checks per day, with the Last 7 days / 30 days / 3 months toggle.
  - **Table:** recent checks with tabs by verdict, a per-row actions menu (open, copy, block) and pagination.
- **Airlock (`/check/<id>`):**
  - **Verdict card:** a large verdict card tinted by the verdict, showing the risk score and the link with its real domain in bold.
  - **Screenshot:** the sandbox screenshot; click it to enlarge.
  - **Gauges and reasons:** four colour-coded gauges (Phishing, Malware, Tracking, Tricks) and a plain-English "Why" list.
  - **Actions:** "Keep it locked" is the main button on dangerous pages, and opening a DANGER link asks for confirmation first.
  - **Tabs:** Journey, Privacy report, Downloads, AI Guard, Technical.
- **Other pages:**
  - History: the same table, with search.
  - Trusted & blocked lists.
  - AI Guard lab: a live prompt-injection tester.
  - Settings: General, Users, Audit log.
  - Login and first-run setup, using the shadcn login-block layout.
  - 403 and 404 pages.
- **Fonts (our own, not the shadcn default Geist):**
  - Space Grotesk for headings, IBM Plex Sans for text, JetBrains Mono for links and code.
  - All three are bundled locally; nothing loads from the internet.
- **Themes:** light and dark follow the Windows setting.
- **Verdict colours:** these are design tokens (`--clear`, `--caution`, `--danger`), tuned for WCAG AA contrast in both themes.

## Keeping the strict Content-Security-Policy

The policy has no `unsafe-inline`, so a page may not inject a `<style>` tag. Stock shadcn breaks this in five places. Each one was fixed:

| Where | What it did | Fix |
|---|---|---|
| `ui/chart.tsx` (ChartStyle) | Wrote series colours into a `<style>` tag | The colours are set as CSS variables through the container's `style` prop (CSSOM, which the policy allows) |
| Radix dialogs and menus (react-remove-scroll) | Add a scroll-lock `<style>` tag | Flask creates a one-time nonce for each page and adds it to `style-src`. The app passes it to Radix with `setNonce()` |
| Radix Select viewport | Renders a `<style>` tag | The `nonce` prop is passed to `SelectPrimitive.Viewport` |
| sonner (toasts) | Injected its CSS at runtime | Its `styles.css` is imported as a normal file. A small Vite plugin turns the runtime injection off, and the build fails if that code ever changes |
| theme-provider | Injected a style tag on theme change | Replaced with a small provider that only toggles the `.dark` class |

The Vaul drawer is not used. The final policy is: `style-src 'self' 'nonce-<fresh per page>'; script-src 'self'`, still without `unsafe-inline`.

## Cleanup pass

After the first shadcn version, everything that was decoration rather than information was removed:

- **Sidebar:** duplicate entries (a History icon button, a "Search" item that only opened History, a one-item "Tools" group, and Settings repeated in the account menu).
- **Dashboard:** extra badges and icon lines on the cards.
- **Table:** row checkboxes, the column picker, the gauge-dot column, a second "Inspect a link" button and the "Waiting" badge on every row.
- **Wording:** filler sentences and icons in titles ("Each one from 0 (quiet) to 100", "Nothing in this picture can reach you").
- **Look:** gradient fills, and the decorative rings and icon tiles on the login page.

## Bugs found and fixed in this phase

| Found by | Problem | Fix |
|---|---|---|
| `test_analyst_cannot_see_or_open_settings` | The 403 and 404 handlers crashed with a 500 error, because `page()` received `title` twice. | The page-title parameter was renamed to `tab_title`. |
| Earlier version of this phase, logging in through a real browser | Login was refused, because `Referrer-Policy: no-referrer` makes Chrome send `Origin: null`. | Policy changed to `same-origin`. |
| Earlier contrast test | Three light-theme colours were below 4.5:1. | The verdict colours were redefined as tokens, and the test now passes in both themes. |

## Tests (`tests/test_phase7_ui.py`, 21 passed)

These run in real Chrome against a live server on a free port.

- **Flows:**
  - A wrong password shows an alert.
  - The dashboard shows today's count, the table, the verdict tabs and the chart toggle.
  - A DANGER verdict explains itself and makes "Keep it locked" the main button.
  - The hidden AI instructions are shown.
  - "Open anyway" asks for confirmation.
  - "Inspect a link" in the sidebar leads to the Airlock.
  - Moving between pages through the sidebar, and back, never reloads the app.
  - The Guard lab flags the example attack.
- **Roles:** an analyst sees no Settings link and gets a 403 "Not allowed" page. A logged-out user is sent to login.
- **Build:**
  - The `dashboard-01` structure is present: SidebarProvider, inset AppSidebar, SiteHeader, SectionCards, ChartAreaInteractive and DataTable.
  - The fonts are Space Grotesk and IBM Plex Sans, not Geist, Inter or Instrument Serif.
- **Security:**
  - The policy keeps no `unsafe-inline` and uses a fresh nonce on every page.
  - Opening a dialog and a select causes no CSP errors.
- **Quality:**
  - No console errors.
  - Every image has alt text and every input has a label.
  - No sideways scrolling at 1366, 1920 or 900 px wide.
  - Dark mode follows the system setting.
  - Text contrast meets WCAG AA in light and dark. Colours are resolved through a canvas, so `oklch()` colours are measured correctly.

**Full suite after this phase:** 305 passed, 1 skipped (the live-LLM test, which needs an API key).

## Proof files

- `pytest.txt`, `junit.xml`: the Phase 7 test run.
- `screens/`: 60 screenshots of the demo, captured by `scripts/screens.py`.
  - Every screen in light and dark at 1366×768, and light at 1920×1080.
  - 0 console errors (see `console-errors.json`).
- `test-shots/`: screenshots taken by the tests themselves.
