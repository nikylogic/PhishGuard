# Phase 7: the user interface ("The Airlock")

**Goal:** a simple, calm interface. It shows the dangerous page safely behind glass, gives a verdict anyone can understand, and makes the safe choice the easy one.

## What was built

- **Airlock (`/check/<id>`):** a "luggage tag" with the link and its real domain highlighted. A glass case holds the sandbox screenshot and shows a sweep animation while the check is running.
- **Verdict:** a rubber-stamp verdict (CLEAR / CAUTION / DANGER) and four gauges (Phishing, Malware, Tracking, Tricks). Below them, a plain-English "Why" list.
- **Actions:** "Keep it locked" is the main button on dangerous pages. Opening a DANGER link needs a second confirmation.
- **Tabs:** Journey (redirect chain), Privacy report, Downloads (quarantined), AI Guard, Technical.
- **Home:** a one-line summary of the day, a paste-to-inspect box, today's tallies, recent checks, a chart for the week and the most-stopped sites.
- **Other pages:**
  - History, with search and a verdict filter.
  - Trusted & blocked lists.
  - AI Guard lab, a live prompt-injection tester.
  - Settings, for admins only: LLM provider, users, audit log.
  - First-run setup and login.
- **Design:** Instrument Serif headings, Geist text, Geist Mono for links. All fonts are bundled locally and nothing is loaded from the internet.
- **Themes and motion:** light and dark themes follow the Windows setting, and animations are reduced when the user asks for less motion.
- **Script safety:** the strict Content-Security-Policy is kept: no inline scripts or styles anywhere.

## Bugs found and fixed in this phase

| Found by | Problem | Fix |
|---|---|---|
| Logging in through a real browser | Login was refused with 403. `Referrer-Policy: no-referrer` makes Chrome send `Origin: null`, which our cross-site check rejects. | Policy changed to `same-origin`. The Phase 0 test was updated and still passes. |
| Screenshot review | The "Opening the page…" placeholder stayed visible under the screenshot. A CSS `display` rule beat the `hidden` attribute. | Added a global `[hidden] { display: none !important }`. |
| Screenshot review | The tally card on Home stretched to the full hero height, and the Inspect button wrapped. | Fixed the alignment and kept the form on one line. |
| Screenshot review | "Open anyway…" wrapped onto two lines. | Made the secondary buttons non-wrapping. |
| `test_text_colours_meet_wcag_aa` | Three light-theme colours were below WCAG AA (4.5:1): muted text 4.33, caution badge 3.56, clear badge 4.50. | Darkened them to 5.17, 5.14 and 5.51. |

## Tests (`tests/test_phase7_ui.py`, 17 passed)

These run in real Chrome against a live server on a free port.

- **Flows:**
  - A wrong password shows an error.
  - Home shows the right counts.
  - A DANGER verdict explains itself and makes "Keep it locked" the main button.
  - The hidden AI instructions are shown.
  - "Open anyway" asks for confirmation.
  - Inspect from Home leads to the Airlock.
  - The Guard lab flags the example attack.
- **Roles:** an analyst sees no Settings link and gets 403 on `/settings`. A logged-out user is sent to login.
- **Quality:**
  - No console errors on any screen.
  - Every image has alt text and every input has a label.
  - No sideways scrolling at 1366, 1920 or 900 px wide.
  - Dark mode follows the system setting.
  - Text colour contrast meets WCAG AA in both themes.

**Full suite after this phase:** 301 passed, 1 skipped (the live-LLM test, which needs an API key).

## Proof files

- `pytest.txt`, `junit.xml`: the Phase 7 test run
- `screens/`: 60 screenshots of the demo, captured by `scripts/screens.py`. Every screen in light and dark at 1366×768, and light at 1920×1080. 0 console errors (`console-errors.json`).
- `test-shots/`: screenshots taken by the tests themselves
