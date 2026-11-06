# The Windows installer

**Goal:** a normal user installs PhishGuard with one file and a few clicks. They need no Python, no commands and no administrator rights.

## What was built

- **`PhishGuard-Setup-1.0.0.exe`** (71 MB), built with Inno Setup 6.7.4, which is free. Before use, the Inno Setup download's code signature was checked: it is valid and signed by Pyrsys B.V., the company of Inno Setup's author. Inno Setup was unpacked in portable mode, so nothing was installed on the build PC.
  - **Installs for the current user only:** the program goes to `%LOCALAPPDATA%\Programs\PhishGuard`, so no administrator prompt appears.
  - **Shortcuts:** it adds a Start menu shortcut, and a desktop shortcut if the user ticks the box.
  - **Uninstall:** it appears under Settings → Apps. Uninstalling stops PhishGuard and Tor, removes PhishGuard as a link handler, and asks whether to also delete the history and settings. The default answer is No.
  - **Updates:** installing a newer version first stops the running copy.
- **Two programs**, built with PyInstaller (`packaging/PhishGuard.spec`):
  - **`PhishGuard.exe` (5 MB):** what Windows runs for every clicked link, plus the dashboard window. It contains only Python's standard library and pywebview.
  - **`PhishGuardEngine.exe`:** the engine (web server, sandbox, AI Guard). The small program starts it only when a link needs a full check.
  - **What is left out:** the model-training libraries (torch, transformers, pandas) and unused extras (pyarrow, PIL). At run time the AI Guard is a 1.3 MB scikit-learn model. This brought the program folder from 351 MB down to 257 MB.
- **Data** is stored in `%LOCALAPPDATA%\PhishGuard`. Only the user's own Windows account can read that folder, which also removes the shared-drive caveat noted in Phase 8b.
- **Sandbox browser:** it uses Chrome if installed, otherwise Microsoft Edge, which every Windows 10/11 PC has.
- **Version details** on the program file: "PhishGuard 1.0.0, © 2026 Nikhil P".

## Results (measured on the packaged programs)

| What | Result |
|---|---|
| Trusted link, a real click (11 runs) | **216 ms** median (target: under 300 ms) |
| Program start alone | 179 ms |
| Unknown link, engine not yet running | Engine started, link checked, Airlock address returned in **3.7 s** |
| Full check inside the packaged engine | Sandbox screenshot taken, rules and AI Guard ran, verdict **Danger 65/100** for `paypa1-secure.top` |
| Dashboard window | Opens from the packaged app (`installed-app-first-run.png`) |
| Engine cannot start | Fails closed: a message box, and the link is not opened |

An earlier measurement showed about 640 ms. That was an error in the test: the stand-in browser held the timer's output pipe open. A real click from Windows has no such pipe.

## Known limits

- **SmartScreen warning:** the installer is not code-signed, because signing certificates cost money and the budget is $0. Windows shows "Windows protected your PC" the first time, and the user clicks **More info → Run anyway**.
- **Size:** most of the program folder is Playwright's browser driver (104 MB), which the sandbox needs.

## Build it again

```
.venv\Scripts\python packaging\make_icon.py
.venv\Scripts\pyinstaller --noconfirm --distpath build\dist --workpath build\work packaging\PhishGuard.spec
ISCC.exe packaging\PhishGuard.iss
```
