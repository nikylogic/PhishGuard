"""PhishGuard's icon in the Windows notification area (the system tray).

The engine (PhishGuardEngine.exe) runs in the background for as long as PhishGuard is on. The icon
shows that it is running and gives the usual Windows-app controls:

    left click              open PhishGuard (or bring its window to the front)
    right click             Open PhishGuard · Check the link I copied · Start with Windows · Quit PhishGuard

Written on Windows' own API (Shell_NotifyIcon) with ctypes, so it needs no extra packages. It runs
on its own thread with its own hidden window and message loop; the engine's web server keeps the
main thread. Only the standard library is used, so PhishGuard.exe can import focus_window() too.
"""
from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import threading
from ctypes import wintypes
from pathlib import Path
from urllib.parse import urlsplit

TITLE = "PhishGuard"                    # the dashboard window's title (pglaunch.open_window)
WM_TRAY = 0x8000 + 1                    # WM_APP + 1: what the icon sends to our window
WM_DESTROY, WM_CLOSE, WM_COMMAND, WM_NULL = 0x0002, 0x0010, 0x0111, 0x0000
WM_LBUTTONUP, WM_RBUTTONUP, WM_CONTEXTMENU = 0x0202, 0x0205, 0x007B
NIM_ADD, NIM_MODIFY, NIM_DELETE = 0, 1, 2
NIF_MESSAGE, NIF_ICON, NIF_TIP, NIF_INFO = 0x1, 0x2, 0x4, 0x10
NIIF_INFO, NIIF_WARNING = 0x1, 0x2
MF_STRING, MF_SEPARATOR, MF_CHECKED, MF_GRAYED = 0x0, 0x800, 0x8, 0x1
TPM_RIGHTBUTTON, TPM_RETURNCMD, TPM_NONOTIFY, TPM_BOTTOMALIGN = 0x2, 0x100, 0x80, 0x20
SW_RESTORE, SW_SHOW = 9, 5
CF_UNICODETEXT = 13
LR_LOADFROMFILE, LR_DEFAULTSIZE, IMAGE_ICON = 0x10, 0x40, 1

OPEN, CHECK_COPIED, STARTUP, QUIT = 1, 2, 3, 4

if os.name == "nt":
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    LRESULT = ctypes.c_ssize_t
    WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)

    class WNDCLASSEXW(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.UINT), ("style", wintypes.UINT), ("lpfnWndProc", WNDPROC),
                    ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int), ("hInstance", wintypes.HINSTANCE),
                    ("hIcon", wintypes.HICON), ("hCursor", wintypes.HANDLE), ("hbrBackground", wintypes.HBRUSH),
                    ("lpszMenuName", wintypes.LPCWSTR), ("lpszClassName", wintypes.LPCWSTR),
                    ("hIconSm", wintypes.HICON)]

    class NOTIFYICONDATAW(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("hWnd", wintypes.HWND), ("uID", wintypes.UINT),
                    ("uFlags", wintypes.UINT), ("uCallbackMessage", wintypes.UINT), ("hIcon", wintypes.HICON),
                    ("szTip", wintypes.WCHAR * 128), ("dwState", wintypes.DWORD), ("dwStateMask", wintypes.DWORD),
                    ("szInfo", wintypes.WCHAR * 256), ("uVersion", wintypes.UINT),
                    ("szInfoTitle", wintypes.WCHAR * 64), ("dwInfoFlags", wintypes.DWORD),
                    ("guidItem", ctypes.c_byte * 16), ("hBalloonIcon", wintypes.HICON)]

    user32.DefWindowProcW.restype = LRESULT
    user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    user32.RegisterClassExW.argtypes = [ctypes.POINTER(WNDCLASSEXW)]
    user32.RegisterClassExW.restype = wintypes.ATOM
    user32.CreateWindowExW.restype = wintypes.HWND
    user32.CreateWindowExW.argtypes = [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
                                       ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.HWND,
                                       wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID]
    user32.FindWindowW.restype = wintypes.HWND
    user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
    user32.CreatePopupMenu.restype = wintypes.HMENU
    user32.AppendMenuW.argtypes = [wintypes.HMENU, wintypes.UINT, ctypes.c_size_t, wintypes.LPCWSTR]
    user32.TrackPopupMenu.argtypes = [wintypes.HMENU, wintypes.UINT, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                      wintypes.HWND, wintypes.LPVOID]
    user32.TrackPopupMenu.restype = wintypes.BOOL
    user32.SetMenuDefaultItem.argtypes = [wintypes.HMENU, wintypes.UINT, wintypes.UINT]
    user32.DestroyMenu.argtypes = [wintypes.HMENU]
    user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    user32.GetClipboardData.restype = wintypes.HANDLE
    user32.LoadImageW.restype = wintypes.HANDLE
    user32.LoadImageW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR, wintypes.UINT, ctypes.c_int, ctypes.c_int,
                                  wintypes.UINT]
    user32.IsIconic.argtypes = [wintypes.HWND]
    user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    user32.SetForegroundWindow.argtypes = [wintypes.HWND]
    user32.DestroyWindow.argtypes = [wintypes.HWND]
    user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
    kernel32.GetModuleHandleW.restype = wintypes.HMODULE
    kernel32.GlobalLock.restype = wintypes.LPVOID
    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    shell32.Shell_NotifyIconW.argtypes = [wintypes.DWORD, ctypes.POINTER(NOTIFYICONDATAW)]
    shell32.Shell_NotifyIconW.restype = wintypes.BOOL
    shell32.ExtractIconExW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, ctypes.POINTER(wintypes.HICON),
                                       ctypes.POINTER(wintypes.HICON), wintypes.UINT]


# --- small helpers (also used by PhishGuard.exe) ------------------------------------------------

def focus_window(title: str = TITLE) -> bool:
    """Bring PhishGuard's open dashboard window to the front. True if there was one."""
    if os.name != "nt":
        return False
    hwnd = user32.FindWindowW(None, title)
    if not hwnd:
        return False
    if user32.IsIconic(hwnd):
        user32.ShowWindow(hwnd, SW_RESTORE)
    else:
        user32.ShowWindow(hwnd, SW_SHOW)
    user32.SetForegroundWindow(hwnd)
    return True


def link_in(text: str | None) -> str | None:
    """The web link in copied text, if the text is one. Anything else is left alone."""
    t = (text or "").strip().strip('"<>')
    if not t or len(t) > 4096 or any(c.isspace() for c in t):
        return None
    if t.lower().startswith("www."):
        t = "https://" + t
    try:
        p = urlsplit(t)
    except ValueError:
        return None
    return t if p.scheme in ("http", "https") and p.hostname else None


def clipboard_text() -> str | None:
    if os.name != "nt" or not user32.OpenClipboard(None):
        return None
    try:
        h = user32.GetClipboardData(CF_UNICODETEXT)
        if not h:
            return None
        p = kernel32.GlobalLock(h)
        try:
            return ctypes.wstring_at(p) if p else None
        finally:
            kernel32.GlobalUnlock(h)
    finally:
        user32.CloseClipboard()


def _app_exe() -> list[str]:
    """How to start PhishGuard.exe (the window side) from the engine."""
    here = Path(sys.executable)
    if getattr(sys, "frozen", False):
        return [str(here.with_name("PhishGuard.exe"))]
    pyw = here.with_name("pythonw.exe")
    return [str(pyw if pyw.exists() else here), str(Path(__file__).with_name("pg_open.pyw"))]


# --- the tray icon -----------------------------------------------------------------------------

class Tray:
    """The notification-area icon. start() returns once the icon is shown (or failed)."""

    def __init__(self, instance: Path, on_quit=None, popen=subprocess.Popen, registry=None, hint: bool = True):
        self.instance = Path(instance)
        self.on_quit = on_quit or self._quit_engine
        self.popen = popen
        self.registry = registry
        self.hint = hint
        self.hwnd = None
        self.shown = threading.Event()
        self.ok = False
        self._proc = None                       # keep the callback alive as long as the window
        self._taskbar_created = 0

    # actions ---------------------------------------------------------------------------------
    def open_app(self) -> None:
        if not focus_window():
            self.popen(_app_exe(), close_fds=True)

    def check_copied(self) -> None:
        url = link_in(clipboard_text())
        if not url:
            self.notify("Copy a link first", "Copy a link (for example from a message), then choose "
                        "“Check the link I copied” again.", warning=True)
            return
        self.popen([*_app_exe(), url], close_fds=True)

    def toggle_startup(self) -> None:
        if self.registry is not None:
            self.registry.set_startup(not self.registry.startup_enabled())

    def _quit_engine(self) -> None:
        """Stop the engine and everything it started (sandbox browser, Tor), like PhishGuard.exe --stop."""
        (self.instance / "server.pid").unlink(missing_ok=True)
        subprocess.run(["taskkill", "/PID", str(os.getpid()), "/T", "/F"], capture_output=True,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        os._exit(0)

    # the icon --------------------------------------------------------------------------------
    def _icon(self):
        small = wintypes.HICON()
        if getattr(sys, "frozen", False) and shell32.ExtractIconExW(sys.executable, 0, None, ctypes.byref(small), 1):
            return small
        ico = Path(__file__).resolve().parent.parent / "packaging" / "phishguard.ico"
        return user32.LoadImageW(None, str(ico), IMAGE_ICON, 0, 0, LR_LOADFROMFILE | LR_DEFAULTSIZE)

    def _data(self, flags: int) -> "NOTIFYICONDATAW":
        d = NOTIFYICONDATAW()
        d.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        d.hWnd = self.hwnd
        d.uID = 1
        d.uFlags = flags
        return d

    def _add(self) -> bool:
        d = self._data(NIF_MESSAGE | NIF_ICON | NIF_TIP)
        d.uCallbackMessage = WM_TRAY
        d.hIcon = self._hicon
        d.szTip = "PhishGuard: checking the links you click"
        return bool(shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(d)))

    def notify(self, title: str, text: str, warning: bool = False) -> None:
        """A Windows notification from the tray icon."""
        if not self.hwnd:
            return
        d = self._data(NIF_INFO)
        d.szInfoTitle = title[:63]
        d.szInfo = text[:255]
        d.dwInfoFlags = NIIF_WARNING if warning else NIIF_INFO
        shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(d))

    def _menu(self) -> None:
        m = user32.CreatePopupMenu()
        user32.AppendMenuW(m, MF_STRING, OPEN, "Open PhishGuard")
        user32.AppendMenuW(m, MF_STRING, CHECK_COPIED, "Check the link I copied")
        user32.AppendMenuW(m, MF_SEPARATOR, 0, None)
        if self.registry is not None:
            on = self.registry.startup_enabled()
            user32.AppendMenuW(m, MF_STRING | (MF_CHECKED if on else 0), STARTUP, "Start with Windows")
            user32.AppendMenuW(m, MF_SEPARATOR, 0, None)
        user32.AppendMenuW(m, MF_STRING, QUIT, "Quit PhishGuard")
        user32.SetMenuDefaultItem(m, OPEN, 0)
        pt = wintypes.POINT()
        user32.GetCursorPos(ctypes.byref(pt))
        user32.SetForegroundWindow(self.hwnd)        # so the menu closes when you click elsewhere
        cmd = user32.TrackPopupMenu(m, TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY | TPM_BOTTOMALIGN,
                                    pt.x, pt.y, 0, self.hwnd, None)
        user32.PostMessageW(self.hwnd, WM_NULL, 0, 0)
        user32.DestroyMenu(m)
        self.command(cmd)

    def command(self, cmd: int) -> None:
        if cmd == OPEN:
            self.open_app()
        elif cmd == CHECK_COPIED:
            self.check_copied()
        elif cmd == STARTUP:
            self.toggle_startup()
        elif cmd == QUIT:
            self.remove()
            self.on_quit()

    def _wndproc(self, hwnd, msg, wparam, lparam):
        try:
            if msg == WM_TRAY:
                event = lparam & 0xFFFF
                if event == WM_LBUTTONUP:
                    self.open_app()
                elif event in (WM_RBUTTONUP, WM_CONTEXTMENU):
                    self._menu()
                return 0
            if msg == self._taskbar_created and msg:      # Explorer restarted: put the icon back
                self._add()
                return 0
            if msg == WM_CLOSE:
                user32.DestroyWindow(hwnd)
                return 0
            if msg == WM_DESTROY:
                user32.PostQuitMessage(0)
                return 0
        except Exception:  # noqa: BLE001 - never let a click crash the engine
            pass
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def _run(self) -> None:
        try:
            hinst = kernel32.GetModuleHandleW(None)
            self._proc = WNDPROC(self._wndproc)
            cls = WNDCLASSEXW(cbSize=ctypes.sizeof(WNDCLASSEXW), lpfnWndProc=self._proc, hInstance=hinst,
                              lpszClassName=f"PhishGuardTray{os.getpid()}")
            user32.RegisterClassExW(ctypes.byref(cls))
            self._taskbar_created = user32.RegisterWindowMessageW("TaskbarCreated")
            self.hwnd = user32.CreateWindowExW(0, cls.lpszClassName, "PhishGuard tray", 0, 0, 0, 0, 0,
                                               None, None, hinst, None)
            self._hicon = self._icon()
            self.ok = bool(self.hwnd) and self._add()
        finally:
            self.shown.set()
        if not self.ok:
            return
        if self.hint:
            self._first_hint()
        msg = wintypes.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

    def _first_hint(self) -> None:
        """Once, the first time: say where PhishGuard went, so nobody thinks it is not running."""
        mark = self.instance / "tray-hint.shown"
        if mark.exists():
            return
        self.notify("PhishGuard is running", "It checks the links you click. Find it here, next to the clock "
                    "(under ^ if hidden). Right-click for options.")
        try:
            mark.write_text("shown\n", encoding="utf-8")
        except OSError:
            pass

    def start(self) -> "Tray":
        if os.name == "nt":
            threading.Thread(target=self._run, name="pg-tray", daemon=True).start()
            self.shown.wait(10)
        return self

    def remove(self) -> None:
        if self.hwnd:
            shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(self._data(0)))

    def stop(self) -> None:
        self.remove()
        if self.hwnd:
            user32.PostMessageW(self.hwnd, WM_CLOSE, 0, 0)
