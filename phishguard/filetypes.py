"""Identify a quarantined file by its contents (magic bytes), never by running it."""
import hashlib
import zipfile
from pathlib import Path

EXECUTABLE_EXT = {"exe", "scr", "msi", "msix", "appx", "appinstaller", "bat", "cmd", "com", "ps1",
                  "vbs", "vbe", "js", "jse", "wsf", "hta", "lnk", "pif", "cpl", "jar", "apk", "dll",
                  "reg", "url", "scf", "iso", "img", "vhd", "vhdx"}
DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif", "mp4"}

SCRIPT_MARKERS = (b"powershell", b"cmd.exe", b"mshta", b"wscript", b"cscript", b"@echo off",
                  b"invoke-expression", b"iex(", b"start-process", b"createobject(")


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _zip_kind(path: Path) -> tuple[str, list[str]]:
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()[:500]
    except (zipfile.BadZipFile, OSError, ValueError):
        return "zip", []
    low = [n.lower() for n in names]
    if "androidmanifest.xml" in low:
        return "apk", []
    if "[content_types].xml" in low:
        return "office", []
    inner = [n for n in names if n.rsplit(".", 1)[-1].lower() in EXECUTABLE_EXT]
    return "zip", inner


def identify(path: Path) -> dict:
    """Return {'real_type', 'executable', 'inner_executables'} from the first bytes."""
    with open(path, "rb") as fh:
        head = fh.read(4096)
        iso = b""
        try:
            fh.seek(0x8001)
            iso = fh.read(5)
        except OSError:
            pass
    lower = head.lower()
    inner: list[str] = []
    if head[:2] == b"MZ":
        kind, exe = "windows-program", True
    elif head[:4] == b"\x7fELF":
        kind, exe = "linux-program", True
    elif head[:4] == b"L\x00\x00\x00" and head[4:8] == b"\x01\x14\x02\x00":
        kind, exe = "windows-shortcut", True
    elif head[:4] == b"PK\x03\x04":
        kind, inner = _zip_kind(path)
        exe = kind == "apk" or bool(inner)
    elif iso == b"CD001":
        kind, exe = "disk-image", True
    elif head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        kind, exe = "msi-or-old-office", True
    elif head[:5] == b"%PDF-":
        kind, exe = "pdf", False
    elif head[:3] == b"\xff\xd8\xff" or head[:8] == b"\x89PNG\r\n\x1a\n" or head[:4] == b"GIF8":
        kind, exe = "image", False
    elif b"<hta:application" in lower:
        kind, exe = "hta-application", True
    elif any(m in lower for m in SCRIPT_MARKERS):
        kind, exe = "script", True
    elif lower.lstrip().startswith((b"<!doctype html", b"<html")):
        kind, exe = "html", False
    else:
        kind, exe = "unknown", False
    return {"real_type": kind, "executable": exe, "inner_executables": inner[:10]}


def extension_of(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def has_double_extension(name: str) -> bool:
    """invoice.pdf.exe: a harmless-looking extension followed by a dangerous one."""
    parts = name.lower().split(".")
    return len(parts) >= 3 and parts[-2] in DOC_EXT and parts[-1] in EXECUTABLE_EXT
