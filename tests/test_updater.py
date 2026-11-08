"""Automatic updates: the signature check, the update flow, the launcher's wait and the API.

GitHub is replaced by a fake that serves a made-up release, signed here with a throwaway test key
(a few lines of plain-Python Ed25519 signing below), so no test touches the network or runs an
installer.
"""
import base64
import hashlib
import json
import os
import time

import pytest

from phishguard import ed25519, updater
from phishguard.updater import UpdateError, Updater, check_manifest, settle

# --- a tiny Ed25519 signer, for tests only -----------------------------------------------------------


def _encode(pt) -> bytes:
    zi = pow(pt[2], ed25519.P - 2, ed25519.P)
    x, y = pt[0] * zi % ed25519.P, pt[1] * zi % ed25519.P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _keys(seed: bytes):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:], _encode(ed25519._mul(a, ed25519.BASE))


def sign(seed: bytes, msg: bytes) -> bytes:
    a, prefix, pub = _keys(seed)
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % ed25519.Q
    big_r = _encode(ed25519._mul(r, ed25519.BASE))
    k = int.from_bytes(hashlib.sha512(big_r + pub + msg).digest(), "little") % ed25519.Q
    return big_r + ((r + k * a) % ed25519.Q).to_bytes(32, "little")


SEED = b"phishguard-test-release-key-0001"
PUB = _keys(SEED)[2]
OTHER_SEED = b"someone-else-entirely-0000000002"


# --- Ed25519 ------------------------------------------------------------------------------------

RFC_PUB = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
RFC_SIG = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39"
                        "701cf9b46bd25bf5f0595bbe24655141438e7a100b")
RFC2_PUB = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
RFC2_SIG = bytes.fromhex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f36"
                         "13d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")


def test_rfc8032_vectors():
    assert ed25519.verify(RFC_PUB, b"", RFC_SIG)
    assert ed25519.verify(RFC2_PUB, b"\x72", RFC2_SIG)


def test_rfc_secret_gives_rfc_public_key():
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    assert _keys(seed)[2] == RFC_PUB
    assert sign(seed, b"") == RFC_SIG


@pytest.mark.parametrize("pub,msg,sig", [
    (RFC_PUB, b"x", RFC_SIG),                                   # other message
    (RFC2_PUB, b"", RFC_SIG),                                   # other key
    (RFC_PUB, b"", RFC_SIG[:63] + bytes([RFC_SIG[63] ^ 1])),     # one bit flipped
    (RFC_PUB, b"", RFC_SIG[:32] + (ed25519.Q + 1).to_bytes(32, "little")),  # s out of range
    (RFC_PUB, b"", RFC_SIG[:40]),                               # short
    (b"\xff" * 32, b"", RFC_SIG),                               # not a point
])
def test_bad_signatures_fail(pub, msg, sig):
    assert not ed25519.verify(pub, msg, sig)


def test_the_built_in_key_is_a_valid_point():
    assert ed25519._point(updater.PUBLIC_KEY) is not None


# --- the signed update description ------------------------------------------------------------------

def manifest(version="1.2.0", data=b"installer", **kw) -> bytes:
    m = {"version": version, "file": f"PhishGuard-Setup-{version}.exe", "sha256": hashlib.sha256(data).hexdigest(),
         "size": len(data)}
    m.update(kw)
    return json.dumps(m).encode()


def sig_of(raw: bytes, seed: bytes = SEED) -> bytes:
    return base64.b64encode(sign(seed, raw))


def test_good_manifest():
    raw = manifest()
    m = check_manifest(raw, sig_of(raw), "1.1.1", PUB)
    assert m["version"] == "1.2.0" and m["newer"] is True


def test_same_or_older_version_is_not_newer():
    for v in ("1.1.1", "1.0.9", "0.9.0"):
        raw = manifest(v)
        assert check_manifest(raw, sig_of(raw), "1.1.1", PUB)["newer"] is False


def test_version_compare_is_numeric():
    raw = manifest("1.10.0")
    assert check_manifest(raw, sig_of(raw), "1.9.3", PUB)["newer"] is True


@pytest.mark.parametrize("case", ["tampered", "other_key", "garbage_sig", "wrong_file", "bad_hash", "huge"])
def test_bad_manifests_are_refused(case):
    raw = manifest()
    sig = sig_of(raw)
    if case == "tampered":
        raw = raw.replace(b"1.2.0", b"1.2.1", 1)
    elif case == "other_key":
        sig = sig_of(raw, OTHER_SEED)
    elif case == "garbage_sig":
        sig = b"not base64!!"
    elif case == "wrong_file":
        raw = manifest(file="evil.exe")
        sig = sig_of(raw)
    elif case == "bad_hash":
        raw = manifest(sha256="abc")
        sig = sig_of(raw)
    elif case == "huge":
        raw = manifest(size=10 ** 10)
        sig = sig_of(raw)
    with pytest.raises(UpdateError):
        check_manifest(raw, sig, "1.1.1", PUB)


# --- the update flow -----------------------------------------------------------------------------

DL = f"https://github.com/{updater.REPO}/releases/download"


class FakeGitHub:
    def __init__(self, version="1.2.0", installer=b"MZ new PhishGuard installer", tag=None, served=None,
                 host=DL, seed=SEED):
        self.installer = installer
        raw = manifest(version, installer)
        self.files = {
            f"{host}/v{version}/update.json": raw,
            f"{host}/v{version}/update.json.sig": sig_of(raw, seed),
            f"{host}/v{version}/PhishGuard-Setup-{version}.exe": installer if served is None else served,
        }
        self.release = {"tag_name": tag or f"v{version}", "html_url": "https://github.com/x",
                        "assets": [{"name": u.rsplit("/", 1)[1], "browser_download_url": u} for u in self.files]}
        self.calls = []

    def json(self, url):
        self.calls.append(url)
        assert url == updater.LATEST
        return self.release

    def small(self, url):
        self.calls.append(url)
        return self.files[url]

    def download(self, url, dest, limit, progress=None):
        self.calls.append(url)
        data = self.files[url]
        if len(data) > limit:
            raise UpdateError("too big")
        dest.write_bytes(data)
        if progress:
            progress(len(data))


def make(tmp_path, gh=None, mode="auto", busy=False, current="1.1.1"):
    launched = []
    u = Updater(tmp_path, settings=lambda: {"update_mode": mode}, busy=lambda: busy, current=current,
                http=gh or FakeGitHub(), launch=lambda exe, logf: launched.append(exe), public_key=PUB,
                supported=True)
    return u, launched


def test_newer_release_is_downloaded_verified_and_installed(tmp_path):
    u, launched = make(tmp_path)
    st = u.check()
    assert st["state"] == "installing" and st["latest"] == "1.2.0"
    exe = tmp_path / "updates" / "PhishGuard-Setup-1.2.0.exe"
    assert launched == [exe] and exe.read_bytes() == b"MZ new PhishGuard installer"
    lock = json.loads((tmp_path / updater.LOCK).read_text())
    assert lock["version"] == "1.2.0" and lock["from"] == "1.1.1"


def test_waits_while_a_link_is_being_checked(tmp_path):
    u, launched = make(tmp_path, busy=True)
    assert u.check()["state"] == "ready"
    assert launched == [] and not (tmp_path / updater.LOCK).exists()


def test_ask_mode_downloads_but_does_not_install(tmp_path):
    u, launched = make(tmp_path, mode="ask")
    assert u.check()["state"] == "ready" and launched == []
    assert u.install() is True and len(launched) == 1


def test_up_to_date(tmp_path):
    gh = FakeGitHub(version="1.1.1")
    u, launched = make(tmp_path, gh)
    assert u.check()["state"] == "up_to_date"
    assert launched == [] and not any("Setup" in c for c in gh.calls)


def test_downgrade_is_never_installed(tmp_path):
    u, launched = make(tmp_path, FakeGitHub(version="1.0.0"))
    assert u.check()["state"] == "up_to_date" and launched == []


def test_tampered_installer_is_deleted_and_never_run(tmp_path):
    u, launched = make(tmp_path, FakeGitHub(served=b"MZ malware with the same size!"[:27]))
    st = u.check()
    assert st["state"] == "error" and "fingerprint" in st["error"]
    assert launched == [] and not list((tmp_path / "updates").glob("*.exe*"))


def test_release_signed_with_another_key_is_refused(tmp_path):
    u, launched = make(tmp_path, FakeGitHub(seed=OTHER_SEED))
    st = u.check()
    assert st["state"] == "error" and "not signed" in st["error"] and launched == []


def test_files_hosted_elsewhere_are_refused(tmp_path):
    u, launched = make(tmp_path, FakeGitHub(host="https://evil.example/releases/download"))
    assert u.check()["state"] == "error" and launched == []


def test_tag_and_manifest_must_agree(tmp_path):
    u, launched = make(tmp_path, FakeGitHub(tag="v9.9.9"))
    assert u.check()["state"] == "error" and launched == []


def test_installer_changed_on_disk_before_install_is_not_run(tmp_path):
    u, launched = make(tmp_path, mode="ask")
    u.check()
    (tmp_path / "updates" / "PhishGuard-Setup-1.2.0.exe").write_bytes(b"swapped by malware")
    assert u.install() is False and launched == []
    assert u.status()["state"] == "error"


def test_no_release_yet(tmp_path):
    gh = FakeGitHub()
    gh.json = lambda url: None
    u, _ = make(tmp_path, gh)
    assert u.check()["state"] == "up_to_date"


def test_network_failure_is_reported_not_raised(tmp_path):
    gh = FakeGitHub()

    def boom(url):
        raise OSError("no network")
    gh.json = boom
    u, _ = make(tmp_path, gh)
    st = u.check()
    assert st["state"] == "error" and "GitHub" in st["error"]


def test_source_copies_never_update(tmp_path):
    gh = FakeGitHub()
    u = Updater(tmp_path, settings=dict, busy=lambda: False, http=gh, launch=None, supported=False)
    assert u.check()["state"] == "unsupported" and gh.calls == []


def test_default_mode_is_auto_and_unknown_falls_back(tmp_path):
    u, _ = make(tmp_path, mode="")
    assert u.mode() == "auto"
    u.settings = lambda: {"update_mode": "sometimes"}
    assert u.mode() == "auto"


def test_settle_after_a_good_update(tmp_path):
    (tmp_path / updater.LOCK).write_text(json.dumps({"version": "1.2.0", "from": "1.1.1"}))
    assert settle(tmp_path, "1.2.0") == "PhishGuard was updated to 1.2.0."
    assert not (tmp_path / updater.LOCK).exists()
    assert json.loads((tmp_path / updater.RESULT).read_text())["ok"] is True
    assert settle(tmp_path, "1.2.0") is None           # only once


def test_settle_after_a_failed_update(tmp_path):
    (tmp_path / updater.LOCK).write_text(json.dumps({"version": "1.2.0", "from": "1.1.1"}))
    msg = settle(tmp_path, "1.1.1")
    assert "did not finish" in msg
    assert json.loads((tmp_path / updater.RESULT).read_text())["ok"] is False


# --- the launcher waits for the new engine during an update ---------------------------------------------

@pytest.fixture
def launcher(tmp_path, monkeypatch):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "launcher"))
    import pglaunch
    monkeypatch.setattr(pglaunch, "UPDATE_WAIT", 1.0)
    cfg = {"instance": tmp_path, "port": 1, "base": "http://127.0.0.1:1"}
    return pglaunch, cfg


def test_launcher_waits_for_the_new_engine_instead_of_starting_the_old_one(launcher, monkeypatch):
    pglaunch, cfg = launcher
    (cfg["instance"] / pglaunch.UPDATE_LOCK).write_text("{}")
    answers = iter([False, False, True])
    monkeypatch.setattr(pglaunch, "healthy", lambda cfg, timeout=0.5: next(answers))
    started = []
    monkeypatch.setattr(pglaunch, "start_server", lambda *a, **k: started.append(1))
    pglaunch.ensure_server(cfg)
    assert started == []


def test_launcher_starts_the_engine_if_the_update_never_finishes(launcher, monkeypatch):
    pglaunch, cfg = launcher
    (cfg["instance"] / pglaunch.UPDATE_LOCK).write_text("{}")
    state = {"up": False}
    monkeypatch.setattr(pglaunch, "healthy", lambda cfg, timeout=0.5: state["up"])
    monkeypatch.setattr(pglaunch, "start_server", lambda *a, **k: state.update(up=True))
    t = time.monotonic()
    pglaunch.ensure_server(cfg, timeout=2)
    assert state["up"] and time.monotonic() - t >= 0.9


def test_stale_lock_is_ignored(launcher):
    pglaunch, cfg = launcher
    lock = cfg["instance"] / pglaunch.UPDATE_LOCK
    lock.write_text("{}")
    old = time.time() - 3600
    os.utime(lock, (old, old))
    assert pglaunch.updating(cfg) is False


def test_after_update_start_does_not_wait(launcher, monkeypatch):
    pglaunch, cfg = launcher
    (cfg["instance"] / pglaunch.UPDATE_LOCK).write_text("{}")
    state = {"up": False}
    monkeypatch.setattr(pglaunch, "healthy", lambda cfg, timeout=0.5: state["up"])
    monkeypatch.setattr(pglaunch, "start_server", lambda *a, **k: state.update(up=True))
    t = time.monotonic()
    pglaunch.ensure_server(cfg, timeout=2, wait_update=False)
    assert state["up"] and time.monotonic() - t < 0.5


# --- the API ---------------------------------------------------------------------------------

@pytest.fixture
def api(tmp_path):
    from phishguard import create_app
    from phishguard.auth import create_user, limiter
    from phishguard.db import connect
    inst = tmp_path / "inst"
    u, launched = make(tmp_path / "upd", mode="ask")
    (tmp_path / "upd").mkdir()
    app = create_app({"INSTANCE_DIR": str(inst), "TESTING": True, "UPDATER": u})
    con = connect(app.config["DATABASE"])
    create_user(con, "admin", "correct-horse-1", "admin")
    create_user(con, "analyst", "battery-staple-2", "analyst")
    con.close()
    limiter.fails.clear()
    return app, u, launched


def client(app, user):
    c = app.test_client()
    tok = c.get("/api/csrf").get_json()["csrf"]
    pw = {"admin": "correct-horse-1", "analyst": "battery-staple-2"}[user]
    tok = c.post("/api/login", json={"username": user, "password": pw}, headers={"X-CSRF-Token": tok}).get_json()["csrf"]
    c.csrf = tok
    return c


def test_api_update_is_admin_only(api):
    app, _, _ = api
    assert client(app, "analyst").get("/api/update").status_code == 403
    st = client(app, "admin").get("/api/update").get_json()
    assert st["current"] and st["mode"] == "ask" and st["supported"] is True


def test_api_install_needs_a_downloaded_update(api):
    app, u, launched = api
    c = client(app, "admin")
    r = c.post("/api/update/install", headers={"X-CSRF-Token": c.csrf})
    assert r.status_code == 409 and launched == []
    u.check()
    r = c.post("/api/update/install", headers={"X-CSRF-Token": c.csrf})
    assert r.status_code == 200 and len(launched) == 1


def test_api_update_mode_setting_is_validated(api):
    app, _, _ = api
    c = client(app, "admin")
    h = {"X-CSRF-Token": c.csrf}
    assert c.post("/api/settings", json={"update_mode": "sometimes"}, headers=h).status_code == 400
    assert c.post("/api/settings", json={"update_mode": "off"}, headers=h).status_code == 200
    assert c.get("/api/settings").get_json()["update_mode"] == "off"
