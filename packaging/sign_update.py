"""Write and sign update.json for a release (run by .github/workflows/release.yml).

    python packaging/sign_update.py build/installer/PhishGuard-Setup-1.2.0.exe

The private key comes from the UPDATE_SIGNING_KEY environment variable (a PEM file's text, kept as a
GitHub secret). The installed app checks the signature with the public key in phishguard/updater.py
before it downloads or runs anything (see that file).
"""
import base64
import hashlib
import json
import os
import re
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from phishguard.ed25519 import verify  # noqa: E402
from phishguard.updater import PUBLIC_KEY  # noqa: E402


def main(installer: str) -> None:
    path = Path(installer)
    m = re.fullmatch(r"PhishGuard-Setup-(\d+\.\d+\.\d+)\.exe", path.name)
    if not m:
        sys.exit(f"unexpected installer name: {path.name}")
    key = serialization.load_pem_private_key(os.environ["UPDATE_SIGNING_KEY"].encode(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        sys.exit("UPDATE_SIGNING_KEY is not an Ed25519 key")
    data = path.read_bytes()
    manifest = json.dumps({"version": m.group(1), "file": path.name, "sha256": hashlib.sha256(data).hexdigest(),
                           "size": len(data)}, indent=2).encode() + b"\n"
    sig = key.sign(manifest)
    if not verify(PUBLIC_KEY, manifest, sig):
        sys.exit("UPDATE_SIGNING_KEY does not match PUBLIC_KEY in phishguard/updater.py")
    (path.parent / "update.json").write_bytes(manifest)
    (path.parent / "update.json.sig").write_text(base64.b64encode(sig).decode() + "\n")
    print(manifest.decode())


if __name__ == "__main__":
    main(sys.argv[1])
