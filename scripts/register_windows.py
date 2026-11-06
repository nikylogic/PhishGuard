"""Make PhishGuard available as a web-link handler for the current Windows user.

    python scripts/register_windows.py

Then open Settings > Apps > Default apps > PhishGuard and set it for HTTP and HTTPS.
Undo with: python scripts/unregister_windows.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "launcher"))

import registry  # noqa: E402

if __name__ == "__main__":
    registry.register()
    print("\n".join(registry.dump()))
    print("\nPhishGuard is registered. Now open Settings > Apps > Default apps > PhishGuard\n"
          "and choose it for HTTP and HTTPS.")
