"""Make PhishGuard available as a web-link handler for the current Windows user.

    python scripts/register_windows.py

It also adds a "PhishGuard" Start menu shortcut that opens the dashboard. Then open
Settings > Apps > Default apps > PhishGuard and press "Set default". (The "Make PhishGuard my
default browser" button in PhishGuard's own Settings does all of this for you.)
Undo with: python scripts/unregister_windows.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "launcher"))

import registry  # noqa: E402

if __name__ == "__main__":
    registry.register()
    print("\n".join(registry.dump()))
    print(f"\nStart menu shortcut: {registry.make_shortcut()}")
    print("\nPhishGuard is registered. Now open Settings > Apps > Default apps > PhishGuard\n"
          "and press \"Set default\".")
