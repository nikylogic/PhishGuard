"""Remove everything register_windows.py wrote.

    python scripts/unregister_windows.py

Windows then hands links back to your previous default browser (it may ask you to pick one).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "launcher"))

import registry  # noqa: E402

if __name__ == "__main__":
    removed = registry.unregister()
    if registry.remove_shortcut():
        removed.append(str(registry.shortcut_path()))
    print("\n".join(f"removed {r}" for r in removed) or "Nothing to remove.")
