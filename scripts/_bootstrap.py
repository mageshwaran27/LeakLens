"""Project-root bootstrap for standalone script execution.

When a script is run as `python scripts/<name>.py`, Python puts `scripts/`
on `sys.path`, not the project root, so `import backend...` fails. Importing
this module (or calling `ensure_root()`) inserts the project root:

    from _bootstrap import ensure_root; ensure_root()

Must run before any `backend.*` import. `python -m scripts.<name>` from the
project root works without it (root is already on the path).
"""
from pathlib import Path
import sys


def ensure_root() -> Path:
    root = Path(__file__).resolve().parents[1]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    return root


ensure_root()
