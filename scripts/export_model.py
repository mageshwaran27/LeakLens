"""Export production model + metadata snapshot for redistribution check."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

import sys as _sys
_sys.path.insert(0, str(ROOT))  # see scripts/_bootstrap.py


def main() -> None:
    from backend.app.ml.registry import load_registry
    reg = load_registry()
    prod = next((m for m in reg.get("models", []) if m.get("name") == reg.get("production")), None)
    if not prod:
        raise SystemExit("No production model registered")
    src = ROOT / prod["path"]
    dest = ROOT / "models" / "registry" / "production_snapshot.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(prod, indent=2))
    print(f"Production model: {src} ({src.stat().st_size / 1024:.1f} KB); snapshot -> {dest}")
    print("Artifacts are locally-trained on synthetic data and safe to redistribute.")


if __name__ == "__main__":
    main()
