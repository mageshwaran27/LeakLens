"""Local model registry: models/registry.json + DB mirror."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
REGISTRY = ROOT / "models" / "registry.json"


def load_registry() -> dict:
    if REGISTRY.exists():
        return json.loads(REGISTRY.read_text())
    return {"production": None, "models": []}


def save_registry(data: dict) -> None:
    REGISTRY.parent.mkdir(parents=True, exist_ok=True)
    REGISTRY.write_text(json.dumps(data, indent=2))


def register_model(entry: dict, make_production: bool = False) -> dict:
    data = load_registry()
    data["models"] = [m for m in data["models"] if m.get("name") != entry.get("name")]
    data["models"].append(entry)
    if make_production or not data.get("production"):
        data["production"] = entry["name"]
    save_registry(data)
    return data
