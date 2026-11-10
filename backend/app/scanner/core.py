"""Reusable file-discovery + line-scanning core used by API and CLI."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

SUPPORTED_EXTS = {".js", ".ts", ".jsx", ".tsx", ".py", ".java", ".go", ".rs", ".php", ".rb",
                  ".json", ".yaml", ".yml", ".xml", ".toml", ".ini", ".cfg", ".conf", ".env",
                  ".properties", ".sql", ".sh", ".bash", ".md", ".txt", ".env.example"}
SPECIAL_FILES = {"dockerfile", "makefile"}
DEFAULT_IGNORES = {".git", "node_modules", "venv", ".venv", "dist", "build", "target",
                   "coverage", "__pycache__", ".idea", ".vscode"}


@dataclass
class ScanConfig:
    root: str
    excludes: set[str] = field(default_factory=lambda: set(DEFAULT_IGNORES))
    max_file_bytes: int = 1_000_000
    max_scan_bytes: int = 500_000_000
    include_docs: bool = True
    include_tests: bool = True
    extra_exts: set[str] = field(default_factory=set)


def is_supported(path: Path, cfg: ScanConfig) -> bool:
    name = path.name.lower()
    if name in SPECIAL_FILES:
        return True
    if path.suffix.lower() in (SUPPORTED_EXTS | cfg.extra_exts):
        return True
    if name.startswith(".env"):
        return True
    if "dockerfile" in name or "terraform" in name or name.endswith((".tf", ".tfvars")):
        return True
    return False


def discover_files(cfg: ScanConfig) -> list[Path]:
    root = Path(cfg.root).resolve()
    out: list[Path] = []
    total_bytes = 0
    cap = cfg.max_scan_bytes or 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames
                       if d not in cfg.excludes and not Path(dirpath, d).is_symlink()]
        for fn in filenames:
            p = Path(dirpath) / fn
            try:
                if p.is_symlink():
                    continue
                size = p.stat().st_size
                if size > cfg.max_file_bytes:
                    continue
                if cap and total_bytes + size > cap:
                    continue
            except OSError:
                continue
            if not is_supported(p, cfg):
                continue
            lp = p.as_posix().lower()
            if not cfg.include_docs and ("/docs/" in lp or "/doc/" in lp or p.suffix.lower() in {".md", ".ipynb"}):
                continue
            if not cfg.include_tests and any(t in lp for t in ["/test", "/tests", "spec", "fixture", "mock"]):
                continue
            total_bytes += size
            out.append(p)
    return sorted(out)


def read_lines_safe(path: Path, limit_bytes: int):
    """Yield (lineno, line) streaming; skips binaries."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(8192)
            if b"\x00" in head:
                return
    except OSError:
        return
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh, 1):
                yield i, line.rstrip("\n")[:4000]
    except OSError:
        return
