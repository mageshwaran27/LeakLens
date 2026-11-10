"""Benchmark: scanner throughput + detection quality on a target repo/fixture."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.app.scanner.core import ScanConfig  # noqa: E402
from backend.app.scanner.pipeline import scan_path  # noqa: E402


def dir_size_mb(path: str) -> float:
    total = 0
    for p in Path(path).rglob("*"):
        try:
            if p.is_file():
                total += p.stat().st_size
        except OSError:
            pass
    return total / 1e6


def main(target: str = ".") -> dict:
    t0 = time.time()
    res = scan_path(target, ScanConfig(root=target))
    dt = time.time() - t0
    mb = dir_size_mb(target)
    out = {"target": target, "files_scanned": res["files_scanned"],
           "findings": len(res["findings"]), "duration_s": round(dt, 2),
           "files_per_sec": round(res["files_scanned"] / max(dt, 1e-6), 1),
           "mb_per_sec": round(mb / max(dt, 1e-6), 2),
           "by_severity": {}, "by_detector": {}}
    for f in res["findings"]:
        out["by_severity"][f["severity"]] = out["by_severity"].get(f["severity"], 0) + 1
        out["by_detector"][f["detector_id"]] = out["by_detector"].get(f["detector_id"], 0) + 1
    dest = ROOT / "reports" / "benchmark" / "latest.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, indent=2))
    (ROOT / "reports" / "benchmark_results.json").write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))
    return out


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
