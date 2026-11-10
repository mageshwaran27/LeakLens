"""Full pipeline: file -> candidates -> pattern -> entropy -> context -> risk -> finding dict."""
from __future__ import annotations

import time
from pathlib import Path

from backend.app.context.risk import RECOMMENDATIONS, classify, extract_context, guess_variable
from backend.app.core.redaction import fingerprint, mask_line, mask_value
from backend.app.detection.entropy import charset_score, shannon_entropy
from backend.app.detection.registry import REGISTRY_VERSION, scan_line, validate
from backend.app.scanner.core import ScanConfig, discover_files, read_lines_safe

ENGINE_VERSION = f"detection-{REGISTRY_VERSION}"


def scan_path(root: str, cfg: ScanConfig | None = None, use_ml=None,
              progress_cb=None, cancel_flag=None) -> dict:
    t0 = time.time()
    cfg = cfg or ScanConfig(root=root)
    files = discover_files(cfg)
    findings: list[dict] = []
    candidates = 0
    scanned = 0
    for idx, path in enumerate(files):
        if cancel_flag is not None and cancel_flag():
            return {"status": "CANCELLED", "files_discovered": len(files),
                    "files_scanned": scanned, "candidates": candidates,
                    "findings": findings, "duration_ms": int((time.time() - t0) * 1000)}
        rel = Path(path).resolve().as_posix()
        try:
            rel = str(Path(path).resolve().relative_to(Path(cfg.root).resolve())).replace("\\", "/")
        except ValueError:
            pass
        lines = list(read_lines_safe(path, cfg.max_file_bytes))
        scanned += 1
        for lineno, line in enumerate([l for _, l in lines], 1):
            for det, raw, col in scan_line(line):
                candidates += 1
                ent = shannon_entropy(raw)
                cs = charset_score(raw)
                var = guess_variable(line)
                near = [l for _, l in lines[max(0, lineno - 4):lineno + 2]]
                ctx = extract_context(rel, var, line, near)
                sev, conf, ctype, ev = classify(det.confidence, ent, len(raw), ctx,
                                                validate(det.id, raw), cs)
                ml_prob = None
                if use_ml is not None:
                    try:
                        ml_prob = float(use_ml(line, rel, var, ent))
                        try:
                            from backend.app.ml.inference.predict import blend
                            conf = blend(conf, ml_prob)
                        except Exception:
                            conf = round(max(0.0, min(0.99, 0.6 * conf + 0.4 * ml_prob)), 2)
                        ev = [*ev, f"ML context probability {ml_prob:.2f}"]
                    except Exception:
                        pass
                ev = [f"Matches {det.name} pattern", *ev]
                findings.append({
                    "detector_id": det.id,
                    "detector_name": det.name,
                    "category": det.category,
                    "context_type": ctype,
                    "severity": det.severity if det.severity == "HIGH" and conf >= 0.6 else sev,
                    "confidence": conf,
                    "rule_confidence": det.confidence,
                    "ml_probability": ml_prob,
                    "file_path": rel,
                    "line_number": lineno,
                    "column": col,
                    "masked_value": mask_value(raw),
                    "masked_line": mask_line(line, [raw]),
                    "fingerprint": fingerprint(f"{det.id}|{rel}|{raw}"),
                    "evidence": ev,
                    "context": ctx,
                    "recommendation": RECOMMENDATIONS.get(det.category,
                        "Remove the value from source, rotate it, and use a secrets manager."),
                    "engine_version": ENGINE_VERSION,
                })
        if progress_cb:
            progress_cb(idx + 1, len(files), candidates, len(findings))
    # de-dup by fingerprint
    seen, uniq = set(), []
    for f in findings:
        if f["fingerprint"] not in seen:
            seen.add(f["fingerprint"])
            uniq.append(f)
    return {"status": "COMPLETED", "files_discovered": len(files), "files_scanned": scanned,
            "candidates": candidates, "findings": uniq,
            "duration_ms": int((time.time() - t0) * 1000)}
