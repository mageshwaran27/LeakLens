"""Sanitized report exporters: JSON / CSV / SARIF / HTML. Masked evidence only."""
from __future__ import annotations

import csv
import html
import io
import json
from datetime import datetime, timezone


def build_summary(findings: list[dict]) -> dict:
    sev: dict[str, int] = {}
    det: dict[str, int] = {}
    for f in findings:
        sev[f.get("severity", "?")] = sev.get(f.get("severity", "?"), 0) + 1
        det[f.get("detector_id", "?")] = det.get(f.get("detector_id", "?"), 0) + 1
    return {"severity": sev, "detectors": det}


def to_json(project: str, scan_id: str, stats: dict, findings: list[dict]) -> str:
    return json.dumps({"project": project, "scan_id": scan_id,
                       "generated_at": datetime.now(timezone.utc).isoformat(),
                       "stats": stats, "summary": build_summary(findings),
                       "findings": findings}, indent=2)


def _csv_safe(value) -> str:
    """Neutralize spreadsheet formula injection: cells starting with
    = + - @ or whitespace/control chars get a leading single quote."""
    s = "" if value is None else str(value)
    if s[:1] in ("=", "+", "-", "@", "\t", "\r", "\n"):
        return "'" + s
    return s


def to_csv(findings: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=["severity", "detector_id", "category", "file_path",
                                        "line_number", "confidence", "masked_value", "status"])
    w.writeheader()
    for f in findings:
        w.writerow({k: _csv_safe(f.get(k, "")) for k in w.fieldnames})
    return buf.getvalue()


def to_sarif(project: str, findings: list[dict]) -> dict:
    rules = {}
    for f in findings:
        rules[f["detector_id"]] = {"id": f["detector_id"],
                                   "name": f.get("detector_name", f["detector_id"]),
                                   "helpUri": "https://leaklens.local/docs/detectors"}
    results = []
    for f in findings:
        results.append({
            "ruleId": f["detector_id"],
            "level": {"HIGH": "error", "MEDIUM": "warning"}.get(f.get("severity"), "note"),
            "message": {"text": f"{f.get('detector_name')}: {f.get('masked_value')}"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.get("file_path")},
                "region": {"startLine": f.get("line_number", 1),
                           "startColumn": (f.get("column", 0) or 0) + 1}}}]})
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "LeakLens", "version": "1.0.0",
                                          "rules": list(rules.values())}},
                      "results": results}]}


def to_html(project: str, scan_id: str, stats: dict, findings: list[dict]) -> str:
    rows = "".join(
        f"<tr><td>{html.escape(str(f.get('severity','')))}</td>"
        f"<td>{html.escape(str(f.get('detector_name','')))}</td>"
        f"<td><code>{html.escape(str(f.get('file_path','')))}:{html.escape(str(f.get('line_number','')))}</code></td>"
        f"<td><code>{html.escape(str(f.get('masked_value','')))}</code></td>"
        f"<td>{html.escape(str(f.get('confidence','')))}</td></tr>" for f in findings)
    return (f"<!DOCTYPE html><html><head><meta charset='utf-8'><title>LeakLens report — {html.escape(project)}</title>"
            f"</head><body><h1>LeakLens Security Report — {html.escape(project)}</h1>"
            f"<p>Scan {html.escape(scan_id)} · {html.escape(str(stats))}</p>"
            f"<table border='1'><tr><th>Severity</th><th>Detector</th><th>Location</th>"
            f"<th>Masked value</th><th>Confidence</th></tr>{rows}</table>"
            f"<p>Values are masked. Raw secrets are never included.</p></body></html>")
