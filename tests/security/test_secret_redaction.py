"""Redaction regression: raw secrets never in DB/API/logs/reports."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.app.core.redaction import fingerprint, mask_value  # noqa: E402
from backend.app.reports.exporters import to_csv, to_html, to_json, to_sarif  # noqa: E402

RAW = "AKIAIOSFODNN7EXAMPLE"


def test_mask_and_fingerprint():
    assert RAW not in mask_value(RAW)
    assert len(fingerprint(RAW)) == 64


def test_exports_contain_no_raw():
    f = {"severity": "HIGH", "detector_id": "AWS_ACCESS_KEY", "detector_name": "AWS",
         "category": "AWS_CREDENTIAL", "file_path": "a.py", "line_number": 1, "column": 0,
         "confidence": 0.9, "masked_value": mask_value(RAW), "status": "OPEN"}
    for blob in [to_json("p", "s", {}, [f]), to_csv([f]),
                 str(to_sarif("p", [f])), to_html("p", "s", {}, [f])]:
        assert RAW not in blob


def test_log_redaction():
    from backend.app.core.redaction import redact_text
    assert RAW not in redact_text(f"found {RAW} here")
