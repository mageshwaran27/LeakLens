"""Hard negatives / placeholders / robustness: must not crash, must stay explainable."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.app.scanner.pipeline import scan_path  # noqa: E402
from backend.app.scanner.core import ScanConfig  # noqa: E402


def test_format_variants(tmp_path):
    variants = ['API_KEY = "AK_EXAMPLE_SYNTHETIC_001122334455"', 'API_KEY="AK_EXAMPLE_SYNTHETIC_001122334455"',
                'apiKey: "AK_EXAMPLE_SYNTHETIC_001122334455"', 'export API_KEY="AK_EXAMPLE_SYNTHETIC_001122334455"',
                '{"api_key": "AK_EXAMPLE_SYNTHETIC_001122334455"}', 'api_key: AK_EXAMPLE_SYNTHETIC_001122334455']
    (tmp_path / "a.py").write_text("\n".join(variants))
    res = scan_path(str(tmp_path), ScanConfig(root=str(tmp_path)))
    assert res["status"] == "COMPLETED"
    assert len(res["findings"]) >= 2


def test_hard_negatives_low_or_absent(tmp_path):
    neg = ['api_key = "YOUR_API_KEY_HERE"', 'x = "a3f9c1e2b7d44f8a91c2"',
           'v = "2.4.1"', '# example placeholder, do not use']
    (tmp_path / "n.py").write_text("\n".join(neg))
    res = scan_path(str(tmp_path), ScanConfig(root=str(tmp_path)))
    highs = [f for f in res["findings"] if f["severity"] == "HIGH" and f["confidence"] > 0.8]
    assert highs == []
