"""Context/risk: placeholders suppressed, production boosted, evidence present."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.app.context.risk import classify, extract_context  # noqa: E402


def test_placeholder_reduces_confidence():
    ctx_prod = extract_context("config/production.yaml", "password", 'password = "SynthPass1234!!"', [])
    ctx_doc = extract_context("docs/setup.md", "api_key", 'api_key = "YOUR_API_KEY_HERE"', [])
    s1, c1, _, _ = classify(0.7, 4.6, 16, ctx_prod, True, 0.8)
    s2, c2, t2, _ = classify(0.7, 4.6, 16, ctx_doc, True, 0.8)
    assert c1 > c2
    assert t2 in ("PLACEHOLDER", "DOCUMENTATION_EXAMPLE", "EXAMPLE_SECRET")


def test_evidence_nonempty():
    ctx = extract_context("src/app.py", "token", "x", [])
    _, _, _, ev = classify(0.8, 4.8, 24, ctx, True, 0.9)
    assert len(ev) >= 1
