"""Detection unit tests: positives fire, high-entropy benign strings do not auto-flag, masking holds."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.app.core.redaction import mask_value, redact_text  # noqa: E402
from backend.app.detection.entropy import shannon_entropy  # noqa: E402
from backend.app.detection.registry import scan_line  # noqa: E402


def test_aws_positive():
    hits = scan_line('key = "AKIAIOSFODNN7EXAMPLE"')
    assert any(d.id == "AWS_ACCESS_KEY" for d, _, _ in hits)


def test_github_positive():
    hits = scan_line('token = "ghp_EXAMPLE0123456789abcdefghij0000000000"')
    assert any(d.id == "GITHUB_TOKEN" for d, _, _ in hits)


def test_private_key_positive():
    hits = scan_line("-----BEGIN RSA PRIVATE KEY-----")
    assert any(d.id == "PRIVATE_KEY" for d, _, _ in hits)


def test_benign_uuid_not_secret():
    assert scan_line('session = "a3f9c1e2b7d44f8a91c2"') == []


def test_benign_hash_not_secret():
    assert scan_line('sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"') == []


def test_entropy_signal_only():
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("AKIAIOSFODNN7EXAMPLE")


def test_masking():
    raw = "AKIAIOSFODNN7EXAMPLE"
    assert raw not in mask_value(raw)
    assert raw not in redact_text(f"key={raw}")
