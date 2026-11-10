"""Scanner core: fixture discovery, ignore rules, symlink/huge-file safety."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.app.scanner.core import ScanConfig, discover_files  # noqa: E402
from backend.app.scanner.pipeline import scan_path  # noqa: E402

FIX = str(Path(__file__).resolve().parents[2] / "test-fixtures" / "vulnerable-project")


def test_discovers_fixture_files():
    files = discover_files(ScanConfig(root=FIX))
    names = [p.name for p in files]
    assert ".env" in names and "app.py" in names


def test_ignores_node_modules_and_git(tmp_path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "a.js").write_text('api_key = "AK_EXAMPLE_SYNTHETIC_001122334455"')
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("[core]\n")
    (tmp_path / "ok.py").write_text("x = 1\n")
    files = discover_files(ScanConfig(root=str(tmp_path)))
    assert files, "expected the top-level file to be discovered"
    assert [p.name for p in files] == ["ok.py"]
    assert all("node_modules" not in p.parts and ".git" not in p.parts for p in files)


def test_scan_finds_synthetic_secrets():
    res = scan_path(FIX, ScanConfig(root=FIX))
    assert res["status"] == "COMPLETED"
    assert len(res["findings"]) >= 5
    for f in res["findings"]:
        assert f["masked_value"] and "EXAMPLE" not in f["fingerprint"]
        assert f["evidence"]
