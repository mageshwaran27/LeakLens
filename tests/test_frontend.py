"""Frontend checks: JS syntax + handler wiring + mock-purge + render smoke.

Runs tests/frontend/ui_smoke.js under node. Skipped when node is unavailable.
"""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
node = shutil.which("node")


@pytest.mark.skipif(node is None, reason="node is not installed")
def test_frontend_smoke():
    script = ROOT / "tests" / "frontend" / "ui_smoke.js"
    r = subprocess.run([node, str(script)], capture_output=True, text=True, timeout=120)
    print(r.stdout)
    assert r.returncode == 0, f"ui_smoke.js failed:\n{r.stdout}\n{r.stderr}"


@pytest.mark.skipif(node is None, reason="node is not installed")
def test_frontend_syntax():
    html = (ROOT / "leaklens" / "index.html").read_text(encoding="utf-8")
    inline = re.findall(r"<script>(.*?)</script>", html, re.S)
    assert inline, "no inline script found"
    for i, src in enumerate(inline):
        p = ROOT / f".ui_check_{i}.js"
        p.write_text(src, encoding="utf-8")
        try:
            r = subprocess.run([node, "--check", str(p)], capture_output=True,
                               text=True, timeout=60)
            assert r.returncode == 0, r.stderr
        finally:
            p.unlink(missing_ok=True)
    r = subprocess.run([node, "--check", str(ROOT / "leaklens" / "api-client.js")],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
