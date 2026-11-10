"""Test isolation: every test session uses a DEDICATED temporary SQLite database.

This module is imported by pytest before any test module, so setting
LEAKLENS_DATABASE_URL here guarantees backend engine/session objects bind to
the isolated test DB instead of the developer's real ./leaklens.db.
"""
import os
import tempfile
from pathlib import Path

_TMPDIR = Path(tempfile.mkdtemp(prefix="leaklens-test-"))
_TEST_DB = _TMPDIR / "test.db"
if _TEST_DB.exists():
    _TEST_DB.unlink()

os.environ["LEAKLENS_DATABASE_URL"] = f"sqlite:///{_TEST_DB.as_posix()}"


def pytest_sessionfinish(session, exitstatus):
    try:
        if _TEST_DB.exists():
            _TEST_DB.unlink()
        _TMPDIR.rmdir()
    except OSError:
        pass
