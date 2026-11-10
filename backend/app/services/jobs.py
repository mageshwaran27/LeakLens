"""Local background job manager (thread-based; Celery/RQ-compatible interface)."""
from __future__ import annotations

import threading
import time
import uuid

_JOBS: dict[str, dict] = {}
_LOCK = threading.Lock()


def submit(fn, *args, **kwargs) -> str:
    jid = uuid.uuid4().hex[:12]
    with _LOCK:
        _JOBS[jid] = {"status": "QUEUED", "progress": {}, "result": None, "error": ""}
    def _run():
        with _LOCK:
            _JOBS[jid]["status"] = "RUNNING"
        try:
            res = fn(job_id=jid, *args, **kwargs)
            with _LOCK:
                _JOBS[jid]["status"] = "DONE"
                _JOBS[jid]["result"] = res
        except Exception as e:  # noqa: BLE001
            with _LOCK:
                _JOBS[jid]["status"] = "FAILED"
                _JOBS[jid]["error"] = str(e)
    threading.Thread(target=_run, daemon=True).start()
    return jid


def update_progress(jid: str, **kw) -> None:
    with _LOCK:
        if jid in _JOBS:
            _JOBS[jid]["progress"].update(kw)


def get(jid: str) -> dict | None:
    with _LOCK:
        return dict(_JOBS.get(jid, {})) if jid in _JOBS else None
