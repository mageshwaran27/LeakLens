# LeakLens — local-first secret scanning

LeakLens scans projects for exposed secrets (API keys, passwords, tokens,
private keys, database credentials, PII), explains each finding with evidence,
and keeps raw values masked at all times. Everything runs on your own device;
there is no cloud integration.

## Architecture

```
browser (leaklens/index.html, static, no build step)
   │  fetch/JSON, Bearer token
   ▼
FastAPI backend (backend/app) ── thread jobs ── scanner pipeline
   │ detectors → entropy → context/risk → optional ML (char-ngram + Platt)
   ▼
SQLite (leaklens.db) — projects, scans, findings (masked only), reports,
activities, users, tokens, settings
```

- Detection engine: 21 versioned regex detectors (`backend/app/detection/registry.py`)
  plus Shannon/charset entropy and file/variable context scoring
  (`backend/app/context/risk.py`). Coverage is intentionally not exhaustive.
- ML context model: char-ngram TF-IDF + logistic regression with Platt scaling
  (`models/v1/`), trained on 209k controlled synthetic rows (test F1 ≈ 0.94).
  The scanner blends rule confidence with the ML probability using tuned
  weights (rule 0.2 / ML 0.8). The model never sees real secrets.
- Redaction: findings persist `masked_value` + SHA-256 fingerprint only.
  Raw values never reach the DB, logs, reports, or API responses
  (`backend/app/core/redaction.py`).

## Requirements

- Python 3.11+ (dependencies in `backend/requirements.txt`)
- Node.js (optional, only for running the frontend checks)
- No external services, no API keys, no network access required at runtime.

## Installation

```powershell
copy .env.example .env
python -m alembic upgrade head   # fresh DB; existing DBs: alembic stamp head
```

If `pip` is restricted in your environment, note all runtime imports are
already covered by `backend/requirements.txt`; install normally with
`pip install -r backend/requirements.txt` where permitted.

## Environment variables (all optional)

| Variable | Purpose | Default |
|---|---|---|
| `LEAKLENS_DATABASE_URL` | SQLAlchemy DB URL | `sqlite:///<project-root>/leaklens.db` |
| `LEAKLENS_CORS_ORIGINS` | Comma-separated allowed origins | localhost/127.0.0.1 on ports 3000, 8000, 8080 |
| `LEAKLENS_LOG_LEVEL` | Backend log level (`log_level` setting also readable; restart applies) | `INFO` |

`.env` holds only the database URL. There are no cloud credentials because
there is no cloud integration. Never commit real secrets to `.env`.

## Database setup

- Canonical location: `<project-root>/leaklens.db` (absolute default; override
  with `LEAKLENS_DATABASE_URL`). A stale `backend/leaklens.db` from older runs
  is superseded and ignored.
- Schema is created automatically on startup (`create_all`); versioned
  migrations live in `alembic/versions/`.
- Tests never touch the dev DB: `tests/conftest.py` points every session at a
  throwaway temp SQLite file.

## Running the backend

```powershell
python -m uvicorn backend.app.main:app --port 8000
```

API docs: http://127.0.0.1:8000/docs · health: `/health`.
The server binds to localhost by default. Exposing it publicly is unsupported:
there is deliberately no multi-user hardening beyond local bearer-token auth.

## Running the frontend

No build step — static files in `leaklens/`:

```powershell
python -m http.server 8080 --directory leaklens
```

Open http://localhost:8080. The API client defaults to
http://127.0.0.1:8000 (override with `window.LEAKLENS_API`).

## Authentication setup

There are no default credentials. On first run, open the UI and create the
admin account (allowed only while no users exist), or use the CLI:

```powershell
python backend/cli.py create-admin --username admin
```

Then: `POST /api/auth/login` → Bearer token (7-day expiry),
`POST /api/auth/logout` revokes it, `GET /api/auth/me` shows the session.
All `/api/*` routes except login/setup/status require the token.
Passwords are PBKDF2-HMAC-SHA256 hashes; tokens are stored as SHA-256 digests.

## Scan workflow

1. Scan page → drop a `.zip` (uploaded, extracted locally, 100MB/20k-file caps,
   zip-slip guarded) or paste a local folder path.
2. Set options: ML scoring, include docs/tests, minimum severity persisted,
   extra excluded directories. Defaults come from Settings.
3. Start → background job → live progress → findings (masked) → click through
   to evidence, then Resolve / False-positive / Ignore (persisted).
4. Past scans stay available under Scans and per-project history after reload.

Uploads live under `uploads/<id>/`; delete them via the API
(`DELETE /api/uploads/{id}`) or the folder itself to reclaim space.

## Report workflow

Reports page → pick a completed scan → JSON/CSV/SARIF/HTML → generated from
real persisted findings (masked only) via `backend/app/reports/exporters.py`
→ download, or delete. CSV cells are formula-injection guarded.

## CLI usage

```powershell
python backend/cli.py scan <path> --format text|json|csv|sarif|html --severity all|low|medium|high --model production|none --output out.txt
python backend/cli.py benchmark <path>
python backend/cli.py create-admin --username admin
```

CLI and API share the same scanner, detectors, redaction, exporters, and model.

## ML model information

- Artifacts: `models/v1/` (`vectorizer` + `classifier` + Platt `calibrator`,
  `feature_schema.json`, `threshold.json`, `hybrid_weights.json`,
  `model_comparison.json`, `metadata.json`). Registry: `models/registry.json`.
- Features v1.1.0: 7 statistical + 6 context + 10 detector-pattern bits
  (`backend/app/ml/features/feature_pipeline.py`). Detector bits are regex
  hits; no secret values are stored.
- Evaluation (`reports/model_evaluation.json`): test F1 ≈ 0.94, ROC AUC ≈ 0.96
  on a 31k labeled synthetic split; hard-negative holdout FPR ≈ 2.9%.
  Measured on controlled synthetic data, not real-world data.

## Dataset pipeline

```powershell
python scripts/generate_synthetic_data.py
python scripts/build_dataset.py
python scripts/normalize_dataset.py
python scripts/deduplicate_dataset.py
python scripts/split_dataset.py
python scripts/validate_dataset.py
python scripts/train_model.py
python scripts/evaluate_model.py
```

All values are synthetic/non-functional. External corpora are documented but
never downloaded automatically (`scripts/acquire_datasets.py` is offline-safe;
per-source notes live under `datasets/external/`).

## Testing

```powershell
python -m pytest tests/ -q
node tests/frontend/ui_smoke.js
```

Backend: engine unit tests, redaction/security tests, auth tests, full API
lifecycle, platform coverage (uploads incl. zip-slip, scan options, reports,
settings validation, benchmarks). Tests use an isolated temp DB and clean up
after themselves. Frontend: handler-wiring checks, mock-leftover scan, and a
render smoke test (boot → login → dashboard) with stubbed DOM/API.

## Security notes

- Mask-only persistence; redacted errors/logs; credential-like settings refused.
- Local bearer-token auth; tight localhost CORS list (configurable).
- Upload caps + zip-slip guard; LIKE-wildcard escaping; CSV formula guard;
  HTML escaping in UI; validated scan options; scan failures persisted.
- Known limits (see code/docs, not hidden): no rate limiting, in-memory job
  queue (a restart loses in-flight scans; rows may stick at QUEUED), single
  local user model, SQLite concurrency.

## Local-first limitations / unsupported

- No multi-user roles, no SSO, no public-deployment hardening.
- No git-history scanning (option removed rather than faked).
- No cloud analysis (shown as unavailable, never simulated).
- No WebSockets/SSE (polling), no email/notifications, no external storage.

## Roadmap (not implemented)

External dataset ingestion, IDE/CI integrations, per-category detector toggles
backed by engine support, durable job queue (only if scale demands it).
