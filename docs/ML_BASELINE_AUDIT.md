# LeakLens ML Baseline Audit (Phase 0)

Date: 2026-09-29. Inspected the actual repository at the project root
(`backend/`, `scripts/` × 14, `datasets/`, `models/`, `tests/`, `leaklens/` frontend).

## 1. Existing dataset structure

- `datasets/synthetic/synthetic.jsonl` — 4000 generated rows.
- `datasets/processed/dataset.jsonl` — merged build output (4000 rows).
- `datasets/normalized/dataset.jsonl` — schema-checked output (4000 rows).
- `datasets/processed/dataset_dedup.jsonl` — deduped output (1827 rows).
- `datasets/train|validation|test/dataset.jsonl` — 1505 / 160 / 162 rows.
- `datasets/splits/*.json`, `datasets/manifests/dataset_manifest.json` (one source recorded).
- `datasets/external/` — sources documented only, nothing downloaded.
- `datasets/regression/` — README only, no cases.

## 2. Existing dataset-generation logic

`scripts/generate_synthetic_data.py`: 10 secret templates + 9 fixed negative
templates × 22 file contexts, random assignment, `--n`/`--seed` flags.
Negatives reuse byte-identical template strings (root cause of Error 3).

## 3. Existing labels

Single-level `label` ∈ {TRUE_SECRET, TRUE_PII, PLACEHOLDER, EXAMPLE,
TEST_SECRET, DOCUMENTATION, BENIGN_HIGH_ENTROPY, BENIGN_CONFIG,
FALSE_POSITIVE} plus boolean `is_positive` and `context_type`. No
`contains_secret` binary field, no `secret_type`/`context_label` split, no
per-record provenance (source_version, license, access_date, language…).

## 4. Existing redaction logic

- Production safety is correct: `backend/app/core/redaction.py`
  (`mask_value`, `fingerprint`, `redact_text`), scanner stores masked values
  only, API/exports covered by redaction tests.
- `scripts/redact_dataset.py` (Error 2) was destructive on training data;
  currently rewritten to audit-only + `--apply` (non-synthetic rows only).
  Spec requires renaming the flag to `--sanitize` and a fixed audit schema —
  still to do (Phase 1).

## 5. Existing deduplication logic

`scripts/deduplicate_dataset.py`: single-level exact MD5 on
`text + file_context`. `scripts/detect_duplicates.py`: exact + prefix-20
near-dup counts (currently reports 2383 exact / 3074 near dups on the 4000
normalized rows). No layered (exact/context/near-dup/group) dedup, no
`leakage_audit.json` (Phase 1).

## 6. Existing train/validation/test split

`scripts/split_dataset.py`: group-aware by `group` key (template-prefix
hash), 70/15/15 → 1505/160/162 rows. No `split_manifest.json`, no overlap
assertion that fails the pipeline (Phase 1/14).

## 7. Existing ML models

`scripts/train_model.py`: 4 candidates (tfidf-logreg, tfidf-svm,
charngram-logreg, numeric-RF), best by validation F1 → single pipeline
joblib in `models/production/` + `models/registry.json`. Missing per spec:
separate vectorizer/classifier/calibrator artifacts, `feature_schema.json`,
calibrated threshold, tuned hybrid weights, `models/v1/` layout,
`model_comparison.json`. No model trained on current data yet in this cycle.

## 8. Existing scanner-to-ML integration

`backend/app/scanner/pipeline.py` accepts `use_ml` callable;
`backend/app/ml/inference/predict.py` loads the production registry entry and
returns a probability blended 0.6 rule / 0.4 ML. Deterministic detection stays
independent. Hybrid weights are fixed, not validation-tuned (Phase 20).

## 9. Existing tests

`tests/detection/` (detectors, context, scanner), `tests/security/`
(redaction), `tests/integration/` (API scan lifecycle), `tests/ml/`
(hard negatives). No `tests/dataset/` (pipeline/schema/provenance tests) and
no per-provider regression suite (Phase 24).

## 10. Existing problems (confirmed by inspection)

1. **Error 1** — `python scripts/redact_dataset.py` fails without manual
   `PYTHONPATH`; only `benchmark_model.py` self-bootstraps.
2. **Error 2** — addressed interim (audit-only); needs `--sanitize` + fixed
   schema + docs.
3. **Error 3** — 4000 → 1827 rows; `text+file_context` workaround kept;
   layered dedup + leakage audit missing.
4. **Class imbalance** — 1629 positive / 198 negative (~89% positive).
   Training on this is blocked until the negative generator is rewritten.
5. **NEW: pandas is unusable in this environment** — `import pandas` fails
   (`DLL load failed … Application Control policy has blocked this file`).
   `scripts/train_model.py` imports pandas → training currently broken.
   Fix: remove pandas from all scripts (stdlib `json`/`csv` only).
6. **NEW: no pyarrow / no `datasets` lib** — parquet output and Hugging Face
   downloads unavailable; JSONL stays the canonical format, external corpora
   need adapters with honest unavailable-records.

## 11. Planned modifications (execution order per master prompt)

1. Script bootstrap (`scripts/_bootstrap.py` + `scripts/__init__.py`) so
   `python scripts/*.py` and `python -m scripts.*` both work; drop pandas.
2. Redact script → fixed audit schema + `--sanitize`.
3. Layered dedup (L1 exact / L2 context-aware / L3 shingle near-dup /
   L4 template groups) + `leakage_audit.json`.
4. Rewritten negative generator (unique UUIDs/hashes/timestamps/versions/IDs,
   varied placeholders, localhost/dev values, doc examples) → ~50/50 balance
   at ~50k positive / ~100k negative scale.
5. Full provenance record schema + manifest; external-source adapters with
   honest access records.
6. Group-aware 70/15/15 splits + `split_manifest.json` + overlap fail-gate;
   separate eval-only hard-negative set.
7. Features incl. statistical/context/detector sets + `feature_schema.json`.
8. Models A/B/C (+calibration, comparison, `models/v1/`), tuned hybrid
   weights, security-focused evaluation (incl. FP/1000, hard-neg, in-the-wild
   handling).
9. Quality report, regression suite, docs, README, E2E, completion report.
