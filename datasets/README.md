# LeakLens datasets

- `synthetic/` — controlled generated data (`scripts/generate_synthetic_data.py`). All values
  synthetic/non-functional (contain `EXAMPLE` or random test values). Safe to redistribute.
- `external/` — NOT bundled. Per-source download instructions and licenses live in
  `external/<source>/README.md` (created by `scripts/acquire_datasets.py`) for
  manual, license-respecting acquisition.
- `processed/`, `normalized/`, `train/`, `validation/`, `test/` — pipeline outputs.
- `manifests/dataset_manifest.json` — provenance for every source.
- `regression/` — per-issue regression cases.
