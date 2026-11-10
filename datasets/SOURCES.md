# LeakLens dataset sources

Every data source below states its origin, license, and exact contribution.
Nothing here is overstated: if a source was not acquired, it says so.

## 1. `leaklens-synthetic-v2` (training + evaluation — 100% of current rows)

- **What:** 210,000 generated rows (101,123 positive / 108,877 negative),
  deduped to 209,181.
- **Reference:** `scripts/generate_synthetic_data.py` (generator v2.0, seed 42).
- **License:** LeakLens-synthetic; generated locally; no third-party data;
  safe to redistribute.
- **Collection date:** 2026-09-29 (regeneration date; deterministic from seed).
- **Preprocessing:** none (values are non-functional by construction:
  random tokens, `AKIA`+random, `EXAMPLE` placeholders, UUID/hash/timestamp
  distractors, localhost/dev values, doc sentences).
- **Redaction methodology:** n/a — no real secrets ever existed in this source.
  Every negative value is unique (uuid/hash generators), so legitimate
  contextual diversity survives deduplication.
- **Allowed usage:** training and evaluation.
- **Resulting samples:** 209,181 after layered dedup (819 exact removed).

## 2. `leaklens-synthetic-v1` (legacy, superseded)

- 4,000 rows from the v1 generator; kept only as `datasets/synthetic/synthetic.jsonl`
  for provenance. Excluded from builds whenever v2 buckets exist
  (`scripts/build_dataset.py`). Not counted in current totals.

## 3. `local-repo-benign` (planned — NOT YET INCLUDED)

- **What:** benign code/documentation lines extracted from this repository
  itself (application code, docs), passed through `redact_text`, with
  secret-like lines rejected.
- **Status:** NOT AVAILABLE in the current build. The training and test sets
  are 100% synthetic until this slice lands with honest per-record
  `source_type="local_repo"` provenance.

## 4. External corpora (NOT ACQUIRED — documented only)

Recorded by `scripts/acquire_datasets.py` in
`datasets/manifests/dataset_manifest.json` (`external-*` entries).
No records from these sources exist in any dataset file, for the stated
reasons. This offline environment cannot download them, and restricted
sources were never requested.

| Source | Reference | License/access | Status | Why no records |
|---|---|---|---|---|
| SecretBench | Springer s10664-023-10355-w | Restricted, author request | ACCESS_RESTRICTED | Gated academic access; no request made |
| Prowl Secrets Corpus | huggingface.co/datasets/prowl | Dataset-card terms | DEPENDENCY_MISSING | Needs `datasets`+`pyarrow`, unavailable here |
| FPSecretBench | huggingface.co | Dataset-card terms | DEPENDENCY_MISSING | Same as above |
| Issue-report corpus | github.com (per-repo OSS) | Per-repo licenses | NOT_ATTEMPTED | Manual curation only; none performed |
| GitGuardian samples | github.com/GitGuardian | Per-repo license | Fixtures only | Regression fixtures, never training corpus |

If any external source is added later, it MUST: preserve `original_label`,
record license/version/access date per record, pass the same schema validation,
and be listed here with its accepted/rejected counts.
