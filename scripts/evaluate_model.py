"""Evaluate production v1 model on test split + hard-negative holdout.

Security-focused metrics: precision/recall/F1, ROC/PR AUC, threshold sweep,
false-positives per 1000 rows, hard-negative-holdout FPR (eval-only set that
was never trained on), per-secret-type recall. Writes reports/model_evaluation.json.
"""
from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

import sys as _sys
_sys.path.insert(0, str(ROOT))  # see scripts/_bootstrap.py


def _label(r: dict) -> int:
    return int(bool(r.get("contains_secret", r.get("is_positive", 0))))


def main() -> dict:
    import joblib
    import numpy as np
    from sklearn.metrics import (average_precision_score, confusion_matrix, f1_score,
                                 precision_score, recall_score, roc_auc_score)

    from backend.app.ml.inference.predict import calibrated_probs, get_model, tuned_threshold

    model, meta = get_model()
    if model is None:
        raise SystemExit("No production model — run train_model.py first")
    algo = (meta or {}).get("algorithm", "")
    thr = tuned_threshold(0.5)

    def probs(texts):
        import numpy as np
        cp = calibrated_probs(texts)  # v1 vectorizer/classifier + Platt dict
        if cp is not None:
            return np.asarray(cp, dtype=float)
        if algo == "C-numeric-rf":
            from backend.app.ml.features.feature_pipeline import featurize_text, shannon, to_vector
            Xn = np.array([to_vector(featurize_text(t or "", "", "", shannon(t or "")))
                           for t in texts], dtype=float)
            if hasattr(model, "predict_proba"):
                return np.asarray(model.predict_proba(Xn)[:, 1], dtype=float)
            return np.asarray(model.predict(Xn), dtype=float)
        # v1 text path: model may be the calibrator expecting vectorized input
        try:
            if hasattr(model, "predict_proba"):
                try:
                    return np.asarray(model.predict_proba(texts)[:, 1], dtype=float)
                except Exception:
                    pass
            from backend.app.ml.inference.predict import _vec
            if _vec is not None:
                Xt = _vec.transform(texts)
                if hasattr(model, "predict_proba"):
                    return np.asarray(model.predict_proba(Xt)[:, 1], dtype=float)
                return np.asarray(model.predict(Xt), dtype=float)
            s = np.asarray(model.decision_function(texts), dtype=float)
            lo, hi = float(s.min()), float(s.max())
            return (s - lo) / max(1e-9, hi - lo)
        except Exception:
            if hasattr(model, "predict_proba"):
                return np.asarray(model.predict_proba(texts)[:, 1], dtype=float)
            raise

    p = ROOT / "datasets" / "test" / "dataset.jsonl"
    rows = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    X = [r.get("text", "") for r in rows]
    y = np.array([_label(r) for r in rows])
    scores = probs(X)

    out = ROOT / "reports"
    out.mkdir(parents=True, exist_ok=True)
    sweep = []
    for t in [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]:
        pred = (scores >= t).astype(int)
        tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
        sweep.append({"threshold": t, "precision": float(precision_score(y, pred, zero_division=0)),
                      "recall": float(recall_score(y, pred, zero_division=0)),
                      "f1": float(f1_score(y, pred, zero_division=0)),
                      "fpr": float(fp / max(1, fp + tn)), "fnr": float(fn / max(1, fn + tp)),
                      "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)})
    pred = (scores >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    fp_per_1000 = round(1000 * fp / max(1, len(y)), 2)

    # Per-secret-type recall on positives.
    by_type: dict[str, dict] = {}
    scores_by_row = scores
    for stype in sorted({r.get("secret_type", "?") for r in rows if _label(r)}):
        idx = [i for i, r in enumerate(rows) if r.get("secret_type") == stype and _label(r)]
        if not idx:
            continue
        rec = float(sum(1 for i in idx if scores_by_row[i] >= thr) / len(idx))
        by_type[stype] = {"n": len(idx), "recall": round(rec, 4)}

    # Hard-negative holdout (eval-only, never trained on): FPR must stay low.
    hn_p = ROOT / "datasets" / "processed" / "hard_negative_test.jsonl"
    if not hn_p.exists():
        hn_p = ROOT / "datasets" / "synthetic" / "hardneg_holdout.jsonl"
    hn_fpr, hn_n = None, 0
    if hn_p.exists():
        hn_rows = [json.loads(l) for l in hn_p.read_text(encoding="utf-8").splitlines() if l.strip()][:10000]
        hn_n = len(hn_rows)
        if hn_n:
            hn_scores = probs([r.get("text", "") for r in hn_rows])
            hn_fpr = round(float(sum(1 for s in hn_scores if s >= thr) / hn_n), 4)

    metrics = {"model": (meta or {}).get("name", "leaklens-context-v1"), "algorithm": algo,
               "threshold": thr, "n_test": len(y),
               "positives": int(y.sum()), "negatives": int(len(y) - y.sum()),
               "precision": float(precision_score(y, pred, zero_division=0)),
               "recall": float(recall_score(y, pred, zero_division=0)),
               "f1": float(f1_score(y, pred, zero_division=0)),
               "roc_auc": float(roc_auc_score(y, scores)) if len(set(y.tolist())) > 1 else None,
               "pr_auc": float(average_precision_score(y, scores)) if len(set(y.tolist())) > 1 else None,
               "confusion_matrix": {"tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)},
               "fp_per_1000": fp_per_1000,
               "hard_negative_holdout": {"rows_scored": hn_n, "fpr": hn_fpr, "eval_only": True},
               "per_secret_type_recall": by_type,
               "label_schema": "contains_secret (v2)",
               "threshold_sweep": sweep,
               "context_labels_test": dict(Counter(r.get("context_label", "?") for r in rows)),
               "note": "Measured on controlled synthetic test split (leaklens-synthetic-v2), not real-world data."}
    (out / "model_evaluation.json").write_text(json.dumps(metrics, indent=2))
    (out / "model_evaluation.html").write_text(
        "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Model evaluation</title></head><body>"
        f"<h1>Model evaluation — {metrics['model']}</h1><pre>{html.escape(json.dumps(metrics, indent=2))}</pre></body></html>")
    (out / "per_class_metrics.json").write_text(json.dumps(
        {"positive": {"precision": metrics["precision"], "recall": metrics["recall"], "f1": metrics["f1"]}}, indent=2))
    print(json.dumps({k: metrics[k] for k in
                      ("model", "algorithm", "threshold", "n_test", "precision", "recall",
                       "f1", "roc_auc", "fp_per_1000", "hard_negative_holdout")}, indent=2))
    return metrics


if __name__ == "__main__":
    main()
