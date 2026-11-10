"""Train LeakLens v1 models (stdlib bootstrap, no pandas).

Models: A=tfidf-logreg  B=charngram-logreg  C=numeric-RF (feature_schema v1.1.0)
        (+bonus D=tfidf-svm). Label: `contains_secret` (fallback `is_positive`).

Selects best by validation F1, calibrates it (sigmoid, prefit) on the
validation split, tunes the decision threshold (max F1 sweep) and the
rule/ML hybrid weights (blended = w_rule*rule_conf + (1-w_rule)*ml_prob).

Artifacts (models/v1/):
  vectorizer.joblib | classifier.joblib | calibrator.joblib |
  feature_schema.json | metadata.json | model_comparison.json |
  threshold.json | hybrid_weights.json
Legacy single-pipeline copy is also saved to models/production/ and the
registry is updated (production = leaklens-context-v1).
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

import sys as _sys
_sys.path.insert(0, str(ROOT))  # see scripts/_bootstrap.py

V1 = ROOT / "models" / "v1"


def _label(r: dict) -> int:
    if "contains_secret" in r:
        return int(bool(r["contains_secret"]))
    return int(bool(r.get("is_positive", 0)))


def load_split(name: str):
    p = ROOT / "datasets" / name / "dataset.jsonl"
    if not p.exists():
        return [], []
    rows = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    return [r.get("text", "") for r in rows], [_label(r) for r in rows]


def _rule_conf(text: str) -> float:
    """Deterministic rule confidence for a raw line (0 when no detector hits)."""
    try:
        from backend.app.detection.registry import scan_line
        hits = scan_line(text or "")
        if not hits:
            return 0.0
        return float(max(h[0].confidence for h in hits))
    except Exception:
        return 0.0


def _ml_probs(model, X, algo: str):
    import numpy as np
    if algo == "numeric-rf":
        from backend.app.ml.features.feature_pipeline import featurize_text, shannon, to_vector
        Xn = np.array([to_vector(featurize_text(t, "", "", shannon(t or ""))) for t in X],
                      dtype=float)
        if hasattr(model, "predict_proba"):
            return np.asarray(model.predict_proba(Xn)[:, 1], dtype=float)
        return np.asarray(model.predict(Xn), dtype=float)
    if hasattr(model, "predict_proba"):
        return np.asarray(model.predict_proba(X)[:, 1], dtype=float)
    s = np.asarray(model.decision_function(X), dtype=float)
    lo, hi = float(s.min()), float(s.max())
    return (s - lo) / max(1e-9, hi - lo)


def main() -> dict:
    import joblib
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import f1_score
    from sklearn.pipeline import make_pipeline
    from sklearn.svm import LinearSVC

    from backend.app.ml.features.feature_pipeline import (
        NUMERIC_KEYS, feature_schema, featurize_text, shannon, to_vector,
    )

    Xtr, ytr = load_split("train")
    Xva, yva = load_split("validation")
    if len(Xtr) < 20 or len(set(ytr)) < 2:
        raise SystemExit("Insufficient training data — run split_dataset.py on v2 first")
    yva_np = np.array(yva)

    models = {
        "A-tfidf-logreg": make_pipeline(
            TfidfVectorizer(max_features=4000),
            LogisticRegression(max_iter=500)),
        "B-charngram-logreg": make_pipeline(
            TfidfVectorizer(analyzer="char", ngram_range=(3, 5), max_features=6000),
            LogisticRegression(max_iter=500)),
        "D-tfidf-svm": make_pipeline(
            TfidfVectorizer(max_features=4000), LinearSVC()),
    }

    def numvec(texts):
        return np.array(
            [to_vector(featurize_text(t or "", "", "", shannon(t or ""))) for t in texts],
            dtype=float)

    Xtr_n, Xva_n = numvec(Xtr), numvec(Xva)
    models["C-numeric-rf"] = RandomForestClassifier(n_estimators=200, random_state=42,
                                                   n_jobs=-1)

    comparison: dict[str, dict] = {}
    fitted: dict = {}
    val_probs: dict[str, np.ndarray] = {}
    for name, m in models.items():
        if name == "C-numeric-rf":
            m.fit(Xtr_n, ytr)
            probs = _ml_probs(m, Xva, "numeric-rf")
            pred = (probs >= 0.5).astype(int)
        else:
            m.fit(Xtr, ytr)
            probs = _ml_probs(m, Xva, "other")
            pred = m.predict(Xva)
            pred = np.asarray(pred, dtype=int)
        f1 = float(f1_score(yva, pred, zero_division=0))
        comparison[name] = {"val_f1_at_0.5": f1}
        fitted[name] = m
        val_probs[name] = np.asarray(probs, dtype=float)
        print(f"{name}: val F1@0.5={f1:.4f}", flush=True)

    best = max(comparison, key=lambda k: comparison[k]["val_f1_at_0.5"])
    algo = "numeric-rf" if best == "C-numeric-rf" else "text"
    print(f"Best: {best}", flush=True)

    # Calibrate best on validation via Platt scaling (logistic on 1-D raw
    # scores) + tune threshold for max F1. (sklearn 1.9 removed
    # CalibratedClassifierCV(cv="prefit"); manual Platt is equivalent.)
    base = fitted[best]
    if best == "C-numeric-rf":
        raw_tr = _ml_probs(base, Xtr, "numeric-rf")
        raw_va = _ml_probs(base, Xva, "numeric-rf")
        score_kind = "proba"
    elif hasattr(base, "predict_proba"):
        raw_tr = _ml_probs(base, Xtr, "other")
        raw_va = _ml_probs(base, Xva, "other")
        score_kind = "proba"
    else:
        raw_va = np.asarray(fitted[best].decision_function(Xva), dtype=float)
        raw_tr = np.asarray(fitted[best].decision_function(Xtr), dtype=float)
        score_kind = "decision"
    platt = LogisticRegression(max_iter=1000)
    platt.fit(raw_tr.reshape(-1, 1), ytr)
    cal_probs = np.asarray(platt.predict_proba(raw_va.reshape(-1, 1))[:, 1], dtype=float)
    cal = {"coef": float(platt.coef_[0][0]), "intercept": float(platt.intercept_[0]),
           "score_kind": score_kind, "model": best}

    best_t, best_f1 = 0.5, -1.0
    for t in [round(x * 0.05, 2) for x in range(2, 19)]:
        f1 = float(f1_score(yva_np, (cal_probs >= t).astype(int), zero_division=0))
        if f1 > best_f1:
            best_f1, best_t = f1, t

    # Tune hybrid rule/ML weights on a validation subsample (speed: <=3000 rows).
    idx = list(range(len(Xva)))
    random.Random(42).shuffle(idx)
    idx = idx[:3000]
    rule = np.array([_rule_conf(Xva[i]) for i in idx], dtype=float)
    ml = cal_probs[idx]
    ysub = yva_np[idx]
    best_w, best_wf1 = 0.6, -1.0
    for w in [round(x * 0.1, 1) for x in range(0, 11)]:
        blended = w * rule + (1 - w) * ml
        f1 = float(f1_score(ysub, (blended >= best_t).astype(int), zero_division=0))
        if f1 > best_wf1:
            best_wf1, best_w = f1, w

    V1.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    if best == "C-numeric-rf":
        joblib.dump(base, V1 / "classifier.joblib")
        (V1 / "vectorizer.joblib").write_bytes(b"")  # marker: numeric model has no text vectorizer
        vectorizer_kind = "none (numeric features v1.1.0)"
    else:
        joblib.dump(base.named_steps["tfidfvectorizer"], V1 / "vectorizer.joblib")
        joblib.dump(list(base.named_steps.values())[-1], V1 / "classifier.joblib")
        vectorizer_kind = type(base.named_steps["tfidfvectorizer"]).__name__
    joblib.dump(cal, V1 / "calibrator.joblib")
    (V1 / "feature_schema.json").write_text(json.dumps(feature_schema(), indent=2))
    for k, v in comparison.items():
        v["val_f1_calibrated"] = None
    comparison[best]["val_f1_calibrated"] = best_f1
    comparison[best]["threshold"] = best_t
    (V1 / "model_comparison.json").write_text(json.dumps(comparison, indent=2))
    (V1 / "threshold.json").write_text(json.dumps(
        {"threshold": best_t, "val_f1": best_f1, "model": best}, indent=2))
    (V1 / "hybrid_weights.json").write_text(json.dumps(
        {"rule_weight": best_w, "ml_weight": round(1 - best_w, 4),
         "threshold": best_t, "val_f1": best_wf1, "method": "grid sweep on 3000-row validation sample",
         "rule_confidence": "max detector confidence via scan_line (0 when no hit)"}, indent=2))
    meta = {"model_name": "leaklens-context-v1", "version": "1.0.0",
            "training_dataset": "leaklens-synthetic-v2", "dataset_version": "v2.0",
            "feature_version": "1.1.0", "algorithm": best,
            "vectorizer": vectorizer_kind,
            "training_date": datetime.now(timezone.utc).isoformat(),
            "train_rows": len(Xtr), "val_rows": len(Xva),
            "metrics": {"validation_f1": best_f1, "threshold": best_t,
                        "all_validation_f1": {k: v["val_f1_at_0.5"] for k, v in comparison.items()}},
            "parameters": {"choice": f"best of {sorted(comparison)}",
                           "calibration": "sigmoid prefit on validation"}}
    (V1 / "metadata.json").write_text(json.dumps(meta, indent=2))

    # Legacy single-pipeline copy for existing inference path.
    dest = ROOT / "models" / "production" / f"leaklens-context-{stamp}.joblib"
    dest.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(fitted[best], dest)
    (dest.parent / "metadata.json").write_text(json.dumps(meta, indent=2))
    (ROOT / "models" / "baseline").mkdir(parents=True, exist_ok=True)
    for name, m in fitted.items():
        joblib.dump(m, ROOT / "models" / "baseline" / f"{name}.joblib")

    from backend.app.ml.registry import register_model
    register_model({"name": "leaklens-context-v1", "version": "1.0.0", "algorithm": best,
                    "dataset_version": "v2.0", "feature_version": "1.1.0",
                    "path": f"models/production/{dest.name}",
                    "artifacts": "models/v1/{vectorizer,classifier,calibrator}.joblib",
                    "threshold": best_t, "hybrid_weights": {"rule": best_w, "ml": round(1 - best_w, 4)},
                    "metrics": meta["metrics"]}, make_production=True)
    print(f"Best: {best} thr={best_t} F1={best_f1:.4f} hybrid rule={best_w} -> {dest}")
    return {"best": best, "threshold": best_t, "val_f1": best_f1,
            "rule_weight": best_w, "path": str(dest)}


if __name__ == "__main__":
    main()
