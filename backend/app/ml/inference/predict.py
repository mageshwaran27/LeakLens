"""Load production model for scanner inference. Returns None when unavailable.

Prefers models/v1/ separated artifacts (vectorizer + classifier + calibrator,
feature_schema v1.1.0, tuned threshold + hybrid weights); falls back to the
legacy single-pipeline registry entry.
"""
from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np

from backend.app.ml.features.feature_pipeline import NUMERIC_KEYS, featurize_text, shannon

ROOT = Path(__file__).resolve().parents[4]
V1 = ROOT / "models" / "v1"

_model = None
_meta = None
_cal = None
_vec = None
_clf = None


def _load_json(p: Path, default):
    try:
        return json.loads(p.read_text())
    except Exception:
        return default


def tuned_threshold(default: float = 0.5) -> float:
    t = _load_json(V1 / "threshold.json", {})
    try:
        return float(t.get("threshold", default))
    except Exception:
        return default


def hybrid_weights() -> tuple[float, float]:
    w = _load_json(V1 / "hybrid_weights.json", {})
    try:
        rw = float(w.get("rule_weight", 0.6))
        return rw, round(1 - rw, 4)
    except Exception:
        return 0.6, 0.4


def blend(rule_conf: float, ml_prob: float) -> float:
    rw, mw = hybrid_weights()
    return round(max(0.0, min(0.99, rw * rule_conf + mw * ml_prob)), 2)


def _production_entry():
    reg = ROOT / "models" / "registry.json"
    if not reg.exists():
        return None
    data = json.loads(reg.read_text())
    name = data.get("production")
    for m in data.get("models", []):
        if m.get("name") == name:
            return m
    return None


def _sigmoid(z):
    import math
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


def _apply_platt(raw_scores, cal):
    """Manual Platt scaling: sigmoid(coef * raw + intercept)."""
    c = float(cal.get("coef", 1.0))
    b = float(cal.get("intercept", 0.0))
    return np.array([_sigmoid(c * float(s) + b) for s in raw_scores], dtype=float)


def calibrated_probs(texts) -> np.ndarray | None:
    """Probabilities via v1 artifacts (vectorizer/classifier + Platt dict)."""
    if _cal is None or _clf is None:
        return None
    if isinstance(_cal, dict):
        kind = _cal.get("score_kind", "proba")
        if _vec is not None:
            Xt = _vec.transform(list(texts))
            if kind == "decision" and hasattr(_clf, "decision_function"):
                raw = np.asarray(_clf.decision_function(Xt), dtype=float)
            elif hasattr(_clf, "predict_proba"):
                raw = np.asarray(_clf.predict_proba(Xt)[:, 1], dtype=float)
            else:
                raw = np.asarray(_clf.predict(Xt), dtype=float)
        else:
            Xn = _numeric_matrix(list(texts))
            if hasattr(_clf, "predict_proba"):
                raw = np.asarray(_clf.predict_proba(Xn)[:, 1], dtype=float)
            else:
                raw = np.asarray(_clf.predict(Xn), dtype=float)
        return _apply_platt(raw, _cal)
    if hasattr(_cal, "predict_proba"):  # legacy CalibratedClassifierCV artifact
        try:
            if _vec is not None:
                return np.asarray(_cal.predict_proba(_vec.transform(list(texts)))[:, 1])
            return np.asarray(_cal.predict_proba(_numeric_matrix(list(texts)))[:, 1])
        except Exception:
            return None
    return None


def _numeric_matrix(lines, file_path: str = "", var: str = ""):
    rows = []
    for t in lines:
        feats = featurize_text(t or "", file_path, var, shannon(t or ""))
        rows.append([float(feats[k]) for k in NUMERIC_KEYS])
    return np.array(rows, dtype=float)


def get_model():
    global _model, _meta, _cal, _vec, _clf
    if _model is not None or _cal is not None:
        return _model or _cal, _meta
    entry = _production_entry()
    _meta = entry
    cal_p, vec_p, clf_p = V1 / "calibrator.joblib", V1 / "vectorizer.joblib", V1 / "classifier.joblib"
    try:
        if cal_p.exists() and clf_p.exists() and cal_p.stat().st_size > 0:
            _cal = joblib.load(cal_p)
            _clf = joblib.load(clf_p)
            if vec_p.exists() and vec_p.stat().st_size > 0:
                _vec = joblib.load(vec_p)
            else:
                _vec = None  # numeric model
            return _cal, _meta
    except Exception:
        _cal = None
    if not entry:
        return None, None
    p = ROOT / entry.get("path", "")
    if not p.exists():
        return None, None
    _model = joblib.load(p)
    return _model, _meta


def ml_probability(line: str, file_path: str, var: str, entropy: float) -> float | None:
    model, meta = get_model()
    if model is None:
        return None
    try:
        algo = (meta or {}).get("algorithm", "")
        if _cal is not None:  # v1 calibrated path
            probs = calibrated_probs([line or ""])
            if probs is not None:
                return float(probs[0])
            # fall through to legacy single-pipeline path
        if algo == "C-numeric-rf" or "numeric" in algo:
            vec = _numeric_matrix([line], file_path, var)
            try:
                return float(model.predict_proba(np.array(vec))[0][1])
            except Exception:
                return float(model.predict(np.array(vec))[0])
        try:
            return float(model.predict_proba([line or ""])[0][1])
        except Exception:
            s = model.decision_function([line or ""])
            return float(np.asarray(s, dtype=float)[0])
    except Exception:
        return None
