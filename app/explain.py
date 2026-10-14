"""Lightweight explainability: top features by RF importance * normalized value."""
import numpy as np


def top_reasons(scorer, x, k=3):
    try:
        imp = np.asarray(scorer.rf.feature_importances_, dtype=float)
    except Exception:
        return []
    from app.features import FEATURES
    x = np.asarray(x, dtype=float)
    scale = np.abs(x) / (np.abs(x).max() + 1e-9)
    ranked = sorted(zip(FEATURES, imp * scale), key=lambda t: -t[1])
    return [{"feature": f, "weight": round(float(w), 4)} for f, w in ranked[:k] if w > 0]
