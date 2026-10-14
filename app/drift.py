"""Drift check: compare live feature means vs training snapshot (PSI-lite)."""
import csv
import json
import math


def snapshot(path="data/dataset.csv", out="models/feature_stats.json"):
    from app.features import FEATURES
    sums, n = None, 0
    with open(path) as f:
        for r in csv.DictReader(f):
            v = [float(r.get(k, 0.0)) for k in FEATURES]
            sums = v if sums is None else [a + b for a, b in zip(sums, v)]
            n += 1
    means = [s / max(n, 1) for s in sums]
    with open(out, "w") as f:
        json.dump({"n": n, "means": means}, f)
    return out


def psi(expected, actual, bins=10):
    """Population Stability Index per feature (binned on expected quantiles)."""
    import numpy as np
    out = []
    for e, a in zip(zip(*expected), zip(*actual)):
        e = np.asarray(e, float)
        a = np.asarray(a, float)
        qs = np.quantile(e, np.linspace(0, 1, bins + 1))
        qs[0], qs[-1] = -math.inf, math.inf
        eh, _ = np.histogram(e, bins=qs)
        ah, _ = np.histogram(a, bins=qs)
        eh = eh / max(eh.sum(), 1) + 1e-6
        ah = ah / max(ah.sum(), 1) + 1e-6
        out.append(float(np.sum((ah - eh) * np.log(ah / eh))))
    return out
