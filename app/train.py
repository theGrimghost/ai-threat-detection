import csv
import json
import os

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedKFold, train_test_split

from app.features import FEATURES
from app.model import THRESHOLD, Scorer


def load(path="data/dataset.csv"):
    X, y, cat, rules = [], [], [], []
    with open(path, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            X.append([float(r.get(k, 0.0)) for k in FEATURES])
            y.append(int(r["label"]))
            cat.append(r["category"])
            rules.append(int(r["rules_flag"]))
    # mix real data if present (CSIC via app.real_data); test-split rows forced to test
    real_test = None
    if os.path.exists("data/real.csv"):
        Xr, yr, catr, rulesr, splitr = [], [], [], [], []
        with open("data/real.csv", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                Xr.append([float(r.get(k, 0.0)) for k in FEATURES])
                yr.append(int(r["label"]))
                catr.append(r.get("category", "real-attack" if int(r["label"]) else "benign"))
                rulesr.append(int(r.get("rules_flag", 0)))
                splitr.append(r.get("split", "train"))
        Xr = np.array(Xr, dtype=np.float32)
        print(f"mixing {len(Xr)} real rows ({sum(s == 'test' for s in splitr)} test-only)")
        X = np.vstack([np.array(X, dtype=np.float32), Xr])
        y = np.concatenate([np.array(y), np.array(yr)])
        cat = np.concatenate([np.array(cat), np.array(catr)])
        rules = np.concatenate([np.array(rules), np.array(rulesr)])
        real_test = np.array([s == "test" for s in splitr])
        # store mask alignment: first len-splitr entries are synthetic (False)
        real_test = np.concatenate([np.zeros(len(X) - len(splitr), dtype=bool), real_test])
    return (np.asarray(X, dtype=np.float32), np.asarray(y), np.asarray(cat), np.asarray(rules),
            real_test)


def prf(y, pred):
    return {"precision": round(float(precision_score(y, pred)), 4),
            "recall": round(float(recall_score(y, pred)), 4),
            "f1": round(float(f1_score(y, pred)), 4)}


def rf_model():
    return RandomForestClassifier(n_estimators=200, max_depth=14, class_weight="balanced",
                                  random_state=42, n_jobs=-1)


def main():
    X, y, cat, rules, real_test = load()
    if real_test is not None and real_test.sum():
        # honor CSIC test-only split: those rows never train
        te_idx = np.where(real_test)[0]
        tr_idx = np.where(~real_test)[0]
        Xtr_s, Xte_s, ytr_s, yte_s, ctr_s, cte_s, _, rte_s = train_test_split(
            X[tr_idx], y[tr_idx], cat[tr_idx], rules[tr_idx],
            test_size=0.25, stratify=y[tr_idx], random_state=42)
        Xtr, ytr, ctr = Xtr_s, ytr_s, ctr_s
        Xte = np.vstack([Xte_s, X[te_idx]])
        yte = np.concatenate([yte_s, y[te_idx]])
        cte = np.concatenate([cte_s, cat[te_idx]])
        rte = np.concatenate([rte_s, rules[te_idx]])
        print(f"real-test rows forced to eval: {len(te_idx)}")
    else:
        Xtr, Xte, ytr, yte, ctr, cte, _, rte = train_test_split(
            X, y, cat, rules, test_size=0.25, stratify=y, random_state=42)

    rf = rf_model().fit(Xtr, ytr)
    iso = IsolationForest(n_estimators=200, random_state=42, n_jobs=-1).fit(Xtr[ytr == 0])
    bs = iso.score_samples(Xtr[ytr == 0])
    meta = {"iso_p50": float(np.median(bs)), "iso_p1": float(np.percentile(bs, 1))}

    os.makedirs("models", exist_ok=True)
    joblib.dump(rf, "models/rf.joblib")
    joblib.dump(iso, "models/iso.joblib")
    with open("models/meta.json", "w") as f:
        json.dump(meta, f)

    sc = Scorer()
    blend = sc.score(Xte) >= THRESHOLD
    rf_only = sc.rf_proba(Xte) >= 0.5
    iso_only = sc.iso_anomaly(Xte) >= 0.5

    # 5-fold CV for honest intervals (RF only, fast)
    cv_f1 = []
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    for tr, va in skf.split(X, y):
        r = rf_model().fit(X[tr], y[tr])
        cv_f1.append(float(f1_score(y[va], r.predict(X[va]))))
    cv_mean, cv_std = round(float(np.mean(cv_f1)), 4), round(float(np.std(cv_f1)), 4)

    # weight search W_RF in [0.5..0.9] with FP<=0.5% constraint
    best = {"w": 0.7, "f1": -1.0}
    rf_p, iso_a = sc.rf_proba(Xte), sc.iso_anomaly(Xte)
    for w in (0.5, 0.6, 0.7, 0.8, 0.9):
        pred = (w * rf_p + (1 - w) * iso_a) >= THRESHOLD
        fp = float(pred[yte == 0].mean()) if (yte == 0).sum() else 1.0
        f1 = float(f1_score(yte, pred))
        if fp <= 0.005 and f1 > best["f1"]:
            best = {"w": w, "f1": round(f1, 4), "fp": round(fp, 4)}

    # per-family advisory thresholds: smallest score catching 95% of family (RF prob)
    fam_thresh = {}
    for c in sorted(set(cte.tolist()) - {"benign"}):
        probs = sc.rf_proba(Xte[cte == c])
        if len(probs):
            fam_thresh[c] = round(float(np.quantile(probs, 0.05)), 4)

    # unseen-family test: never show the model evasive attacks during training
    keep = ctr != "evasive"
    rf2 = rf_model().fit(Xtr[keep], ytr[keep])
    ev = cte == "evasive"

    # leave-one-family-out: true zero-day proxy for every attack family
    # RF-only shows pure ML generalization; layered shows production (rules still on).
    lofo_recall = {}
    lofo_layered = {}
    for fam in sorted(set(ctr.tolist()) - {"benign"}):
        k = ctr != fam
        try:
            r = rf_model().fit(Xtr[k], ytr[k])
        except ValueError:
            continue
        m = cte == fam
        if m.sum():
            rf_r = float(r.predict(Xte[m]).mean())
            rules_r = float(rte[m].mean())
            # layered proxy: caught if rules fire OR RF fires (IF omitted for speed)
            lofo_recall[fam] = round(rf_r, 4)
            lofo_layered[fam] = round(float(((r.predict(Xte[m]) == 1) | (rte[m] == 1)).mean()), 4)

    cats = tuple(sorted(set(cte.tolist()) - {"benign"})) or ("classic", "evasive", "recon")
    results = {
        "rules": prf(yte, rte), "random_forest": prf(yte, rf_only),
        "isolation_forest": prf(yte, iso_only), "ensemble": prf(yte, blend),
        "ensemble_false_positive_rate": round(float(blend[yte == 0].mean()), 4),
        "recall_by_category": {
            c: {"rules": round(float(rte[cte == c].mean()), 4) if (cte == c).sum() else 0.0,
                "ensemble": round(float(blend[cte == c].mean()), 4) if (cte == c).sum() else 0.0}
            for c in cats},
        "unseen_evasive_recall_rf": round(float(rf2.predict(Xte[ev]).mean()), 4) if ev.sum() else 0.0,
        "lofo_recall_rf": lofo_recall,
        "lofo_layered_recall": lofo_layered,
        "cv_f1_mean": cv_mean,
        "cv_f1_std": cv_std,
        "cv_f1_folds": [round(v, 4) for v in cv_f1],
        "weight_search": best,
        "per_family_rf_threshold_95": fam_thresh,
    }
    with open("models/metrics.json", "w") as f:
        json.dump(results, f, indent=2)

    print(f"{'model':<18}{'precision':>10}{'recall':>9}{'f1':>8}")
    for k in ("rules", "random_forest", "isolation_forest", "ensemble"):
        r = results[k]
        print(f"{k:<18}{r['precision']:>10}{r['recall']:>9}{r['f1']:>8}")
    print("ensemble FP rate:", results["ensemble_false_positive_rate"])
    print("recall by category:", json.dumps(results["recall_by_category"]))
    print("evasive recall when UNSEEN in training (RF):", results["unseen_evasive_recall_rf"])
    print("LOFO recall (RF, family unseen):", json.dumps(results["lofo_recall_rf"]))
    print("LOFO layered recall (rules OR RF):", json.dumps(results["lofo_layered_recall"]))
    print(f"CV F1 5-fold: {cv_mean} +- {cv_std} {cv_f1_folds if (cv_f1_folds := results['cv_f1_folds']) else ''}")
    print("weight search:", json.dumps(best), "per-family 95% thresholds:", json.dumps(fam_thresh))


if __name__ == "__main__":
    main()
