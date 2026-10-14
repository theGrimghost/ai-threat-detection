import time
from collections import defaultdict
from typing import Optional

from app.features import extract
from app.model import THRESHOLD, Scorer
from app.rules import detect


class Engine:
    """Combines regex rules and the ML ensemble into one alert decision."""

    def __init__(self, scorer: Optional[Scorer] = None, sweep_window: float = 60.0, sweep_n: int = 3):
        self.scorer = scorer or Scorer()
        self.sweep_window = sweep_window
        self.sweep_n = sweep_n
        self._hits: dict[str, list] = defaultdict(list)

    def _sweep(self, ip: str, sensitive: bool) -> bool:
        now = time.time()
        if sensitive:
            self._hits[ip].append(now)
        hist = [t for t in self._hits[ip] if now - t <= self.sweep_window]
        self._hits[ip] = hist
        return len(hist) >= self.sweep_n

    def analyze(self, rec: dict) -> Optional[dict]:
        from app.features import FEATURES

        rules = detect(rec)
        feats = extract(rec)
        score = float(self.scorer.score([feats])[0])
        # session signal: repeated sensitive probing from one IP
        fmap = dict(zip(FEATURES, feats))
        sensitive = bool(rules) or score >= THRESHOLD or fmap.get("sensitive_path", 0) >= 1 or fmap.get("recon_admin", 0) >= 1 or fmap.get("recon_dot", 0) >= 1
        sweep = self._sweep(rec.get("ip", "-"), sensitive)
        if sweep and not rules:
            rules = ["sweep"]
            score = max(score, THRESHOLD + 0.05)
        if not rules and score < THRESHOLD:
            return None
        source = "both" if rules and score >= THRESHOLD else ("rules" if rules else "ml")
        if sweep and source == "ml":
            source = "ml+sweep"
        severity = "medium"
        if score >= 0.7:
            severity = "high"
        if score >= 0.9:
            severity = "critical"
        if rules and severity == "medium":
            severity = "high"
        try:
            from app.explain import top_reasons

            reasons = top_reasons(self.scorer, feats)
        except Exception:
            reasons = []
        return {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "ip": rec.get("ip", "-"),
            "method": rec.get("method", "-"),
            "path": rec.get("path", "-"),
            "ua": rec.get("ua", "-"),
            "rules": rules,
            "score": round(score, 4),
            "severity": severity,
            "source": source,
            "reasons": reasons,
        }
