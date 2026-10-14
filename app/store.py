import json
import os
import sqlite3
import threading

SCHEMA = """CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, ip TEXT, method TEXT, path TEXT,
    ua TEXT, rules TEXT, score REAL, severity TEXT, source TEXT, label INTEGER DEFAULT NULL)"""


class Store:
    """Alert persistence. SQLite for now; swap this class to move to Postgres."""

    def __init__(self, path: str = "data/alerts.db"):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        self.db.execute(SCHEMA)
        try:
            self.db.execute("ALTER TABLE alerts ADD COLUMN label INTEGER DEFAULT NULL")
        except Exception:
            pass
        try:
            self.db.execute("ALTER TABLE alerts ADD COLUMN body TEXT DEFAULT ''")
        except Exception:
            pass
        self.db.commit()

    def add(self, a: dict) -> dict:
        with self.lock:
            cur = self.db.execute(
                "INSERT INTO alerts (ts, ip, method, path, ua, rules, score, severity, source) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (a["ts"], a["ip"], a["method"], a["path"], a["ua"],
                 json.dumps(a["rules"]), a["score"], a["severity"], a["source"]))
            self.db.commit()
        return {**a, "id": cur.lastrowid}

    def recent(self, limit: int = 50) -> list:
        with self.lock:
            rows = self.db.execute(
                "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [{**dict(r), "rules": json.loads(r["rules"])} for r in rows]

    def feedback(self, alert_id: int, label: int) -> None:
        """Active-learning hook: 1=attack, 0=benign. Powers next retrain."""
        with self.lock:
            self.db.execute("UPDATE alerts SET label=? WHERE id=?", (int(label), int(alert_id)))
            self.db.commit()

    def stats(self) -> dict:
        with self.lock:
            q = self.db.execute
            total = q("SELECT COUNT(*) FROM alerts").fetchone()[0]
            sev = {r[0]: r[1] for r in q("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")}
            src = {r[0]: r[1] for r in q("SELECT source, COUNT(*) FROM alerts GROUP BY source")}
            top = [{"ip": r[0], "count": r[1]} for r in q(
                "SELECT ip, COUNT(*) c FROM alerts GROUP BY ip ORDER BY c DESC LIMIT 5")]
        return {"total": total, "by_severity": sev, "by_source": src, "top_ips": top}
