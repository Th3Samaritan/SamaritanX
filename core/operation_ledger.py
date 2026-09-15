"""Transactional operation accounting retained across interruptions and resume."""
import sqlite3
from contextlib import closing


class OperationLedger:
    def __init__(self, path, run_id, limit, reserves, *, resume=False):
        if not run_id:
            raise ValueError("durable operation accounting requires a run ID")
        self.path, self.run_id = str(path), run_id
        with closing(self._connect()) as db, db:
            db.execute("CREATE TABLE IF NOT EXISTS operation_runs (run_id TEXT PRIMARY KEY, budget INTEGER NOT NULL, baseline INTEGER NOT NULL, verification INTEGER NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS operation_usage (run_id TEXT NOT NULL, purpose TEXT NOT NULL, used INTEGER NOT NULL, PRIMARY KEY(run_id,purpose))")
            if resume and not db.execute("SELECT 1 FROM operation_runs WHERE run_id=?", (run_id,)).fetchone():
                raise ValueError("cannot resume without the original operation ledger; start a new run explicitly")
            db.execute("INSERT OR IGNORE INTO operation_runs VALUES (?,?,?,?)", (run_id, limit, reserves['baseline'], reserves['verification']))
            db.execute("UPDATE operation_runs SET budget=MIN(budget,?) WHERE run_id=?", (limit, run_id))
            row = db.execute("SELECT budget,baseline,verification FROM operation_runs WHERE run_id=?", (run_id,)).fetchone()
            self.limit = min(limit, row[0])
            self.reserves = dict(zip(('baseline','verification'), row[1:]))

    def _connect(self):
        return sqlite3.connect(self.path, timeout=30)

    def counts(self):
        with closing(self._connect()) as db:
            return dict(db.execute("SELECT purpose,used FROM operation_usage WHERE run_id=?", (self.run_id,)))

    def take(self, purpose):
        with closing(self._connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            self.limit = db.execute("SELECT budget FROM operation_runs WHERE run_id=?", (self.run_id,)).fetchone()[0]
            counts = dict(db.execute("SELECT purpose,used FROM operation_usage WHERE run_id=?", (self.run_id,)))
            if not available(counts, self.limit, self.reserves, purpose):
                return None
            db.execute("INSERT INTO operation_usage VALUES (?,?,1) ON CONFLICT(run_id,purpose) DO UPDATE SET used=used+1", (self.run_id,purpose))
            return sum(counts.values()) + 1


def available(counts, limit, reserves, purpose):
    protected = sum(max(0, amount - counts.get(name, 0))
                    for name, amount in reserves.items() if name != purpose)
    return sum(counts.values()) < limit - protected
