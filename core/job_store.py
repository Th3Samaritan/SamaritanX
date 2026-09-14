"""Durable queue leases with ownership checks and conservative crash recovery.

Expired work is retained for review unless its kind is explicitly replay-safe.
Lease fencing protects the job record; it cannot undo remote side effects.
"""
import json
import sqlite3
import time
import uuid
from contextlib import contextmanager


class JobStore:
    def __init__(self, path):
        self.path = str(path)
        with self.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS jobs (
                key TEXT PRIMARY KEY, target TEXT, kind TEXT, payload TEXT,
                priority INTEGER, status TEXT, owner TEXT, expires REAL,
                attempts INTEGER DEFAULT 0, reason TEXT DEFAULT '')""")

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def enqueue(self, key, target, kind, payload, priority):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT status FROM jobs WHERE key=?", (key,)).fetchone()
            if row and row["status"] in {"queued", "running"}:
                return False
            db.execute("INSERT OR REPLACE INTO jobs VALUES (?,?,?,?,?,'queued','',0,0,'')",
                       (key, target, kind, json.dumps(payload), priority))
        return True

    def claim(self, key, seconds):
        owner = uuid.uuid4().hex
        with self.connect() as db:
            cur = db.execute("UPDATE jobs SET status='running', owner=?, expires=?, attempts=attempts+1 WHERE key=? AND status='queued'",
                             (owner, time.time() + seconds, key))
        return owner if cur.rowcount else None

    def renew(self, key, owner, seconds):
        with self.connect() as db:
            cur = db.execute("UPDATE jobs SET expires=? WHERE key=? AND owner=? AND status='running' AND expires>?",
                             (time.time() + seconds, key, owner, time.time()))
        return bool(cur.rowcount)

    def finish(self, key, owner, status, reason=""):
        with self.connect() as db:
            cur = db.execute("UPDATE jobs SET status=?, reason=?, expires=0 WHERE key=? AND owner=? AND status='running' AND expires>?",
                             (status, reason, key, owner, time.time()))
        return bool(cur.rowcount)

    def recover(self, target, replay_safe=()):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            expired = db.execute("SELECT key,kind FROM jobs WHERE target=? AND status='running' AND expires<=?",
                                 (target, time.time())).fetchall()
            for row in expired:
                status = "queued" if row["kind"] in replay_safe else "interrupted"
                db.execute("UPDATE jobs SET status=?, owner='', reason='lease expired; execution outcome unknown' WHERE key=?",
                           (status, row["key"]))
            rows = db.execute("SELECT * FROM jobs WHERE target=? AND status='queued'", (target,)).fetchall()
        return [dict(row, payload=json.loads(row["payload"])) for row in rows]

    def list(self, target):
        with self.connect() as db:
            return [dict(r) for r in db.execute(
                "SELECT key,kind,status,attempts,reason FROM jobs WHERE target=?", (target,))]
