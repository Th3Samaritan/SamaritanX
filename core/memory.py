"""Persistent memory layer.

Stores findings, payload effectiveness scores, scan-resume cursors, and
per-target intelligence so SamaritanX can learn — and resume — across runs.
SQLite is used so there are no external dependencies and a single .sqlite
file is portable across hosts.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


def _fingerprint(finding: dict[str, Any]) -> str:
    """Stable hash so the same bug isn't recorded twice on re-runs."""
    parts = [
        finding.get("target") or "",
        finding.get("category") or "",
        finding.get("url") or "",
        finding.get("parameter") or "",
        # title strips dynamic tokens by trimming after last colon/space digit
        (finding.get("title") or "").lower(),
    ]
    return hashlib.sha1("||".join(parts).encode("utf-8")).hexdigest()


SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    slug        TEXT UNIQUE NOT NULL,
    root        TEXT NOT NULL,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    metadata    TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT NOT NULL,
    category    TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    cvss        REAL NOT NULL DEFAULT 0,
    url         TEXT,
    parameter   TEXT,
    payload     TEXT,
    evidence    TEXT,
    request     TEXT,
    response    TEXT,
    discovered  INTEGER NOT NULL,
    fingerprint TEXT,
    confidence  REAL NOT NULL DEFAULT 0.5,
    metadata    TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_fingerprint
    ON findings(target, fingerprint) WHERE fingerprint IS NOT NULL;

CREATE TABLE IF NOT EXISTS scan_state (
    target      TEXT PRIMARY KEY,
    cursor      TEXT NOT NULL DEFAULT '{}',
    completed   TEXT NOT NULL DEFAULT '[]',
    updated     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS payload_stats (
    payload     TEXT NOT NULL,
    category    TEXT NOT NULL,
    hits        INTEGER NOT NULL DEFAULT 0,
    misses      INTEGER NOT NULL DEFAULT 0,
    last_used   INTEGER NOT NULL,
    PRIMARY KEY (payload, category)
);

CREATE TABLE IF NOT EXISTS assets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT NOT NULL,
    kind        TEXT NOT NULL,
    value       TEXT NOT NULL,
    metadata    TEXT NOT NULL DEFAULT '{}',
    discovered  INTEGER NOT NULL,
    UNIQUE (target, kind, value)
);

CREATE TABLE IF NOT EXISTS processed_urls (
    target      TEXT NOT NULL,
    url         TEXT NOT NULL,
    phase       TEXT NOT NULL,
    processed   INTEGER NOT NULL,
    PRIMARY KEY (target, url, phase)
);

CREATE TABLE IF NOT EXISTS url_fingerprints (
    target      TEXT NOT NULL,
    url         TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    updated     INTEGER NOT NULL,
    PRIMARY KEY (target, url)
);
"""


class Memory:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._connect() as conn:
            conn.executescript(SCHEMA)
            try:
                conn.execute("ALTER TABLE findings ADD COLUMN confidence REAL NOT NULL DEFAULT 0.5")
            except Exception:
                pass  # column already exists


    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    # ---------- targets ----------
    def upsert_target(self, slug: str, root: str, metadata: dict[str, Any] | None = None) -> None:
        now = int(time.time())
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO targets (slug, root, first_seen, last_seen, metadata)
                VALUES (?,?,?,?,?)
                ON CONFLICT(slug) DO UPDATE SET last_seen=excluded.last_seen,
                                                metadata=excluded.metadata
                """,
                (slug, root, now, now, json.dumps(metadata or {})),
            )

    # ---------- findings ----------
    def record_finding(self, finding: dict[str, Any]) -> int:
        """Insert a finding, deduplicated on (target, fingerprint).
        Returns existing row id if the same finding was already recorded."""
        finding = dict(finding)
        finding.setdefault("discovered", int(time.time()))
        finding.setdefault("metadata", {})
        if "confidence" not in finding:
            try:
                from .confidence import assign
                finding["confidence"] = round(assign(finding)[0], 2)
            except Exception:
                finding["confidence"] = 0.5
        fp = _fingerprint(finding)
        with self._lock, self._connect() as conn:
            existing = conn.execute(
                "SELECT id FROM findings WHERE target=? AND fingerprint=?",
                (finding["target"], fp),
            ).fetchone()
            if existing:
                return int(existing["id"])
            cur = conn.execute(
                """
                INSERT INTO findings
                    (target, category, title, severity, cvss, url, parameter,
                     payload, evidence, request, response, discovered,
                     fingerprint, confidence, metadata)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    finding["target"],
                    finding["category"],
                    finding["title"],
                    finding.get("severity", "info"),
                    float(finding.get("cvss", 0)),
                    finding.get("url"),
                    finding.get("parameter"),
                    finding.get("payload"),
                    finding.get("evidence"),
                    finding.get("request"),
                    finding.get("response"),
                    finding["discovered"],
                    fp,
                    float(finding.get("confidence", 0.5)),
                    json.dumps(finding.get("metadata") or {}),
                ),
            )
            return int(cur.lastrowid)

    def update_finding(self, finding_id: int, **fields) -> None:
        """Update fields on an existing finding. Thread-safe, uses parameterized queries."""
        al_lowed = {"severity", "cvss", "title", "metadata", "evidence", "url",
                    "category", "parameter", "payload", "request", "response", "confidence"}
        updates = {k: v for k, v in fields.items() if k in al_lowed}
        if not updates:
            return
        if "metadata" in updates and not isinstance(updates["metadata"], str):
            updates["metadata"] = json.dumps(updates["metadata"])
        set_clause = ", ".join(f"{k}=?" for k in updates)
        values = list(updates.values()) + [finding_id]
        with self._lock, self._connect() as conn:
            conn.execute(
                f"UPDATE findings SET {set_clause} WHERE id=?",
                values,
            )

    def has_finding(self, target: str, finding: dict[str, Any]) -> bool:
        fp = _fingerprint({**finding, "target": target})
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM findings WHERE target=? AND fingerprint=?",
                (target, fp),
            ).fetchone()
            return bool(row)

    # ---------- resume support ----------
    def mark_completed(self, target: str, key: str) -> None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT completed FROM scan_state WHERE target=?", (target,),
            ).fetchone()
            done = json.loads(row["completed"]) if row else []
            if key not in done:
                done.append(key)
            if row:
                conn.execute(
                    "UPDATE scan_state SET completed=?, updated=? WHERE target=?",
                    (json.dumps(done), int(time.time()), target),
                )
            else:
                conn.execute(
                    "INSERT INTO scan_state (target, cursor, completed, updated) "
                    "VALUES (?,?,?,?)",
                    (target, "{}", json.dumps(done), int(time.time())),
                )

    def is_completed(self, target: str, key: str) -> bool:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT completed FROM scan_state WHERE target=?", (target,),
            ).fetchone()
            if not row:
                return False
            return key in json.loads(row["completed"])

    def reset_scan_state(self, target: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM scan_state WHERE target=?", (target,))

    def list_findings(self, target: str | None = None) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            if target:
                rows = conn.execute(
                    "SELECT * FROM findings WHERE target=? ORDER BY discovered DESC",
                    (target,),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM findings ORDER BY discovered DESC").fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["metadata"] = json.loads(d["metadata"] or "{}")
                out.append(d)
            return out

    # ---------- assets ----------
    def add_asset(self, target: str, kind: str, value: str, metadata: dict | None = None) -> bool:
        with self._lock, self._connect() as conn:
            try:
                conn.execute(
                    "INSERT INTO assets (target, kind, value, metadata, discovered) VALUES (?,?,?,?,?)",
                    (target, kind, value, json.dumps(metadata or {}), int(time.time())),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def list_assets(self, target: str, kind: str | None = None) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            q = "SELECT * FROM assets WHERE target=?"
            args: tuple = (target,)
            if kind:
                q += " AND kind=?"
                args = (target, kind)
            rows = conn.execute(q + " ORDER BY discovered DESC", args).fetchall()
            return [dict(r) for r in rows]

    # ---------- payload learning ----------
    def record_payload_result(self, payload: str, category: str, hit: bool) -> None:
        now = int(time.time())
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO payload_stats (payload, category, hits, misses, last_used)
                VALUES (?,?,?,?,?)
                ON CONFLICT(payload, category) DO UPDATE SET
                    hits = hits + excluded.hits,
                    misses = misses + excluded.misses,
                    last_used = excluded.last_used
                """,
                (payload, category, 1 if hit else 0, 0 if hit else 1, now),
            )

    def best_payloads(self, category: str, limit: int = 25) -> list[str]:
        """Return payloads sorted by hit-rate (Wilson lower bound) for a category."""
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT payload, hits, misses FROM payload_stats WHERE category=?",
                (category,),
            ).fetchall()
        scored = []
        for r in rows:
            n = r["hits"] + r["misses"]
            if n == 0:
                continue
            p = r["hits"] / n
            # Wilson score interval lower bound (z=1.96)
            z = 1.96
            denom = 1 + z * z / n
            centre = (p + z * z / (2 * n)) / denom
            margin = (z * ((p * (1 - p) + z * z / (4 * n)) / n) ** 0.5) / denom
            scored.append((centre - margin, r["payload"]))
        scored.sort(reverse=True)
        return [p for _, p in scored[:limit]]

    # ---------- mid-phase resumability ----------
    def mark_url_processed(self, target: str, url: str, phase: str) -> None:
        """Record that a URL was already processed in a given phase so
        resume can skip it."""
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO processed_urls (target, url, phase, processed) "
                "VALUES (?,?,?,?)",
                (target, url, phase, int(time.time())),
            )

    def is_url_processed(self, target: str, url: str, phase: str) -> bool:
        """Check if a URL was already handled in a given phase."""
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM processed_urls WHERE target=? AND url=? AND phase=?",
                (target, url, phase),
            ).fetchone()
            return bool(row)

    def clear_processed_urls(self, target: str, phase: str | None = None) -> None:
        """Clear processed URL bookmarks so a fresh scan runs everything."""
        with self._lock, self._connect() as conn:
            if phase:
                conn.execute(
                    "DELETE FROM processed_urls WHERE target=? AND phase=?",
                    (target, phase),
                )
            else:
                conn.execute("DELETE FROM processed_urls WHERE target=?", (target,))

    # ---------- incremental scanning ----------
    def set_url_fingerprint(self, target: str, url: str, fingerprint: str) -> None:
        """Record the content fingerprint observed when a URL was scanned."""
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO url_fingerprints (target, url, fingerprint, updated) "
                "VALUES (?,?,?,?) "
                "ON CONFLICT(target, url) DO UPDATE SET "
                "fingerprint=excluded.fingerprint, updated=excluded.updated",
                (target, url, fingerprint, int(time.time())),
            )

    def get_url_fingerprint(self, target: str, url: str) -> str | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT fingerprint FROM url_fingerprints WHERE target=? AND url=?",
                (target, url),
            ).fetchone()
            return str(row["fingerprint"]) if row else None
