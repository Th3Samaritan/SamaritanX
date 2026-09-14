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
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

# bump when the schema changes; recorded in run manifests for reproducibility
SCHEMA_VERSION = 9


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
CREATE TABLE IF NOT EXISTS execution_contexts (
    target TEXT, execution_key TEXT, context TEXT, PRIMARY KEY(target,execution_key)
);
CREATE TABLE IF NOT EXISTS finding_lifecycle (
    finding_id INTEGER PRIMARY KEY, state TEXT NOT NULL, updated REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS finding_history (
    id INTEGER PRIMARY KEY, finding_id INTEGER, state TEXT, snapshot TEXT, updated REAL
);
CREATE TABLE IF NOT EXISTS scanner_tasks (
    target TEXT NOT NULL,
    task_key TEXT NOT NULL,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL,
    PRIMARY KEY (target, task_key)
);
CREATE TABLE IF NOT EXISTS scanner_executions (
    target TEXT NOT NULL,
    execution_key TEXT NOT NULL,
    scanner TEXT NOT NULL,
    url TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT NOT NULL,
    attempts INTEGER NOT NULL,
    requests INTEGER NOT NULL,
    updated REAL NOT NULL,
    PRIMARY KEY (target, execution_key)
);
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

CREATE TABLE IF NOT EXISTS finding_groups (
    group_id    TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    label       TEXT NOT NULL DEFAULT '',
    note        TEXT NOT NULL DEFAULT '',
    created     REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS finding_group_members (
    group_id    TEXT NOT NULL,
    finding_id  INTEGER NOT NULL,
    role        TEXT NOT NULL DEFAULT 'member',
    added       REAL NOT NULL,
    PRIMARY KEY (group_id, finding_id)
);

CREATE TABLE IF NOT EXISTS group_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id    TEXT,
    action      TEXT,
    finding_id  INTEGER,
    detail      TEXT,
    updated     REAL
);
"""


class Memory:
    def record_execution_context(self, target, key, context):
        with self._lock, self._connect() as conn:
            conn.execute("INSERT OR REPLACE INTO execution_contexts VALUES (?,?,?)", (target, key, json.dumps(context)))

    def set_finding_state(self, finding_id, state, note=""):
        if state not in {"new", "confirmed", "fixed", "reopened", "inconclusive"}:
            raise ValueError("invalid finding state")
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
            if not row:
                raise ValueError("finding not found")
            conn.execute("INSERT OR REPLACE INTO finding_lifecycle VALUES (?,?,?)", (finding_id, state, time.time()))
            conn.execute("INSERT INTO finding_history(finding_id,state,snapshot,updated) VALUES (?,?,?,?)",
                         (finding_id, state, json.dumps({"finding": dict(row), "note": note}), time.time()))

    def finding_states(self, target):
        with self._connect() as conn:
            return {r["finding_id"]: r["state"] for r in conn.execute(
                "SELECT l.finding_id,l.state FROM finding_lifecycle l JOIN findings f ON f.id=l.finding_id WHERE f.target=?", (target,))}

    def finding_history(self, finding_id):
        with self._connect() as conn:
            return [dict(r) for r in conn.execute("SELECT state,snapshot,updated FROM finding_history WHERE finding_id=? ORDER BY id", (finding_id,))]

    # ---------- conservative cross-tool grouping (plan 11.11) ----------
    def create_group(self, target, finding_ids, *, label="", note="", canonical_id=None):
        """Relate independently-stored findings to one canonical review item.

        Observations are never deleted; membership is reversible through
        ``dissolve_group``/``remove_group_member`` and every action is written
        to ``group_history`` for audit."""
        ids = sorted({int(fid) for fid in finding_ids})
        if len(ids) < 2:
            raise ValueError("a group needs at least two findings")
        owned = {r["id"] for r in self.list_findings(target)}
        unknown = [fid for fid in ids if fid not in owned]
        if unknown:
            raise ValueError(f"findings not in target {target}: {unknown}")
        canonical = int(canonical_id) if canonical_id is not None else ids[0]
        if canonical not in ids:
            raise ValueError("canonical finding must be a group member")
        group_id = "g" + uuid.uuid4().hex[:12]
        now = time.time()
        with self._lock, self._connect() as conn:
            conn.execute("INSERT INTO finding_groups (group_id,target,label,note,created) VALUES (?,?,?,?,?)",
                         (group_id, target, label, note, now))
            for fid in ids:
                conn.execute("INSERT INTO finding_group_members (group_id,finding_id,role,added) VALUES (?,?,?,?)",
                             (group_id, fid, "canonical" if fid == canonical else "member", now))
            conn.execute("INSERT INTO group_history (group_id,action,finding_id,detail,updated) VALUES (?,?,?,?,?)",
                         (group_id, "create", canonical,
                          json.dumps({"members": ids, "label": label}), now))
        return group_id

    def add_group_member(self, group_id, finding_id, role="member"):
        with self._lock, self._connect() as conn:
            exists = conn.execute("SELECT 1 FROM finding_groups WHERE group_id=?", (group_id,)).fetchone()
            if not exists:
                raise ValueError("group not found")
            conn.execute("INSERT OR REPLACE INTO finding_group_members (group_id,finding_id,role,added) VALUES (?,?,?,?)",
                         (group_id, int(finding_id), role, time.time()))
            conn.execute("INSERT INTO group_history (group_id,action,finding_id,detail,updated) VALUES (?,?,?,?,?)",
                         (group_id, "add", int(finding_id), role, time.time()))

    def remove_group_member(self, group_id, finding_id):
        """Split one finding out of a group; a group of one dissolves itself."""
        with self._lock, self._connect() as conn:
            cur = conn.execute("DELETE FROM finding_group_members WHERE group_id=? AND finding_id=?",
                               (group_id, int(finding_id)))
            if cur.rowcount:
                conn.execute("INSERT INTO group_history (group_id,action,finding_id,detail,updated) VALUES (?,?,?,?,?)",
                             (group_id, "remove", int(finding_id), "", time.time()))
            remaining = conn.execute("SELECT COUNT(*) FROM finding_group_members WHERE group_id=?",
                                     (group_id,)).fetchone()[0]
            if remaining < 2:
                conn.execute("DELETE FROM finding_groups WHERE group_id=?", (group_id,))
        return bool(cur.rowcount)

    def dissolve_group(self, group_id):
        """Undo a manual grouping — findings and their evidence are untouched."""
        with self._lock, self._connect() as conn:
            exists = conn.execute("SELECT 1 FROM finding_groups WHERE group_id=?", (group_id,)).fetchone()
            if not exists:
                return False
            conn.execute("DELETE FROM finding_group_members WHERE group_id=?", (group_id,))
            conn.execute("DELETE FROM finding_groups WHERE group_id=?", (group_id,))
            conn.execute("INSERT INTO group_history (group_id,action,finding_id,detail,updated) VALUES (?,?,?,?,?)",
                         (group_id, "dissolve", None, "", time.time()))
        return True

    def list_groups(self, target):
        with self._connect() as conn:
            groups = [dict(r) for r in conn.execute(
                "SELECT group_id,label,note,created FROM finding_groups WHERE target=? ORDER BY created",
                (target,))]
            rows = conn.execute(
                "SELECT m.group_id,m.finding_id,m.role FROM finding_group_members m "
                "JOIN finding_groups g ON g.group_id=m.group_id WHERE g.target=?", (target,)).fetchall()
        by_group: dict[str, list] = {}
        for row in rows:
            by_group.setdefault(row["group_id"], []).append(
                {"finding_id": row["finding_id"], "role": row["role"]})
        for group in groups:
            group["members"] = sorted(by_group.get(group["group_id"], []),
                                      key=lambda m: m["finding_id"])
        return groups

    def groups_for_finding(self, finding_id):
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT g.group_id,g.label,m.role FROM finding_group_members m "
                "JOIN finding_groups g ON g.group_id=m.group_id WHERE m.finding_id=? ORDER BY g.created",
                (finding_id,)).fetchall()
        return [dict(r) for r in rows]

    def group_history(self, group_id):
        with self._connect() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT action,finding_id,detail,updated FROM group_history WHERE group_id=? ORDER BY id",
                (group_id,))]

    def remember_scan_task(self, target, kind, payload):
        encoded = json.dumps(payload, sort_keys=True)
        key = hashlib.sha256((kind + encoded).encode()).hexdigest()
        with self._lock, self._connect() as conn:
            conn.execute("INSERT OR REPLACE INTO scanner_tasks VALUES (?,?,?,?)",
                         (target, key, kind, encoded))

    def remembered_scan_tasks(self, target):
        with self._connect() as conn:
            rows = conn.execute("SELECT kind,payload FROM scanner_tasks WHERE target=?", (target,)).fetchall()
        return [(row["kind"], json.loads(row["payload"])) for row in rows]

    def record_execution(self, target, key, scanner, url, status, reason="", attempts=0,
                         requests=0, *, run_id="", exit_code=None, phase="",
                         startup_s=None, duration_s=None, diagnostics=""):
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO scanner_executions "
                "(target, execution_key, scanner, url, status, reason, attempts, requests, "
                " updated, run_id, exit_code, phase, startup_s, duration_s, diagnostics) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (target, key, scanner, url, status, reason, attempts, requests, time.time(),
                 run_id, exit_code, phase, startup_s, duration_s,
                 (diagnostics or "")[:2000]))

    def execution_summary(self, target):
        """Attempted / completed / incomplete counts for coverage reporting."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT status, COUNT(*) FROM scanner_executions WHERE target=? "
                "GROUP BY status", (target,)).fetchall()
        counts = {r["status"]: r[1] for r in rows}
        total = sum(counts.values())
        completed = counts.get("completed", 0)
        return {"attempted": total, "completed": completed,
                "incomplete": total - completed, "by_status": counts}

    def execution_reusable(self, target, key, max_age):
        with self._connect() as conn:
            row = conn.execute("SELECT status, updated FROM scanner_executions WHERE target=? AND execution_key=?",
                               (target, key)).fetchone()
        return bool(row and row["status"] == "completed" and time.time() - row["updated"] < max_age)

    def execution_coverage(self, target):
        with self._connect() as conn:
            rows = conn.execute("SELECT e.scanner,e.url,e.status,e.reason,e.attempts,e.requests,e.updated,c.context FROM scanner_executions e LEFT JOIN execution_contexts c ON e.target=c.target AND e.execution_key=c.execution_key WHERE e.target=? ORDER BY e.updated DESC",
                                (target,)).fetchall()
        records = [dict(r) for r in rows]
        for row in records:
            row["context"] = json.loads(row["context"]) if row["context"] else {}
        counts = {}
        for row in records:
            counts[row["status"]] = counts.get(row["status"], 0) + 1
        return {"counts": counts, "records": records,
                "scope": "Latest persisted scanner executions by context; not a complete inventory of undiscovered surface."}

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
            # structured-execution migrations (plan 11.3) — additive, preserving
            # historical rows
            for col, decl in (
                ("run_id", "TEXT NOT NULL DEFAULT ''"),
                ("exit_code", "INTEGER"),
                ("phase", "TEXT NOT NULL DEFAULT ''"),
                ("startup_s", "REAL"),
                ("duration_s", "REAL"),
                ("diagnostics", "TEXT NOT NULL DEFAULT ''"),
            ):
                try:
                    conn.execute(f"ALTER TABLE scanner_executions ADD COLUMN {col} {decl}")
                except Exception:
                    pass
        # ordered, transactional migrations with pre-upgrade backup (plan 11.9)
        try:
            from .migrations import migrate
            migrate(self.db_path, target=SCHEMA_VERSION)
        except Exception as exc:
            try:
                from .logger import get_logger
                get_logger("memory").warning(
                    "migration failed (old database preserved): %s", exc)
            except Exception:
                pass


    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            if conn.in_transaction:
                conn.commit()
        except BaseException:
            if conn.in_transaction:
                conn.rollback()
            raise
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
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT * FROM findings WHERE target=? AND fingerprint=?",
                (finding["target"], fp),
            ).fetchone()
            if existing:
                fid = int(existing["id"])
                old = conn.execute("SELECT state FROM finding_lifecycle WHERE finding_id=?", (fid,)).fetchone()
                conn.execute("INSERT INTO finding_history(finding_id,state,snapshot,updated) VALUES (?,?,?,?)",
                             (fid, old["state"] if old else "new", json.dumps(dict(existing)), time.time()))
                from core.proof_gate import is_verified
                state = "reopened" if old and old["state"] == "fixed" and is_verified(finding) else "new"
                if state == "new" and old:
                    state = "inconclusive"
                conn.execute("UPDATE findings SET metadata=?, evidence=?, request=?, response=?, confidence=?, discovered=?, payload=?, severity=?, cvss=? WHERE id=?",
                             (json.dumps(finding["metadata"]), finding.get("evidence"), finding.get("request"),
                              finding.get("response"), finding["confidence"], finding["discovered"],
                              finding.get("payload"), finding.get("severity", "info"), float(finding.get("cvss", 0)), fid))
                conn.execute("INSERT OR REPLACE INTO finding_lifecycle VALUES (?,?,?)", (fid, state, time.time()))
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
            fid = int(cur.lastrowid)
            conn.execute("INSERT OR REPLACE INTO finding_lifecycle VALUES (?,'new',?)", (fid, time.time()))
            return fid

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
            conn.execute("BEGIN IMMEDIATE")
            if set(updates) & {"metadata", "request", "response", "evidence"}:
                previous = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
                if previous:
                    state = conn.execute("SELECT state FROM finding_lifecycle WHERE finding_id=?", (finding_id,)).fetchone()
                    conn.execute("INSERT INTO finding_history(finding_id,state,snapshot,updated) VALUES (?,?,?,?)",
                                 (finding_id, state["state"] if state else "new", json.dumps(dict(previous)), time.time()))
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
