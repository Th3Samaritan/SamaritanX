"""Explicit schema versions, transactional migrations and crash recovery
(plan §11.9).

Every store participates in a single versioned migration sequence driven by
SQLite's ``PRAGMA user_version``. Before any migration the database is backed
up with the SQLite online-backup API; each step runs inside one transaction,
so a failed migration leaves the old database usable and the backup is the
explicit rollback path. Historical rows are preserved — migrations are
strictly additive by policy.
"""
from __future__ import annotations

import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Any


# ordered by target version: version -> SQL statements (additive only)
MIGRATIONS: dict[int, list[str]] = {
    # v8: structured execution states (milestone 1) — recorded here so fresh
    # databases and pre-v8 databases converge on the same shape
    8: [
        "ALTER TABLE scanner_executions ADD COLUMN run_id TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE scanner_executions ADD COLUMN exit_code INTEGER",
        "ALTER TABLE scanner_executions ADD COLUMN phase TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE scanner_executions ADD COLUMN startup_s REAL",
        "ALTER TABLE scanner_executions ADD COLUMN duration_s REAL",
        "ALTER TABLE scanner_executions ADD COLUMN diagnostics TEXT NOT NULL DEFAULT ''",
    ],
}

TARGET_VERSION = max(MIGRATIONS) if MIGRATIONS else 0


def current_version(path: str | Path) -> int:
    with closing(sqlite3.connect(str(path), timeout=30)) as db:
        return db.execute("PRAGMA user_version").fetchone()[0]


def backup_db(path: str | Path) -> Path | None:
    """SQLite online backup — the rollback path for a failed migration."""
    src = Path(path)
    if not src.exists():
        return None
    dst = src.with_name(src.name + f".pre-migrate-v{current_version(src)}.bak")
    with closing(sqlite3.connect(str(dst), timeout=30)) as dest:
        with closing(sqlite3.connect(str(src), timeout=30)) as source:
            source.backup(dest)
    return dst


def migrate(path: str | Path, target: int = TARGET_VERSION) -> dict:
    """Bring the database up to `target`. Returns the migration record.

    On failure the partial transaction is rolled back and the exception
    propagates — the pre-migration backup remains for manual restore, so a
    failed migration never corrupts the old database."""
    path = str(path)
    old = current_version(path)
    if old >= target:
        return {"path": path, "from": old, "to": old, "applied": [], "backup": None}
    backup = backup_db(path)
    applied: list[int] = []
    with closing(sqlite3.connect(path, timeout=30, isolation_level=None)) as db:
        try:
            db.execute("BEGIN")
            for version in sorted(MIGRATIONS):
                if version <= old or version > target:
                    continue
                for stmt in MIGRATIONS[version]:
                    try:
                        db.execute(stmt)
                    except sqlite3.OperationalError as exc:
                        # duplicate column = already applied by the inline
                        # schema path — idempotent convergence
                        if "duplicate column" not in str(exc).lower():
                            raise
                applied.append(version)
            db.execute(f"PRAGMA user_version = {target}")
            db.execute("COMMIT")
        except Exception:
            try:
                db.execute("ROLLBACK")
            except Exception:
                pass
            raise
    return {"path": path, "from": old, "to": target, "applied": applied,
            "backup": str(backup) if backup else None}


def integrity_report(memory_path: str | Path) -> dict[str, Any]:
    """Offline integrity report: distinguish recoverable conditions from
    required manual action. Makes no network requests."""
    path = str(memory_path)
    out: dict[str, Any] = {"ok": True, "recoverable": [], "manual": [], "checks": []}
    if not Path(path).exists():
        out.update({"ok": False, "manual": ["database file does not exist"],
                    "checks": [("missing", "database file")]})
        return out
    try:
        with closing(sqlite3.connect(path, timeout=30)) as db:
            result = db.execute("PRAGMA integrity_check").fetchone()[0]
            out["checks"].append(("integrity_check", result))
            if result != "ok":
                out["ok"] = False
                out["manual"].append("integrity_check failed — restore from backup")
            version = db.execute("PRAGMA user_version").fetchone()[0]
            out["checks"].append(("schema_version", version))
            if version > TARGET_VERSION:
                out["manual"].append(
                    f"database schema ({version}) is newer than this build "
                    f"({TARGET_VERSION}) — upgrade the tool, do not downgrade in place")
            # expired job leases are recoverable (conservative requeue policy)
            try:
                expired = db.execute(
                    "SELECT COUNT(*) FROM jobs WHERE status='running' AND expires<=?",
                    (time.time(),)).fetchone()[0]
            except sqlite3.OperationalError:
                expired = 0
            if expired:
                out["recoverable"].append(
                    f"{expired} job lease(s) expired — recover() requeues only "
                    "replay-safe kinds, the rest need review")
            # uncertain mutation outcomes always need human review
            try:
                uncertain = db.execute(
                    "SELECT COUNT(*) FROM jobs WHERE status='interrupted'").fetchone()[0]
            except sqlite3.OperationalError:
                uncertain = 0
            if uncertain:
                out["manual"].append(
                    f"{uncertain} interrupted job(s) with unknown mutation outcome — "
                    "manual review required before retry")
    except sqlite3.Error as exc:
        out.update({"ok": False, "manual": [f"database open failed: {exc}"],
                    "checks": [("open", "failed")]})
    return out
