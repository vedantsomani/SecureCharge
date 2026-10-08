"""SQLite persistence: replay nonces, open transactions, billing ledger, audit log.

One connection is shared across threads (Streamlit uses several) behind a lock.
The replay check is the security-critical part: claiming a nonce is a single
INSERT against a PRIMARY KEY, so two copies of one message can never both win.
"""

from __future__ import annotations

import os
import json
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .verdict import Reason, Verdict

_SCHEMA = """
CREATE TABLE IF NOT EXISTS seen_nonces (
    nonce    TEXT NOT NULL,
    key_id   TEXT    NOT NULL,
    msg_ts   INTEGER NOT NULL,
    seen_at  INTEGER NOT NULL,
    PRIMARY KEY (key_id, nonce)
);
CREATE INDEX IF NOT EXISTS idx_seen_nonces_msg_ts ON seen_nonces (msg_ts);

CREATE TABLE IF NOT EXISTS transactions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    system          TEXT    NOT NULL CHECK (system IN ('legacy', 'securecharge')),
    charge_point_id TEXT    NOT NULL,
    connector_id    INTEGER NOT NULL,
    meter_start_wh  INTEGER NOT NULL,
    started_at      INTEGER NOT NULL,
    open            INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS ledger (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    system          TEXT    NOT NULL CHECK (system IN ('legacy', 'securecharge')),
    charge_point_id TEXT    NOT NULL,
    transaction_id  INTEGER NOT NULL,
    energy_wh       INTEGER NOT NULL,
    amount_paise    INTEGER NOT NULL,
    recorded_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    at              INTEGER NOT NULL,
    layer           TEXT    NOT NULL,
    accepted        INTEGER NOT NULL,
    legacy          INTEGER NOT NULL DEFAULT 0,  -- message carried no SHA-3 tag
    reason          TEXT    NOT NULL,
    charge_point_id TEXT,
    detail          TEXT    NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS unique_bill ON ledger (system, transaction_id);
CREATE UNIQUE INDEX IF NOT EXISTS unique_open_connector ON transactions (system, charge_point_id, connector_id) WHERE open = 1;
CREATE TABLE IF NOT EXISTS request_cache (
    charge_point_id TEXT NOT NULL, uid TEXT NOT NULL, digest TEXT NOT NULL,
    reason TEXT NOT NULL, facts TEXT, recorded_at INTEGER NOT NULL,
    PRIMARY KEY (charge_point_id, uid)
);
CREATE TABLE IF NOT EXISTS fleet_policy (
    charge_point_id TEXT PRIMARY KEY, enrolled_at INTEGER NOT NULL
);
"""


class Store:
    def __init__(self, path: str | os.PathLike[str] = ":memory:") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            try:
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(fd)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            if self.path != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.executescript(_SCHEMA)
            # Upgrade v1 databases without deleting retained replay evidence.
            columns = list(self._conn.execute("PRAGMA table_info(seen_nonces)"))
            if sum(bool(row["pk"]) for row in columns) == 1:
                self._conn.executescript("""
                    BEGIN IMMEDIATE;
                    ALTER TABLE seen_nonces RENAME TO seen_nonces_v1;
                    CREATE TABLE seen_nonces (nonce TEXT NOT NULL, key_id TEXT NOT NULL,
                        msg_ts INTEGER NOT NULL, seen_at INTEGER NOT NULL, PRIMARY KEY(key_id,nonce));
                    INSERT INTO seen_nonces SELECT nonce,key_id,msg_ts,seen_at FROM seen_nonces_v1;
                    DROP TABLE seen_nonces_v1;
                    CREATE INDEX idx_seen_nonces_msg_ts ON seen_nonces(msg_ts);
                    COMMIT;
                """)

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if self._conn.in_transaction:
                yield self._conn
                return
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")

    @contextmanager
    def atomic(self) -> Iterator[sqlite3.Connection]:
        """Serialize and commit a complete request, including nested store calls."""
        with self._transaction() as conn:
            yield conn

    def cached_request(self, cp: str, uid: str) -> dict[str, Any] | None:
        rows = self._rows("SELECT * FROM request_cache WHERE charge_point_id=? AND uid=?", (cp, uid))
        if not rows:
            return None
        row = rows[0]
        row["facts"] = json.loads(row["facts"]) if row["facts"] is not None else None
        return row

    def cache_request(self, cp: str, uid: str, digest: str, reason: Reason, facts: Any, now: int) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO request_cache VALUES (?,?,?,?,?,?)",
                (cp, uid, digest, reason.value, json.dumps(facts) if facts is not None else None, now),
            )

    def security_required(self, cp: str) -> bool:
        return bool(self._rows("SELECT 1 FROM fleet_policy WHERE charge_point_id=?", (cp,)))

    def require_security(self, cp: str, now: int) -> None:
        with self._lock:
            self._conn.execute("INSERT OR IGNORE INTO fleet_policy VALUES (?,?)", (cp, now))

    def fleet_rows(self) -> list[dict[str, Any]]:
        return self._rows("SELECT * FROM fleet_policy ORDER BY charge_point_id")

    def connector_open(self, system: str, cp: str, connector: int) -> bool:
        return bool(
            self._rows(
                "SELECT 1 FROM transactions WHERE system=? AND charge_point_id=? AND connector_id=? AND open=1",
                (system, cp, connector),
            )
        )

    # --- replay protection -------------------------------------------------

    def claim_nonce(self, *, nonce: str, key_id: str, msg_ts: int, now: int) -> bool:
        """Record a nonce the first time it is seen. False means it was already used."""
        with self._transaction() as conn:
            try:
                conn.execute(
                    "INSERT INTO seen_nonces (nonce, key_id, msg_ts, seen_at) VALUES (?, ?, ?, ?)",
                    (nonce, key_id, msg_ts, now),
                )
            except sqlite3.IntegrityError:
                return False
        return True

    def purge_nonces(self, older_than: int) -> int:
        """Forget nonces so old their messages would fail the freshness check anyway."""
        with self._lock:
            return self._conn.execute("DELETE FROM seen_nonces WHERE msg_ts < ?", (older_than,)).rowcount

    # --- transactions and billing -----------------------------------------

    def open_transaction(
        self, *, system: str, charge_point_id: str, connector_id: int, meter_start_wh: int, at: int
    ) -> int:
        """Record a StartTransaction and return the CSMS-assigned transaction id."""
        with self._transaction() as conn:
            cur = conn.execute(
                "INSERT INTO transactions (system, charge_point_id, connector_id, meter_start_wh, started_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (system, charge_point_id, connector_id, meter_start_wh, at),
            )
            return int(cur.lastrowid)

    def open_meter_start(self, system: str, transaction_id: int, charge_point_id: str) -> int | None:
        rows = self._rows(
            "SELECT meter_start_wh FROM transactions WHERE system = ? AND id = ? AND charge_point_id = ? AND open = 1",
            (system, transaction_id, charge_point_id),
        )
        return rows[0]["meter_start_wh"] if rows else None

    def close_transaction(
        self, *, system: str, transaction_id: int, charge_point_id: str, energy_wh: int, amount_paise: int, at: int
    ) -> bool:
        with self._transaction() as conn:
            changed = conn.execute(
                "UPDATE transactions SET open = 0 WHERE system = ? AND id = ? AND charge_point_id = ? AND open = 1",
                (system, transaction_id, charge_point_id),
            )
            if changed.rowcount != 1:
                return False
            conn.execute(
                "INSERT INTO ledger (system, charge_point_id, transaction_id, energy_wh, amount_paise, recorded_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (system, charge_point_id, transaction_id, energy_wh, amount_paise, at),
            )
            return True

    # --- audit -------------------------------------------------------------

    def log(self, verdict: Verdict, *, at: int, charge_point_id: str | None = None) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit_log (at, layer, accepted, legacy, reason, charge_point_id, detail)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    at,
                    verdict.layer.value,
                    int(verdict.accepted),
                    int(verdict.legacy),
                    verdict.reason.value,
                    (charge_point_id or "")[:40] or None,
                    verdict.detail[:300],
                ),
            )

    # --- queries -----------------------------------------------------------

    def _rows(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(row) for row in self._conn.execute(sql, params)]

    def audit_rows(self, limit: int = 200) -> list[dict[str, Any]]:
        return self._rows("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))

    def ledger_rows(self, system: str | None = None) -> list[dict[str, Any]]:
        if system is None:
            return self._rows("SELECT * FROM ledger ORDER BY id DESC")
        return self._rows("SELECT * FROM ledger WHERE system = ? ORDER BY id DESC", (system,))

    def nonce_count(self) -> int:
        return self._rows("SELECT COUNT(*) AS n FROM seen_nonces")[0]["n"]

    def migration_stats(self) -> dict[str, int]:
        """Counts the migration dashboard shows: legacy vs upgraded, per outcome."""
        out = {"nonces": self.nonce_count(), "legacy_messages": 0, "upgraded_messages": 0}
        for row in self._rows(
            "SELECT legacy, accepted, COUNT(*) AS n FROM audit_log"
            " WHERE layer = 'secure-csms' GROUP BY legacy, accepted"
        ):
            bucket = "legacy_messages" if row["legacy"] else "upgraded_messages"
            out[bucket] += row["n"]
            key = f"{'legacy' if row['legacy'] else 'upgraded'}:{'accepted' if row['accepted'] else 'rejected'}"
            out[key] = row["n"]
        return out

    def reset(self) -> None:
        with self._transaction() as conn:
            for table in ("seen_nonces", "transactions", "ledger", "audit_log", "request_cache", "fleet_policy"):
                conn.execute(f"DELETE FROM {table}")

    def close(self) -> None:
        with self._lock:
            self._conn.close()
