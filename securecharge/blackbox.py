"""Bounded, authenticated write-ahead custody journal for the Pi pilot.

No local success acknowledgement: a CALLRESULT is released only after a verified
CSMS receipt. A protected external anchor is necessary to detect tail rollback.
The HMAC journal provides integrity under protected keys, not non-repudiation.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
import sqlite3
import threading
import time
import uuid

from . import security
from .keys import Keyring
from .messages import OcppCall
from .serialization import canonical_json, parse_json
from .transport import Envelope

CONTEXT = b"SecureCharge/blackbox/v1\x00"
ZERO = "0" * 64
CALL_LIMIT = 16384


class JournalError(ValueError):
    pass


class QueueFull(JournalError):
    pass


class RequestConflict(JournalError):
    pass


class BlackBox:
    def __init__(self, path: str | Path, keyring: Keyring, *, capacity: int = 5000):
        if capacity < 1:
            raise ValueError("capacity must be positive")
        self.path, self.keyring, self.capacity = Path(path), keyring, capacity
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS identity (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS events (
                seq INTEGER PRIMARY KEY, previous TEXT NOT NULL, kid TEXT NOT NULL,
                body TEXT NOT NULL, tag TEXT NOT NULL);
        """)
        self.db.execute("INSERT OR IGNORE INTO identity VALUES (1,?)", (uuid.uuid4().hex,))
        self.journal_id = self.db.execute("SELECT value FROM identity WHERE id=1").fetchone()[0]
        try:
            self.snapshot()
        except BaseException:
            self.db.close()
            raise

    def _tag(self, seq, previous, kid, body):
        key = self.keyring.key(kid)
        if key is None:
            raise JournalError("journal verification key unavailable; preserve retired verification keys")
        encoded = canonical_json(
            {"journal": self.journal_id, "seq": seq, "previous": previous, "kid": kid, "body": body}
        )
        return hmac.new(key, CONTEXT + encoded, hashlib.sha3_256).hexdigest()

    def snapshot(self, anchor: dict | None = None) -> dict:
        with self.lock:
            requests, seen, head, count = {}, {}, ZERO, 0
            for row in self.db.execute("SELECT * FROM events ORDER BY seq"):
                count += 1
                if count > 2 * self.capacity:
                    raise JournalError("journal exceeds configured capacity")
                try:
                    body = parse_json(row["body"])
                    expected = self._tag(count, head, row["kid"], body)
                    if row["seq"] != count or row["previous"] != head or not hmac.compare_digest(row["tag"], expected):
                        raise JournalError("journal authentication/sequence failure")
                    if body["kind"] == "queued":
                        call = OcppCall.from_frame(body["call"]).validate()
                        identity = (body["cp"], call.unique_id)
                        if (
                            identity in seen
                            or body["id"] in requests
                            or not self.keyring.authorized(row["kid"], body["cp"])
                        ):
                            raise JournalError("duplicate or unauthorized journal request")
                        seen[identity] = body["id"]
                        requests[body["id"]] = {**body, "response": None}
                    elif body["kind"] == "confirmed":
                        original = requests[body["id"]]
                        request = Envelope.from_frame(body["request"])
                        if original["response"] is not None or request.to_frame()["ocpp"] != original["call"]:
                            raise JournalError("receipt does not match queued call")
                        if request.security["cp"] != original["cp"]:
                            raise JournalError("receipt charger mismatch")
                        # Historical receipt verification; timestamp checks at original receipt time.
                        frame = security.verify_reply(body["reply"], request, self.keyring, body["received_at"])
                        original["response"] = frame
                    else:
                        raise JournalError("unknown journal event")
                except (KeyError, TypeError, ValueError) as exc:
                    raise JournalError(f"invalid journal event {count}: {exc}") from None
                head = row["tag"]
                if anchor is not None and count == anchor.get("sequence") and head != anchor.get("head"):
                    raise JournalError("external anchor mismatch")
            if anchor is not None:
                if anchor.get("journal") != self.journal_id or type(anchor.get("sequence")) is not int:
                    raise JournalError("invalid external anchor")
                if anchor["sequence"] > count or anchor["sequence"] < 0:
                    raise JournalError("journal truncated before external anchor")
                if anchor["sequence"] == 0 and anchor.get("head") != ZERO:
                    raise JournalError("invalid empty anchor")
            return {"journal": self.journal_id, "sequence": count, "head": head, "requests": requests}

    def _append(self, state, body):
        seq, kid = state["sequence"] + 1, self.keyring.active_kid
        tag = self._tag(seq, state["head"], kid, body)
        self.db.execute(
            "INSERT INTO events VALUES (?,?,?,?,?)", (seq, state["head"], kid, canonical_json(body).decode(), tag)
        )

    def _mutate(self, action):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                result = action(self.snapshot())
                self.db.execute("COMMIT")
                return result
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def enqueue(self, call: OcppCall, cp: str) -> str:
        call.validate()
        if not self.keyring.authorized(self.keyring.active_kid, cp):
            raise JournalError("charger not owned by gateway key")
        if len(canonical_json(call.to_frame())) > CALL_LIMIT:
            raise JournalError("pilot CALL exceeds 16 KiB")

        def insert(state):
            for item in state["requests"].values():
                if item["cp"] == cp and item["call"][1] == call.unique_id:
                    if item["call"] != call.to_frame():
                        raise RequestConflict("request ID reused with different data")
                    return item["id"]
            if len(state["requests"]) >= self.capacity:
                raise QueueFull("journal capacity reached; export/anchor and rotate under operator control")
            identifier = uuid.uuid4().hex
            self._append(
                state,
                {"kind": "queued", "id": identifier, "cp": cp, "call": call.to_frame(), "created_at": int(time.time())},
            )
            return identifier

        return self._mutate(insert)

    def confirm(self, identifier: str, request: Envelope, reply: dict, now: int) -> list:
        def insert(state):
            original = state["requests"][identifier]
            if original["response"] is not None:
                return original["response"]
            if original["call"] != request.call.to_frame() or original["cp"] != request.security["cp"]:
                raise JournalError("confirmation does not match custody record")
            frame = security.verify_reply(reply, request, self.keyring, now)
            self._append(
                state,
                {
                    "kind": "confirmed",
                    "id": identifier,
                    "request": request.to_frame(),
                    "reply": reply,
                    "received_at": now,
                },
            )
            return frame

        return self._mutate(insert)

    def pending(self) -> list[dict]:
        return [item for item in self.snapshot()["requests"].values() if item["response"] is None]

    def response(self, identifier: str) -> list | None:
        return self.snapshot()["requests"][identifier]["response"]

    def anchor(self) -> dict:
        return {k: v for k, v in self.snapshot().items() if k != "requests"}

    def close(self):
        with self.lock:
            self.db.close()
