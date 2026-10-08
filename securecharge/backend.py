"""SC2 verification, durable per-charger migration and atomic request effects."""

from __future__ import annotations
import sqlite3
from enum import Enum
from typing import Any
from . import billing, security
from .clock import Clock, SystemClock
from .crypto import sha3_256_hex
from .keys import Keyring
from .legacy import CHECKSUMS, check_integrity
from .messages import MessageError
from .serialization import CanonicalizationError, canonical_json
from .transport import Envelope
from .storage import Store
from .verdict import Layer, Reason, Verdict

DEFAULT_TTL_SECONDS = 120
DEFAULT_MAX_SKEW_SECONDS = 30
PURGE_INTERVAL_SECONDS = 60


class Mode(str, Enum):
    MONITOR = "monitor"
    WARN = "warn"
    ENFORCE = "enforce"


class SecureCsms:
    def __init__(
        self,
        keyring: Keyring,
        store: Store,
        clock: Clock | None = None,
        mode: Mode | str = Mode.ENFORCE,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        max_skew_seconds: int = DEFAULT_MAX_SKEW_SECONDS,
        legacy_algorithm: str = "md5",
    ) -> None:
        if (
            type(ttl_seconds) is not int
            or ttl_seconds <= 0
            or type(max_skew_seconds) is not int
            or max_skew_seconds < 0
        ):
            raise ValueError("TTL must be positive and skew non-negative integers")
        if legacy_algorithm not in CHECKSUMS:
            raise ValueError("unknown legacy algorithm")
        self.keyring, self.store, self.clock = keyring, store, clock or SystemClock()
        self.mode = Mode(mode)
        self.ttl_seconds, self.max_skew_seconds = ttl_seconds, max_skew_seconds
        self.legacy_algorithm = legacy_algorithm
        self._last_purge: int | None = None

    def receive(self, frame: Any, charge_point_id: str = "CP-01") -> Verdict:
        now = self.clock.now()
        try:
            if not isinstance(charge_point_id, str) or not security.CP_RE.fullmatch(charge_point_id):
                raise MessageError("invalid receiving charger identity")
            message = Envelope.from_frame(frame)
            canonical_json(message.to_frame())  # bounds/types also apply to in-memory calls
            if not message.security_present:
                # Policy check is repeated inside the write transaction to prevent a race.
                return self._receive_legacy(message, now, charge_point_id)
            sc = security.verify(message, self.keyring, charge_point_id)
            age = now - sc["ts"]
            if age > self.ttl_seconds:
                return self._finish(now, charge_point_id, Reason.EXPIRED, "signing timestamp expired")
            if -age > self.max_skew_seconds:
                return self._finish(now, charge_point_id, Reason.FUTURE_TIMESTAMP, "signing timestamp too far ahead")
            message.validate()
            with self.store.atomic():
                if not self.store.claim_nonce(nonce=sc["nonce"], key_id=sc["kid"], msg_ts=sc["ts"], now=now):
                    return self._finish(now, charge_point_id, Reason.REPLAY, "nonce already committed")
                digest = sha3_256_hex(canonical_json(message.call.to_frame()))
                cached = self.store.cached_request(charge_point_id, message.unique_id)
                if cached:
                    if cached["digest"] != digest:
                        return self._finish(
                            now, charge_point_id, Reason.REQUEST_CONFLICT, "request ID reused with changed data"
                        )
                    return self._finish(
                        now,
                        charge_point_id,
                        Reason(cached["reason"]),
                        "idempotent retry; no repeated effects",
                        facts=cached["facts"],
                    )
                reason, detail, facts = billing.apply(self.store, "securecharge", message.call, charge_point_id, now)
                if reason is Reason.ACCEPTED:
                    self.store.require_security(charge_point_id, now)
                    self.store.cache_request(charge_point_id, message.unique_id, digest, reason, facts, now)
                verdict = self._finish(now, charge_point_id, reason, detail, facts=facts)
            self._maybe_purge(now)
            return verdict
        except security.ExtensionError as exc:
            reason = next(
                (
                    r
                    for t, r in {
                        security.MalformedExtension: Reason.MALFORMED,
                        security.UnsupportedVersion: Reason.UNSUPPORTED_VERSION,
                        security.UnknownKeyId: Reason.UNKNOWN_KEY,
                        security.WrongCharger: Reason.WRONG_CHARGER,
                        security.BadTag: Reason.BAD_TAG,
                    }.items()
                    if isinstance(exc, t)
                ),
                Reason.BAD_TAG,
            )
            return self._finish(now, charge_point_id, reason, str(exc))
        except (MessageError, CanonicalizationError, RecursionError, TypeError, OverflowError) as exc:
            return self._finish(now, charge_point_id, Reason.MALFORMED, str(exc))
        except sqlite3.Error:
            # Atomic context has rolled back nonce, business effects and cached response.
            return Verdict(Layer.BACKEND, Reason.STORAGE_ERROR, "storage failure; retry with the same envelope")

    def _receive_legacy(self, message: Envelope, now: int, cp: str) -> Verdict:
        with self.store.atomic():
            if self.mode is Mode.ENFORCE or self.store.security_required(cp):
                return self._finish(
                    now,
                    cp,
                    Reason.MISSING_SECURITY,
                    "unsigned message forbidden by durable charger policy",
                    legacy=True,
                )
            reason, detail, checked = check_integrity(message, self.legacy_algorithm)
            facts = None
            if checked is not None:
                reason, detail, facts = billing.apply(self.store, "securecharge", checked, cp, now)
                detail = f"accepted without authentication ({self.mode.value}); {detail}"
            return self._finish(now, cp, reason, detail, facts, legacy=True)

    def _maybe_purge(self, now: int) -> None:
        if self._last_purge is None or now - self._last_purge >= PURGE_INTERVAL_SECONDS:
            self.store.purge_nonces(older_than=now - self.ttl_seconds - self.max_skew_seconds)
            self._last_purge = now

    def _finish(
        self, now: int, cp: str, reason: Reason, detail: str, facts: dict[str, Any] | None = None, legacy: bool = False
    ) -> Verdict:
        verdict = Verdict(Layer.BACKEND, reason, detail, facts, legacy)
        self.store.log(verdict, at=now, charge_point_id=cp)
        return verdict
