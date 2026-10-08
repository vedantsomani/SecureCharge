"""Decisions made by each layer, with machine-readable reasons."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class Layer(str, Enum):
    LEGACY = "legacy-csms"
    GATEWAY = "gateway"
    BACKEND = "secure-csms"


class Reason(str, Enum):
    ACCEPTED = "ACCEPTED"
    MALFORMED = "MALFORMED"
    CHECKSUM_MISMATCH = "CHECKSUM_MISMATCH"
    INVALID_MESSAGE = "INVALID_MESSAGE"
    MISSING_SECURITY = "MISSING_SECURITY"
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    UNKNOWN_KEY = "UNKNOWN_KEY"
    BAD_TAG = "BAD_TAG"
    EXPIRED = "EXPIRED"
    FUTURE_TIMESTAMP = "FUTURE_TIMESTAMP"
    REPLAY = "REPLAY"
    WRONG_CHARGER = "WRONG_CHARGER"
    REQUEST_CONFLICT = "REQUEST_CONFLICT"
    STORAGE_ERROR = "STORAGE_ERROR"


REASON_TEXT = {
    Reason.ACCEPTED: "All checks for this layer passed.",
    Reason.MALFORMED: "Not a well-formed, canonical OCPP CALL.",
    Reason.CHECKSUM_MISMATCH: "The checksum does not match the payload.",
    Reason.INVALID_MESSAGE: "The message fails OCPP field validation.",
    Reason.MISSING_SECURITY: "No SecureCharge tag, and the backend is enforcing.",
    Reason.UNSUPPORTED_VERSION: "Unknown extension version (downgrade attempt?).",
    Reason.UNKNOWN_KEY: "The key id is unknown or retired.",
    Reason.BAD_TAG: "HMAC-SHA3-256 tag invalid: the message was modified or forged.",
    Reason.EXPIRED: "Timestamp older than the allowed lifetime.",
    Reason.FUTURE_TIMESTAMP: "Timestamp too far in the future.",
    Reason.REPLAY: "This nonce was already accepted: replayed message.",
    Reason.WRONG_CHARGER: "The signed charger/key does not match this connection.",
    Reason.REQUEST_CONFLICT: "A request ID was reused for different business data.",
    Reason.STORAGE_ERROR: "Storage failed; business effects and nonce were rolled back.",
}


@dataclass(frozen=True)
class Verdict:
    layer: Layer
    reason: Reason
    detail: str = ""
    # Billing facts recovered from an accepted message, for the ledger / UI.
    facts: dict[str, Any] | None = None
    # True when the message carried no SecureCharge tag (a legacy message).
    legacy: bool = False

    @property
    def accepted(self) -> bool:
        return self.reason is Reason.ACCEPTED

    @property
    def label(self) -> str:
        return "ACCEPTED" if self.accepted else f"REJECTED ({self.reason.value})"
