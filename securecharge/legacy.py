"""Modeled vendor checksums carried OUTSIDE standard OCPP 1.6 payloads.

OCPP does not require MD5. This explicit legacy assumption detects accidental
corruption but permits deliberate edits followed by checksum recomputation.
"""

from __future__ import annotations
from typing import Any
from dataclasses import replace
from . import billing
from .clock import Clock, SystemClock
from .crypto import md5_hex, sha1_hex, sha256_hex, sha3_256_hex
from .messages import MessageError, OcppCall
from .serialization import CanonicalizationError, canonical_json
from .transport import Envelope, as_envelope
from .storage import Store
from .verdict import Layer, Reason, Verdict

CHECKSUMS = {"md5": md5_hex, "sha1": sha1_hex, "sha256": sha256_hex, "sha3_256": sha3_256_hex}
CHECKSUM_LABELS = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "sha3_256": "SHA3-256"}


def payload_checksum(payload: dict[str, Any], algorithm: str = "md5") -> str:
    return CHECKSUMS[algorithm](canonical_json(payload))


def add_legacy_integrity(call: OcppCall | Envelope, algorithm: str = "md5") -> Envelope:
    return replace(as_envelope(call), legacy={"alg": algorithm, "value": payload_checksum(call.payload, algorithm)})


def check_integrity(call: Envelope, algorithm: str = "md5") -> tuple[Reason, str, OcppCall | None]:
    integrity = call.legacy
    if not isinstance(integrity, dict) or set(integrity) != {"alg", "value"} or integrity["alg"] != algorithm:
        return Reason.MALFORMED, "missing/invalid vendor checksum or policy algorithm mismatch", None
    if not isinstance(integrity["value"], str):
        return Reason.MALFORMED, "checksum must be hex", None
    try:
        actual = payload_checksum(call.payload, algorithm)
        if actual != integrity["value"]:
            return Reason.CHECKSUM_MISMATCH, "vendor checksum does not match payload", None
        call.validate()
    except (CanonicalizationError, MessageError) as exc:
        return Reason.INVALID_MESSAGE, str(exc), None
    return Reason.ACCEPTED, f"{CHECKSUM_LABELS[algorithm]} matches (unauthenticated)", call.call


class LegacyCsms:
    def __init__(self, store: Store, algorithm: str = "md5", clock: Clock | None = None) -> None:
        if algorithm not in CHECKSUMS:
            raise ValueError("unknown legacy algorithm")
        self.store, self.algorithm, self.clock = store, algorithm, clock or SystemClock()

    def receive(self, frame: Any, charge_point_id: str = "CP-01") -> Verdict:
        now = self.clock.now()
        try:
            message = Envelope.from_frame(frame)
            reason, detail, call = check_integrity(message, self.algorithm)
        except (MessageError, CanonicalizationError) as exc:
            reason, detail, call = Reason.MALFORMED, str(exc), None
        facts = None
        if call is not None:
            reason, detail, facts = billing.apply(self.store, "legacy", call, charge_point_id, now)
        verdict = Verdict(Layer.LEGACY, reason, detail, facts, legacy=True)
        self.store.log(verdict, at=now, charge_point_id=charge_point_id)
        return verdict
