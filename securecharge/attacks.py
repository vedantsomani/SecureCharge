"""Local defensive test mutations; no external targets or traffic."""

from __future__ import annotations
import copy
from dataclasses import replace
from typing import Any
from .crypto import generate_key, hmac_sha3_256_hex, sha3_256_hex
from .legacy import add_legacy_integrity
from .transport import Envelope
from .security import mac_input, new_nonce


def tamper_meter_stop(message: Envelope, meter_stop: int, *, recompute_md5: bool) -> Envelope:
    return set_field(message, "meterStop", meter_stop, recompute_md5=recompute_md5)


def set_field(message: Envelope, field: str, value: Any, *, recompute_md5: bool) -> Envelope:
    payload = copy.deepcopy(message.payload)
    payload[field] = value
    edited = message.with_payload(payload)
    return add_legacy_integrity(edited, message.legacy["alg"]) if recompute_md5 else edited


def strip_extension(message: Envelope) -> Envelope:
    return replace(message, security=None, security_present=False)


def _set_sc(message: Envelope, sc: dict[str, Any]) -> Envelope:
    return replace(message, security=copy.deepcopy(sc), security_present=True)


def tag_with_plain_hash(message: Envelope, meter_stop: int) -> Envelope:
    edited = tamper_meter_stop(message, meter_stop, recompute_md5=True)
    sc = dict(edited.security)
    sc["tag"] = sha3_256_hex(mac_input(edited, kid=sc["kid"], ts=sc["ts"], nonce=sc["nonce"], charge_point_id=sc["cp"]))
    return _set_sc(edited, sc)


def resign_with_foreign_key(message: Envelope, meter_stop: int, key: bytes | None = None) -> Envelope:
    edited = tamper_meter_stop(message, meter_stop, recompute_md5=True)
    sc = dict(edited.security)
    sc["tag"] = hmac_sha3_256_hex(
        key or generate_key(),
        mac_input(edited, kid=sc["kid"], ts=sc["ts"], nonce=sc["nonce"], charge_point_id=sc["cp"]),
    )
    return _set_sc(edited, sc)


def downgrade_version(message: Envelope, version: str = "SC1") -> Envelope:
    return _set_sc(message, {**message.security, "v": version})


def refresh_timestamp(message: Envelope, ts: int) -> Envelope:
    return _set_sc(message, {**message.security, "ts": ts})


def change_nonce(message: Envelope, nonce: str | None = None) -> Envelope:
    return _set_sc(message, {**message.security, "nonce": nonce or new_nonce()})


def replay(message: Envelope) -> Envelope:
    return copy.deepcopy(message)
