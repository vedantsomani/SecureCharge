"""Collision substitution inside schema-valid OCPP 1.6 SignedData samples.

MVR-128 is a deliberately specified RESEARCH MODEL, not a vendor discovery.
Its 128-byte record stores a big-endian 31-bit Wh counter at bytes 16..19
(high bit reserved); other bytes are opaque vendor data. A trusted expected
MD5 of the decoded record is pinned before substitution. The published pair
has identical MD5 but different counter values. Neither base64 nor JSON is
claimed to collide. The legacy hashing boundary is the DECODED record.
"""

from __future__ import annotations
import base64
import copy
from dataclasses import asdict, dataclass
from typing import Any
from .collision import COLLISION_A, COLLISION_B, EXPECTED_MD5
from .crypto import md5_hex, sha256_hex, sha3_256_hex
from .messages import MessageError, OcppCall, example_stop, price_for
from .legacy import add_legacy_integrity
from .keys import Keyring
from . import security

MODEL = "MVR-128 research fixture; no real vendor firmware claim"


def read_counter(record: bytes) -> int:
    if len(record) != 128:
        raise MessageError("MVR-128 must be exactly 128 bytes")
    return int.from_bytes(record[16:20], "big") & 0x7FFFFFFF


def make_call(record: bytes) -> OcppCall:
    counter = read_counter(record)
    call = example_stop(transaction_id=1, meter_stop=counter, unique_id="collision-stop")
    payload = copy.deepcopy(call.payload)
    payload["transactionData"] = [
        {
            "timestamp": payload["timestamp"],
            "sampledValue": [
                {
                    "value": base64.b64encode(record).decode("ascii"),
                    "format": "SignedData",
                    "measurand": "Energy.Active.Import.Register",
                    "unit": "Wh",
                }
            ],
        }
    ]
    return call.with_payload(payload).validate()


def legacy_accepts(call: OcppCall, trusted_digest: str) -> bool:
    """Pinned digest remains unchanged; the attacker does NOT recompute it."""
    try:
        call.validate()
        sample = call.payload["transactionData"][0]["sampledValue"][0]
        if sample["format"] != "SignedData":
            return False
        record = base64.b64decode(sample["value"], validate=True)
        return md5_hex(record) == trusted_digest and read_counter(record) == call.payload["meterStop"]
    except (KeyError, ValueError, TypeError, IndexError):
        return False


@dataclass(frozen=True)
class CollisionExperiment:
    model: str
    hashing_boundary: str
    pinned_md5: str
    honest_meter_stop: int
    substituted_meter_stop: int
    meter_start: int
    honest_bill_paise: int
    substituted_bill_paise: int
    legacy_accepts_both: bool
    full_json_md5_equal: bool
    sha256_record_equal: bool
    sha3_record_equal: bool
    secure_substitution_reason: str
    honest_ocpp: list[Any]
    substituted_ocpp: list[Any]


def run() -> CollisionExperiment:
    honest, substituted = make_call(COLLISION_A), make_call(COLLISION_B)
    meter_start = honest.payload["meterStop"] - 12_500
    envelope = security.attach(
        add_legacy_integrity(honest),
        Keyring({"fixture": bytes(range(32))}, "fixture"),
        ts=1_790_000_900,
        nonce="a" * 32,
    )
    forged = envelope.with_payload(substituted.payload)
    reason = "ACCEPTED"
    try:
        security.verify(forged, Keyring({"fixture": bytes(range(32))}, "fixture"))
    except security.BadTag:
        reason = "BAD_TAG"
    from .serialization import canonical_json

    return CollisionExperiment(
        MODEL,
        "base64-decoded 128-byte vendor meter record ONLY",
        EXPECTED_MD5,
        honest.payload["meterStop"],
        substituted.payload["meterStop"],
        meter_start,
        price_for(honest.payload["meterStop"] - meter_start),
        price_for(substituted.payload["meterStop"] - meter_start),
        legacy_accepts(honest, EXPECTED_MD5) and legacy_accepts(substituted, EXPECTED_MD5),
        md5_hex(canonical_json(honest.to_frame())) == md5_hex(canonical_json(substituted.to_frame())),
        sha256_hex(COLLISION_A) == sha256_hex(COLLISION_B),
        sha3_256_hex(COLLISION_A) == sha3_256_hex(COLLISION_B),
        reason,
        honest.to_frame(),
        substituted.to_frame(),
    )


def report() -> dict[str, Any]:
    return asdict(run())
