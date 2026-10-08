"""SC2: HMAC-SHA3-256 over an outer envelope and charger identity.

SC-JSON-1 encoding, domain separation, random 128-bit nonce, signed key id,
version and timestamp. The embedded OCPP payload is never extended.
"""

from __future__ import annotations
import re
import secrets
from dataclasses import replace
from typing import Any
from .crypto import hmac_sha3_256_hex, verify_hmac_sha3_256
from .keys import KEY_ID_RE, Keyring
from .messages import OcppCall
from .serialization import canonical_json
from .transport import FORMAT, Envelope, as_envelope

SC_VERSION = "SC2"
MAC_CONTEXT = b"SecureCharge/SC2 ocpp-integrity\n"
CP_RE = re.compile(r"[A-Za-z0-9_.-]{1,40}")


class ExtensionError(ValueError):
    pass


class MalformedExtension(ExtensionError):
    pass


class UnsupportedVersion(ExtensionError):
    pass


class UnknownKeyId(ExtensionError):
    pass


class BadTag(ExtensionError):
    pass


class WrongCharger(ExtensionError):
    pass


def new_nonce() -> str:
    return secrets.token_hex(16)


def signed_view(
    call: OcppCall | Envelope, *, kid: str, ts: int, nonce: str, charge_point_id: str = "CP-01"
) -> dict[str, Any]:
    message = as_envelope(call)
    return {
        "format": FORMAT,
        "ocpp": message.call.to_frame(),
        "legacy": message.legacy,
        "security": {"v": SC_VERSION, "kid": kid, "ts": ts, "nonce": nonce, "cp": charge_point_id},
    }


def mac_input(call: OcppCall | Envelope, *, kid: str, ts: int, nonce: str, charge_point_id: str = "CP-01") -> bytes:
    return MAC_CONTEXT + canonical_json(signed_view(call, kid=kid, ts=ts, nonce=nonce, charge_point_id=charge_point_id))


def attach(
    call: OcppCall | Envelope, keyring: Keyring, *, ts: int, nonce: str | None = None, charge_point_id: str = "CP-01"
) -> Envelope:
    if not keyring.authorized(keyring.active_kid, charge_point_id):
        raise WrongCharger("active key is not authorized for this charger")
    nonce = nonce if nonce is not None else new_nonce()
    sc = {"v": SC_VERSION, "kid": keyring.active_kid, "ts": ts, "nonce": nonce, "cp": charge_point_id}
    sc["tag"] = hmac_sha3_256_hex(
        keyring.active_key, mac_input(call, kid=sc["kid"], ts=ts, nonce=nonce, charge_point_id=charge_point_id)
    )
    _checked(sc)
    return replace(as_envelope(call), security=sc, security_present=True)


def extract(call: Envelope) -> Any:
    return call.security if call.security_present else None


def _checked(sc: Any) -> dict[str, Any]:
    fields = {"v": str, "kid": str, "ts": int, "nonce": str, "cp": str, "tag": str}
    if not isinstance(sc, dict) or set(sc) != set(fields):
        raise MalformedExtension("security must contain exactly v, kid, ts, nonce, cp, tag")
    if any(type(sc[k]) is not t for k, t in fields.items()):
        raise MalformedExtension("invalid security field type")
    if not KEY_ID_RE.fullmatch(sc["kid"]) or not CP_RE.fullmatch(sc["cp"]):
        raise MalformedExtension("invalid key or charger id")
    if not re.fullmatch(r"[0-9a-f]{32}", sc["nonce"]) or not re.fullmatch(r"[0-9a-f]{64}", sc["tag"]):
        raise MalformedExtension("nonce/tag must be lowercase hex of length 32/64")
    if not 0 <= sc["ts"] <= 2**53 - 1:
        raise MalformedExtension("invalid signing timestamp")
    return dict(sc)


def verify(call: Envelope, keyring: Keyring, charge_point_id: str = "CP-01") -> dict[str, Any]:
    sc = _checked(call.security)
    if sc["v"] != SC_VERSION:
        raise UnsupportedVersion("unsupported security version")
    key = keyring.key(sc["kid"])
    if key is None:
        raise UnknownKeyId("unknown or retired key id")
    data = mac_input(call, kid=sc["kid"], ts=sc["ts"], nonce=sc["nonce"], charge_point_id=sc["cp"])
    if not verify_hmac_sha3_256(key, data, sc["tag"]):
        raise BadTag("HMAC-SHA3-256 does not authenticate this envelope")
    if sc["cp"] != charge_point_id or not keyring.authorized(sc["kid"], charge_point_id):
        raise WrongCharger("signed charger/key does not match receiving charger")
    return sc


REPLY_CONTEXT = b"SecureCharge/SC2 reply\n"


def sign_reply(frame: list[Any], request: Envelope, keyring: Keyring, now: int) -> dict[str, Any]:
    sc = _checked(request.security)
    body = {
        "format": "SecureCharge/2-reply",
        "request_nonce": sc["nonce"],
        "cp": sc["cp"],
        "kid": sc["kid"],
        "ts": now,
        "ocpp": frame,
    }
    key = keyring.key(sc["kid"])
    if key is None or not keyring.authorized(sc["kid"], sc["cp"]):
        raise UnknownKeyId("reply key unavailable")
    return {**body, "tag": hmac_sha3_256_hex(key, REPLY_CONTEXT + canonical_json(body))}


def verify_reply(
    reply: Any, request: Envelope, keyring: Keyring, now: int, ttl: int = 120, skew: int = 30
) -> list[Any]:
    if not isinstance(reply, dict) or set(reply) != {"format", "request_nonce", "cp", "kid", "ts", "ocpp", "tag"}:
        raise MalformedExtension("malformed authenticated reply")
    sc = _checked(request.security)
    body = {k: v for k, v in reply.items() if k != "tag"}
    if (
        body["format"] != "SecureCharge/2-reply"
        or any(body[k] != sc[k] for k in ("cp", "kid"))
        or body["request_nonce"] != sc["nonce"]
    ):
        raise BadTag("reply does not match outstanding request")
    key = keyring.key(sc["kid"])
    if (
        key is None
        or not isinstance(reply["tag"], str)
        or not verify_hmac_sha3_256(key, REPLY_CONTEXT + canonical_json(body), reply["tag"])
    ):
        raise BadTag("reply MAC invalid")
    if type(body["ts"]) is not int or not -skew <= now - body["ts"] <= ttl:
        raise BadTag("reply outside freshness window")
    frame = body["ocpp"]
    if (
        not isinstance(frame, list)
        or len(frame) not in (3, 5)
        or type(frame[0]) is not int
        or frame[0] not in (3, 4)
        or frame[1] != request.unique_id
    ):
        raise MalformedExtension("reply is not a matching OCPP response")
    if frame[0] == 3:
        if len(frame) != 3:
            raise MalformedExtension("invalid CALLRESULT shape")
        from .protocol import validate_payload

        validate_payload(request.action, frame[2], response=True)
    elif (
        len(frame) != 5
        or not isinstance(frame[2], str)
        or not isinstance(frame[3], str)
        or not isinstance(frame[4], dict)
    ):
        raise MalformedExtension("invalid CALLERROR shape")
    return frame
