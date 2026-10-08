"""OCPP 1.6-J message model.

OCPP 1.6-J (the JSON-over-WebSocket binding of the Open Charge Point Protocol)
puts every request on the wire as a CALL array::

    [2, "<uniqueId>", "<Action>", {<payload>}]

    2            MessageTypeId for a CALL (a request)
    "<uniqueId>" message id the matching response must echo
    "<Action>"   e.g. "StartTransaction", "StopTransaction", "MeterValues"
    {<payload>}  the action's fields

SecureCharge targets the messages a charging bill is built from. A session is
opened by ``StartTransaction`` (carrying ``meterStart``, the energy meter's Wh
reading at plug-in) and closed by ``StopTransaction`` (carrying ``meterStop``,
the reading at unplug). The energy sold is ``meterStop - meterStart`` and the
charge is that times the tariff, so ``meterStop`` is the number an attacker
would want to lower - the OCPP-native version of "change the amount".

Integrity metadata lives in a separate SC2 transport envelope. OCPP 1.6 does
not permit ``customData`` in these payloads. The adapter unwraps the unchanged
CALL before handing it to a strict legacy parser.
"""

from __future__ import annotations

import random
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

MESSAGE_TYPE_CALL = 2
VENDOR_ID = "SecureCharge"
CUSTOM_DATA = "customData"

ID_TAG_RE = re.compile(r"[A-Za-z0-9*.\-_=:+|@]{1,20}")
UNIQUE_ID_RE = re.compile(r"[A-Za-z0-9\-]{1,36}")

MAX_CONNECTOR_ID = 8
MAX_METER_WH = 2_147_483_647  # application limit for a signed 32-bit counter
DEFAULT_TARIFF_PAISE_PER_KWH = 1_200  # Rs 12.00 per kWh

# Per action: the required fields and, for each, the validator kind used below.
_REQUIRED_FIELDS: dict[str, dict[str, str]] = {
    "StartTransaction": {
        "connectorId": "connector",
        "idTag": "idtag",
        "meterStart": "meter",
        "timestamp": "timestamp",
    },
    "StopTransaction": {
        "transactionId": "txid",
        "meterStop": "meter",
        "timestamp": "timestamp",
    },
    "MeterValues": {"connectorId": "connector", "meterValue": "metervalue"},
    "Heartbeat": {},
    "BootNotification": {"chargePointVendor": "shortstr", "chargePointModel": "shortstr"},
}
BILLABLE_ACTIONS = ("StartTransaction", "StopTransaction")


class MessageError(ValueError):
    """A message is not a structurally valid OCPP CALL for a known action."""


def _is_int(value: Any) -> bool:
    return type(value) is int  # bool is an int subclass; reject it


def _require_int(name: str, value: Any, low: int, high: int) -> None:
    if not _is_int(value):
        raise MessageError(f"{name} must be an integer, got {type(value).__name__}")
    if not low <= value <= high:
        raise MessageError(f"{name}={value} is outside [{low}, {high}]")


def _validate_field(kind: str, name: str, value: Any) -> None:
    if kind == "connector":
        _require_int(name, value, 1, MAX_CONNECTOR_ID)
    elif kind == "txid":
        _require_int(name, value, 1, 2_000_000_000)
    elif kind == "meter":
        _require_int(name, value, 0, MAX_METER_WH)
    elif kind == "idtag":
        if not isinstance(value, str) or not ID_TAG_RE.fullmatch(value):
            raise MessageError(f"{name} must be a 1-20 char idTag")
    elif kind == "timestamp":
        if not isinstance(value, str) or not value:
            raise MessageError(f"{name} must be an ISO-8601 timestamp string")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError("timezone missing")
        except ValueError:
            raise MessageError(f"{name} must be a timezone-aware date-time") from None
    elif kind == "shortstr":
        if not isinstance(value, str) or not 1 <= len(value) <= 50:
            raise MessageError(f"{name} must be a 1-50 char string")
    elif kind == "metervalue":
        if not isinstance(value, list) or not value:
            raise MessageError(f"{name} must be a non-empty list")


def core_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Business payload; transport integrity fields never appear inside it."""
    return dict(payload)


def custom_data(payload: Mapping[str, Any]) -> dict[str, Any]:
    value = payload.get(CUSTOM_DATA)
    return dict(value) if isinstance(value, Mapping) else {}


@dataclass(frozen=True)
class OcppCall:
    """An OCPP 1.6 CALL without vendor transport metadata."""

    unique_id: str
    action: str
    payload: dict[str, Any]

    def __post_init__(self) -> None:
        if not isinstance(self.unique_id, str) or not UNIQUE_ID_RE.fullmatch(self.unique_id):
            raise MessageError(f"unique_id must be a 1-36 char token, got {self.unique_id!r}")
        if self.action not in _REQUIRED_FIELDS:
            raise MessageError(f"unknown or unsupported action {self.action!r}")
        if not isinstance(self.payload, dict):
            raise MessageError("payload must be an object")

    def validate(self) -> OcppCall:
        """Check the core fields for this action. Raises on anything invalid."""
        core = core_payload(self.payload)
        for name, kind in _REQUIRED_FIELDS[self.action].items():
            if name not in core:
                raise MessageError(f"{self.action} is missing required field {name!r}")
            _validate_field(kind, name, core[name])
        from .protocol import validate_payload

        validate_payload(self.action, self.payload)
        return self

    def to_frame(self) -> list[Any]:
        return [MESSAGE_TYPE_CALL, self.unique_id, self.action, self.payload]

    @classmethod
    def from_frame(cls, frame: Any) -> OcppCall:
        if not isinstance(frame, list) or len(frame) != 4:
            raise MessageError("an OCPP CALL is a 4-element array")
        type_id, unique_id, action, payload = frame
        if type(type_id) is not int or type_id != MESSAGE_TYPE_CALL:
            raise MessageError(f"MessageTypeId {type_id!r} is not a CALL (2)")
        if not isinstance(action, str):
            raise MessageError("action must be a string")
        if not isinstance(payload, Mapping):
            raise MessageError("payload must be an object")
        return cls(unique_id, action, dict(payload))

    def with_payload(self, payload: Mapping[str, Any]) -> OcppCall:
        return OcppCall(self.unique_id, self.action, dict(payload))


def price_for(energy_wh: int, tariff_paise_per_kwh: int = DEFAULT_TARIFF_PAISE_PER_KWH) -> int:
    """Charge in paise for an energy amount, rounded half-up to the paisa."""
    return (energy_wh * tariff_paise_per_kwh + 500) // 1000


def iso_timestamp(epoch_seconds: int) -> str:
    return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_unique_id(rng: random.Random | None = None) -> str:
    return f"{(rng or random).getrandbits(64):016x}"


def example_start(
    meter_start: int = 48_000, *, unique_id: str = "msg-0001", connector_id: int = 1, at: int = 1_790_000_000
) -> OcppCall:
    """A charger opening a session at a 48.000 kWh lifetime meter reading."""
    return OcppCall(
        unique_id,
        "StartTransaction",
        {
            "connectorId": connector_id,
            "idTag": "RFID-1234",
            "meterStart": meter_start,
            "timestamp": iso_timestamp(at),
        },
    ).validate()


def example_stop(
    transaction_id: int = 1001, meter_stop: int = 60_500, *, unique_id: str = "msg-0002", at: int = 1_790_000_900
) -> OcppCall:
    """Closing the session at 60.500 kWh: 12.5 kWh sold, i.e. Rs 150.00."""
    return OcppCall(
        unique_id,
        "StopTransaction",
        {
            "transactionId": transaction_id,
            "idTag": "RFID-1234",
            "meterStop": meter_stop,
            "timestamp": iso_timestamp(at),
            "reason": "Local",
        },
    ).validate()


def format_inr(paise: int, symbol: str = "₹") -> str:
    """150_00 -> '₹150.00'; 1_00_000_00 -> '₹1,00,000.00' (Indian digit grouping)."""
    sign = "-" if paise < 0 else ""
    rupees, rest = divmod(abs(paise), 100)
    digits = str(rupees)
    if len(digits) > 3:
        head, tail = digits[:-3], digits[-3:]
        groups = []
        while len(head) > 2:
            groups.insert(0, head[-2:])
            head = head[:-2]
        if head:
            groups.insert(0, head)
        digits = ",".join([*groups, tail])
    return f"{sign}{symbol}{digits}.{rest:02d}"
