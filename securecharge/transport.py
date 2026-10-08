"""SC2 outer transport. Its embedded OCPP CALL is unchanged and schema-valid.

This is a gateway/CSMS adapter protocol, not an OCPP extension. Legacy parsers
receive ``ocpp`` only; they never receive the envelope itself.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, replace
from typing import Any

from .messages import MessageError, OcppCall
from .serialization import canonical_json, parse_json

FORMAT = "SecureCharge/2"


@dataclass(frozen=True)
class Envelope:
    call: OcppCall
    legacy: dict[str, Any] | None = None
    security: Any = None
    security_present: bool = False

    @property
    def payload(self) -> dict[str, Any]:
        return self.call.payload

    @property
    def unique_id(self) -> str:
        return self.call.unique_id

    @property
    def action(self) -> str:
        return self.call.action

    def validate(self) -> Envelope:
        self.call.validate()
        return self

    def with_payload(self, payload: dict[str, Any]) -> Envelope:
        return replace(self, call=self.call.with_payload(copy.deepcopy(payload)))

    def to_frame(self) -> dict[str, Any]:
        value = {"format": FORMAT, "ocpp": self.call.to_frame(), "legacy": self.legacy}
        if self.security_present:
            value["security"] = self.security
        return copy.deepcopy(value)

    def to_bytes(self) -> bytes:
        return canonical_json(self.to_frame())

    @classmethod
    def from_frame(cls, value: Any) -> Envelope:
        if isinstance(value, (str, bytes)):
            value = parse_json(value)
        if isinstance(value, list):
            return cls(OcppCall.from_frame(value))
        if not isinstance(value, dict):
            raise MessageError("expected an SC2 transport object or OCPP CALL")
        if set(value) not in ({"format", "ocpp", "legacy"}, {"format", "ocpp", "legacy", "security"}):
            raise MessageError("unexpected or missing envelope fields")
        if value["format"] != FORMAT:
            raise MessageError("unsupported transport format")
        legacy = value["legacy"]
        if legacy is not None and not isinstance(legacy, dict):
            raise MessageError("legacy integrity must be an object or null")
        return cls(
            OcppCall.from_frame(value["ocpp"]),
            copy.deepcopy(legacy),
            copy.deepcopy(value.get("security")),
            "security" in value,
        )


def as_envelope(value: OcppCall | Envelope) -> Envelope:
    return value if isinstance(value, Envelope) else Envelope(value)
