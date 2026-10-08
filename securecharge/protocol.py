"""Independent OCPP 1.6 schemas and standard response framing."""

from __future__ import annotations
import json
from functools import lru_cache
from importlib.resources import files
from typing import Any
from jsonschema import Draft4Validator, FormatChecker
from .messages import MessageError, OcppCall
from .verdict import Verdict


@lru_cache(maxsize=32)
def schema_validator(action: str, response: bool = False) -> Draft4Validator:
    name = action + ("Response" if response else "") + ".json"
    path = files("ocpp").joinpath("v16", "schemas", name)
    return Draft4Validator(json.loads(path.read_text(encoding="utf-8")), format_checker=FormatChecker())


def validate_payload(action: str, payload: dict[str, Any], *, response: bool = False) -> None:
    error = next(schema_validator(action, response).iter_errors(payload), None)
    if error:
        location = ".".join(str(p) for p in error.absolute_path) or "$"
        raise MessageError(f"OCPP 1.6 schema: {location}: {error.message}")


def response_for(call: OcppCall, verdict: Verdict) -> list[Any]:
    if not verdict.accepted:
        return [
            4,
            call.unique_id,
            "FormationViolation" if verdict.reason.value == "INVALID_MESSAGE" else "SecurityError",
            verdict.reason.value,
            {},
        ]
    if call.action == "StartTransaction":
        payload = {"transactionId": verdict.facts["transaction_id"], "idTagInfo": {"status": "Accepted"}}
    elif call.action == "StopTransaction":
        payload = {"idTagInfo": {"status": "Accepted"}}
    elif call.action in ("Heartbeat", "BootNotification"):
        from .messages import iso_timestamp
        import time

        payload = {"currentTime": iso_timestamp(int(time.time()))}
        if call.action == "BootNotification":
            payload.update(status="Accepted", interval=60)
    else:
        payload = {}
    validate_payload(call.action, payload, response=True)
    return [3, call.unique_id, payload]
