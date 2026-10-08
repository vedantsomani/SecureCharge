"""OCPP 1.6 CALL framing and field validation."""

from __future__ import annotations

import pytest

from securecharge.messages import MessageError, OcppCall, example_start, example_stop, format_inr, price_for


def test_frame_roundtrip():
    call = example_stop()
    assert OcppCall.from_frame(call.to_frame()) == call
    assert call.to_frame()[0] == 2  # MessageTypeId for a CALL


def test_from_frame_rejects_bad_shapes():
    for bad in (
        [2, "id", "StopTransaction"],
        {"not": "a list"},
        [3, "id", "A", {}],
        [2, "id", 5, {}],
        [2, "id", "A", "not-object"],
    ):
        with pytest.raises(MessageError):
            OcppCall.from_frame(bad)


def test_unknown_action_rejected():
    with pytest.raises(MessageError):
        OcppCall("id", "LaunchMissiles", {})


def test_validate_catches_bad_fields():
    with pytest.raises(MessageError):
        OcppCall("id", "StopTransaction", {"transactionId": 1, "meterStop": -5, "timestamp": "t"}).validate()
    with pytest.raises(MessageError):
        # bool must not pass as connectorId
        OcppCall(
            "id", "StartTransaction", {"connectorId": True, "idTag": "A", "meterStart": 0, "timestamp": "t"}
        ).validate()
    with pytest.raises(MessageError):
        OcppCall("id", "StopTransaction", {"transactionId": 1, "meterStop": 1, "timestamp": ""}).validate()


def test_examples_validate():
    example_start().validate()
    example_stop().validate()


def test_pricing_and_formatting():
    assert price_for(12_500) == 15_000  # 12.5 kWh @ Rs 12 = Rs 150.00
    assert format_inr(15_000) == "₹150.00"
    assert format_inr(1_00_000_00) == "₹1,00,000.00"
    assert format_inr(120) == "₹1.20"
