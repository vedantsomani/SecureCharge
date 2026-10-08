"""Turning accepted OCPP messages into ledger entries.

This runs *after* a backend has decided a message is authentic. Both the legacy
CSMS and the secure CSMS share it, so the two systems bill identically and any
difference in what gets billed comes only from the integrity check, never from
the accounting. ``StartTransaction`` opens a session at ``meterStart``;
``StopTransaction`` closes it and bills ``meterStop - meterStart`` at tariff.
"""

from __future__ import annotations

from typing import Any
from datetime import datetime

from .messages import OcppCall, core_payload, price_for
from .storage import Store
from .verdict import Reason


def apply(
    store: Store, system: str, call: OcppCall, charge_point_id: str, now: int
) -> tuple[Reason, str, dict[str, Any] | None]:
    with store.atomic():
        return _apply(store, system, call, charge_point_id, now)


def _apply(
    store: Store, system: str, call: OcppCall, charge_point_id: str, now: int
) -> tuple[Reason, str, dict[str, Any] | None]:
    core = core_payload(call.payload)

    if call.action == "StartTransaction":
        if store.connector_open(system, charge_point_id, core["connectorId"]):
            return Reason.INVALID_MESSAGE, "connector already has an open transaction", None
        txid = store.open_transaction(
            system=system,
            charge_point_id=charge_point_id,
            connector_id=core["connectorId"],
            meter_start_wh=core["meterStart"],
            at=int(datetime.fromisoformat(core["timestamp"].replace("Z", "+00:00")).timestamp()),
        )
        facts = {"transaction_id": txid, "meter_start_wh": core["meterStart"]}
        return Reason.ACCEPTED, f"transaction {txid} opened at meterStart={core['meterStart']} Wh", facts

    if call.action == "StopTransaction":
        txid = core["transactionId"]
        meter_start = store.open_meter_start(system, txid, charge_point_id)
        if meter_start is None:
            return Reason.INVALID_MESSAGE, f"StopTransaction for unknown/closed transaction {txid}", None
        energy_wh = core["meterStop"] - meter_start
        if energy_wh < 0:
            return Reason.INVALID_MESSAGE, f"meterStop {core['meterStop']} is below meterStart {meter_start}", None
        amount_paise = price_for(energy_wh)
        if not store.close_transaction(
            system=system,
            transaction_id=txid,
            charge_point_id=charge_point_id,
            energy_wh=energy_wh,
            amount_paise=amount_paise,
            at=now,
        ):
            return Reason.INVALID_MESSAGE, "transaction no longer open or charger ownership mismatch", None
        facts = {
            "transaction_id": txid,
            "energy_wh": energy_wh,
            "amount_paise": amount_paise,
            "meter_stop_wh": core["meterStop"],
        }
        return Reason.ACCEPTED, f"transaction {txid} billed {energy_wh} Wh", facts

    # Other actions (Heartbeat, BootNotification, MeterValues) carry no charge.
    return Reason.ACCEPTED, f"{call.action} accepted (no billing effect)", None
