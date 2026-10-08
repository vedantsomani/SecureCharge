"""Regression tests for accounting, identity, retries, policy and wire input."""

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import pytest
from securecharge import security
from securecharge.backend import Mode, SecureCsms
from securecharge.clock import FakeClock
from securecharge.gateway import MigrationGateway
from securecharge.keys import Keyring
from securecharge.legacy import add_legacy_integrity
from securecharge.messages import MessageError, example_start, example_stop
from securecharge.storage import Store
from securecharge.verdict import Reason


def lab(path=":memory:", mode=Mode.ENFORCE):
    s = Store(path)
    k = Keyring.generate()
    c = FakeClock(1_790_000_900)
    return s, MigrationGateway(k, clock=c), SecureCsms(k, s, clock=c, mode=mode)


def signed(g, call):
    return g.process(add_legacy_integrity(call).to_frame()).message


def start(g, b):
    return b.receive(signed(g, example_start()).to_frame()).facts["transaction_id"]


def test_signed_charger_cannot_be_relabelled():
    s, g, b = lab()
    assert b.receive(signed(g, example_start()).to_frame(), "CP-02").reason is Reason.WRONG_CHARGER
    assert s.nonce_count() == 0


def test_key_is_authorized_for_one_charger():
    k = Keyring.generate(charge_point_id="CP-02")
    with pytest.raises(security.WrongCharger):
        security.attach(example_start(), k, ts=100, charge_point_id="CP-01")


def test_transaction_cannot_be_closed_by_another_charger():
    s, g, b = lab()
    tx = start(g, b)
    k2 = Keyring.generate("gw-2", "CP-02")
    b2 = SecureCsms(k2, s, clock=b.clock)
    msg = security.attach(
        add_legacy_integrity(example_stop(transaction_id=tx)), k2, ts=b.clock.now(), charge_point_id="CP-02"
    )
    assert b2.receive(msg.to_frame(), "CP-02").reason is Reason.INVALID_MESSAGE
    assert s.ledger_rows() == []


def test_concurrent_distinct_stops_bill_once():
    s, g, b = lab()
    tx = start(g, b)
    frames = [signed(g, example_stop(transaction_id=tx, unique_id=f"stop-{i}")).to_frame() for i in range(16)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(b.receive, frames))
    assert sum(v.accepted for v in results) == 1
    assert len(s.ledger_rows()) == 1


def test_concurrent_exact_replay_has_one_winner():
    s, g, b = lab()
    frame = signed(g, example_start()).to_frame()
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(b.receive, [frame] * 16))
    assert sum(v.accepted for v in results) == 1
    assert all(v.accepted or v.reason is Reason.REPLAY for v in results)


def test_retry_with_fresh_envelope_returns_original_result():
    s, g, b = lab()
    original = b.receive(signed(g, example_start()).to_frame())
    retry = b.receive(signed(g, example_start()).to_frame())
    assert retry.accepted and retry.facts == original.facts
    assert len(s._rows("SELECT * FROM transactions")) == 1


def test_request_id_reuse_with_changed_payload_is_rejected():
    s, g, b = lab()
    start(g, b)
    altered = example_start(meter_start=49_000)
    assert b.receive(signed(g, altered).to_frame()).reason is Reason.REQUEST_CONFLICT


def test_storage_failure_rolls_back_nonce_and_business_state(monkeypatch):
    s, g, b = lab()
    frame = signed(g, example_start()).to_frame()
    original = s.cache_request

    def fail(*args):
        raise sqlite3.OperationalError("injected fault after transaction insertion")

    monkeypatch.setattr(s, "cache_request", fail)
    assert b.receive(frame).reason is Reason.STORAGE_ERROR
    assert s.nonce_count() == 0 and not s._rows("SELECT * FROM transactions")
    monkeypatch.setattr(s, "cache_request", original)
    assert b.receive(frame).accepted


def test_replay_and_policy_survive_restart(tmp_path):
    s, g, b = lab(tmp_path / "state.sqlite", Mode.MONITOR)
    frame = signed(g, example_start()).to_frame()
    assert b.receive(frame).accepted
    s.close()
    reopened = Store(tmp_path / "state.sqlite")
    b2 = SecureCsms(g.keyring, reopened, clock=b.clock, mode=Mode.MONITOR)
    assert b2.receive(frame).reason is Reason.REPLAY
    assert (
        b2.receive(add_legacy_integrity(example_start(unique_id="next")).to_frame()).reason is Reason.MISSING_SECURITY
    )


@pytest.mark.parametrize("mode", ["enforce", Mode.ENFORCE])
def test_mode_normalization_does_not_allow_unsigned(mode):
    s, g, b = lab(mode=mode)
    assert b.receive(add_legacy_integrity(example_start()).to_frame()).reason is Reason.MISSING_SECURITY


@pytest.mark.parametrize("bad", [None, False, [], "", {}, {"v": "SC2"}])
def test_present_malformed_security_never_falls_back(bad):
    s, g, b = lab(mode=Mode.MONITOR)
    message = replace(add_legacy_integrity(example_start()), security=bad, security_present=True)
    assert b.receive(message.to_frame()).reason is Reason.MALFORMED


def test_float_payload_rejected_without_uncaught_exception():
    s, g, b = lab()
    frame = signed(g, example_start()).to_frame()
    frame["ocpp"][3]["extra"] = 1.5
    assert b.receive(frame).reason is Reason.MALFORMED


def test_duplicate_keys_rejected_at_real_receive_boundary():
    s, g, b = lab()
    wire = json.dumps(signed(g, example_start()).to_frame())
    wire = wire.replace('"meterStart": 48000', '"meterStart": 48000, "meterStart": 0')
    assert b.receive(wire).reason is Reason.MALFORMED


def test_normal_whitespace_is_allowed_on_wire():
    s, g, b = lab()
    assert b.receive(json.dumps(signed(g, example_start()).to_frame(), indent=2)).accepted


def test_strict_schema_rejects_ocpp16_customdata():
    call = example_start()
    with pytest.raises(MessageError):
        call.with_payload({**call.payload, "customData": {"vendorId": "example"}}).validate()


def test_unwrap_preserves_original_ocpp():
    s, g, b = lab()
    original = example_start()
    assert signed(g, original).call.to_frame() == original.to_frame()


def test_schema_checks_optional_fields_and_dates():
    call = example_stop()
    for field, value in (("reason", "MadeUp"), ("timestamp", "nonsense"), ("idTag", "x" * 21)):
        with pytest.raises(MessageError):
            call.with_payload({**call.payload, field: value}).validate()


def test_rotation_overlap_then_retirement():
    s, g, b = lab()
    old_message = signed(g, example_start())
    rotated = g.keyring.with_key("gw-2", b"r" * 32, activate=True)
    assert security.verify(old_message, rotated)
    new_message = security.attach(example_start(), rotated, ts=b.clock.now())
    retired = rotated.without_key("gw-1")
    assert security.verify(new_message, retired)
    with pytest.raises(security.UnknownKeyId):
        security.verify(old_message, retired)


@pytest.mark.parametrize(
    "delta,reason",
    [(120, Reason.ACCEPTED), (121, Reason.EXPIRED), (-30, Reason.ACCEPTED), (-31, Reason.FUTURE_TIMESTAMP)],
)
def test_freshness_boundary(delta, reason):
    s, g, b = lab()
    message = signed(g, example_start())
    b.clock.advance(delta)
    assert b.receive(message.to_frame()).reason is reason
