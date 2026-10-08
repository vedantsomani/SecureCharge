"""End-to-end gateway + secure CSMS behaviour, including migration modes."""

from __future__ import annotations

import pytest

from securecharge import attacks
from securecharge.backend import Mode, SecureCsms
from securecharge.clock import FakeClock
from securecharge.gateway import MigrationGateway
from securecharge.keys import Keyring
from securecharge.legacy import add_legacy_integrity
from securecharge.messages import example_start, example_stop
from securecharge.storage import Store
from securecharge.transport import Envelope
from securecharge.verdict import Reason


@pytest.fixture
def lab():
    clock = FakeClock(1_790_000_900)
    keyring = Keyring.generate()
    store = Store(":memory:")
    gw = MigrationGateway(keyring, clock=clock, store=store)
    be = SecureCsms(keyring, store, clock=clock, mode=Mode.ENFORCE)
    start = add_legacy_integrity(example_start(meter_start=48_000, at=1_790_000_000))
    txid = be.receive(gw.process(start.to_frame()).frame).facts["transaction_id"]
    return clock, gw, be, store, txid


def _upgraded_stop(gw, txid):
    stop = add_legacy_integrity(example_stop(transaction_id=txid, meter_stop=60_500, at=1_790_000_900))
    return Envelope.from_frame(gw.process(stop.to_frame()).frame)


def test_honest_message_is_billed(lab):
    _, gw, be, _, txid = lab
    v = be.receive(_upgraded_stop(gw, txid).to_frame())
    assert v.accepted and v.facts["amount_paise"] == 15_000


def test_replay_is_rejected(lab):
    _, gw, be, _, txid = lab
    msg = _upgraded_stop(gw, txid)
    assert be.receive(msg.to_frame()).accepted
    assert be.receive(msg.to_frame()).reason is Reason.REPLAY


def test_expired_and_future(lab):
    clock, gw, be, _, txid = lab
    msg = _upgraded_stop(gw, txid)
    clock.advance(10_000)
    assert be.receive(msg.to_frame()).reason is Reason.EXPIRED

    future_gw = MigrationGateway(gw.keyring, clock=FakeClock(clock.now() + 10_000), store=be.store)
    stop = add_legacy_integrity(example_stop(transaction_id=txid, meter_stop=60_500))
    ahead = future_gw.process(stop.to_frame()).frame
    assert be.receive(ahead).reason is Reason.FUTURE_TIMESTAMP


def test_tamper_and_downgrade_rejected(lab):
    _, gw, be, _, txid = lab
    msg = _upgraded_stop(gw, txid)
    assert be.receive(attacks.tamper_meter_stop(msg, 48_100, recompute_md5=True).to_frame()).reason is Reason.BAD_TAG
    assert be.receive(attacks.strip_extension(msg).to_frame()).reason is Reason.MISSING_SECURITY


def test_modes_differ_on_legacy_messages():
    keyring = Keyring.generate()
    store = Store(":memory:")
    clock = FakeClock(1_790_000_900)
    legacy_only = add_legacy_integrity(example_start(meter_start=48_000, at=1_790_000_000))

    enforce = SecureCsms(keyring, store, clock=clock, mode=Mode.ENFORCE)
    assert enforce.receive(legacy_only.to_frame()).reason is Reason.MISSING_SECURITY

    monitor = SecureCsms(keyring, Store(":memory:"), clock=clock, mode=Mode.MONITOR)
    v = monitor.receive(legacy_only.to_frame())
    assert v.accepted and v.legacy

    warn = SecureCsms(keyring, Store(":memory:"), clock=clock, mode=Mode.WARN)
    assert warn.receive(legacy_only.to_frame()).accepted


def test_migration_stats_counts_legacy_vs_upgraded(lab):
    _, gw, be, store, txid = lab
    be.receive(_upgraded_stop(gw, txid).to_frame())
    stats = store.migration_stats()
    assert stats["upgraded_messages"] >= 1
