"""Legacy MD5 integrity and the SecureCharge SHA-3 extension."""

from __future__ import annotations

import pytest

from securecharge import attacks, security
from securecharge.keys import Keyring
from securecharge.legacy import add_legacy_integrity, check_integrity
from securecharge.messages import example_stop
from securecharge.verdict import Reason


def test_legacy_accepts_untampered():
    call = add_legacy_integrity(example_stop())
    reason, _, checked = check_integrity(call, "md5")
    assert reason is Reason.ACCEPTED and checked is not None


def test_legacy_rejects_tamper_with_stale_checksum():
    call = add_legacy_integrity(example_stop())
    forged = attacks.tamper_meter_stop(call, 48_100, recompute_md5=False)
    reason, _, checked = check_integrity(forged, "md5")
    assert reason is Reason.CHECKSUM_MISMATCH and checked is None


def test_legacy_is_fooled_when_checksum_recomputed():
    # The core weakness being demonstrated: an unkeyed checksum proves nothing.
    call = add_legacy_integrity(example_stop())
    forged = attacks.tamper_meter_stop(call, 48_100, recompute_md5=True)
    reason, _, checked = check_integrity(forged, "md5")
    assert reason is Reason.ACCEPTED and checked is not None


@pytest.fixture
def keyring():
    return Keyring({"gw-1": b"k" * 32}, "gw-1")


def _signed(keyring):
    call = add_legacy_integrity(example_stop())
    return security.attach(call, keyring, ts=1_790_000_900, nonce="a" * 32)


def test_attach_then_verify_ok(keyring):
    assert security.verify(_signed(keyring), keyring)["kid"] == "gw-1"


def test_tamper_breaks_the_tag(keyring):
    forged = attacks.tamper_meter_stop(_signed(keyring), 48_100, recompute_md5=True)
    with pytest.raises(security.BadTag):
        security.verify(forged, keyring)


def test_hash_instead_of_mac_is_not_accepted(keyring):
    forged = attacks.tag_with_plain_hash(_signed(keyring), 48_100)
    with pytest.raises(security.BadTag):
        security.verify(forged, keyring)


def test_foreign_key_is_not_accepted(keyring):
    forged = attacks.resign_with_foreign_key(_signed(keyring), 48_100)
    with pytest.raises(security.BadTag):
        security.verify(forged, keyring)


def test_version_and_key_errors(keyring):
    with pytest.raises(security.UnsupportedVersion):
        security.verify(attacks.downgrade_version(_signed(keyring)), keyring)
    other = Keyring({"gw-2": b"x" * 32}, "gw-2")
    with pytest.raises(security.UnknownKeyId):
        security.verify(_signed(keyring), other)


def test_timestamp_and_nonce_are_bound(keyring):
    with pytest.raises(security.BadTag):
        security.verify(attacks.refresh_timestamp(_signed(keyring), 1_799_999_999), keyring)
    with pytest.raises(security.BadTag):
        security.verify(attacks.change_nonce(_signed(keyring), "b" * 32), keyring)
