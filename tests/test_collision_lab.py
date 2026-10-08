"""A genuine collision substitution with an explicit binary hash boundary."""

import base64
import copy
from securecharge.collision import COLLISION_A, COLLISION_B, EXPECTED_MD5
from securecharge.collision_lab import legacy_accepts, make_call, report
from securecharge.crypto import md5_hex


def test_substitution_changes_billing_without_changing_pinned_digest():
    r = report()
    assert r["legacy_accepts_both"]
    assert r["honest_meter_stop"] - r["substituted_meter_stop"] == 128
    assert r["honest_bill_paise"] > r["substituted_bill_paise"]
    assert r["secure_substitution_reason"] == "BAD_TAG"
    assert not r["full_json_md5_equal"]
    assert not r["sha256_record_equal"] and not r["sha3_record_equal"]
    for frame in (r["honest_ocpp"], r["substituted_ocpp"]):
        assert "customData" not in frame[3]


def test_hash_boundary_is_decoded_record_not_base64_or_json():
    assert md5_hex(COLLISION_A) == md5_hex(COLLISION_B) == EXPECTED_MD5
    assert md5_hex(base64.b64encode(COLLISION_A)) != md5_hex(base64.b64encode(COLLISION_B))


def test_random_corruption_fails_the_unchanged_pinned_md5():
    altered = bytearray(COLLISION_A)
    altered[0] ^= 1
    assert not legacy_accepts(make_call(bytes(altered)), EXPECTED_MD5)


def test_meterstop_must_match_embedded_counter():
    call = make_call(COLLISION_A)
    payload = copy.deepcopy(call.payload)
    payload["meterStop"] -= 1
    assert not legacy_accepts(call.with_payload(payload), EXPECTED_MD5)
