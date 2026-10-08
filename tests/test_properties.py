"""Property-based tests (Hypothesis).

These assert the central security property over thousands of generated cases
rather than a handful of hand-picked ones: once a message is signed, no change
an attacker can make to a protected field is ever accepted by the verifier.
"""

from __future__ import annotations

import copy

from hypothesis import given, settings
from hypothesis import strategies as st

from securecharge import security
from securecharge.keys import Keyring
from securecharge.messages import OcppCall
from securecharge.attacks import _set_sc
from dataclasses import replace
from securecharge.serialization import canonical_json, parse_canonical

KEYRING = Keyring({"gw-1": b"k" * 32}, "gw-1")

# JSON-ish values the canonical codec accepts (ints, ascii strings, bools, None).
json_scalars = st.one_of(st.integers(-(10**9), 10**9), st.booleans(), st.none(), st.text("abcXYZ0129 _-", max_size=12))
json_values = st.recursive(
    json_scalars,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(st.text("abcXYZ_", min_size=1, max_size=6), children, max_size=4),
    ),
    max_leaves=12,
)


@given(json_values)
@settings(max_examples=300)
def test_canonical_json_is_idempotent(value):
    data = canonical_json(value)
    assert canonical_json(parse_canonical(data)) == data


def _signed_stop(meter_stop: int, ts: int = 1_790_000_900, nonce: str = "a" * 32) -> OcppCall:
    call = OcppCall(
        "mid", "StopTransaction", {"transactionId": 1, "meterStop": meter_stop, "timestamp": "2026-10-02T00:00:00Z"}
    )
    return security.attach(call, KEYRING, ts=ts, nonce=nonce)


@given(meter_stop=st.integers(0, 100_000), new_stop=st.integers(0, 100_000))
@settings(max_examples=300)
def test_changing_meter_stop_always_breaks_the_tag(meter_stop, new_stop):
    signed = _signed_stop(meter_stop)
    assert security.verify(signed, KEYRING)["ts"] == 1_790_000_900  # unchanged verifies
    if new_stop == meter_stop:
        return
    payload = copy.deepcopy(signed.payload)
    payload["meterStop"] = new_stop
    try:
        security.verify(signed.with_payload(payload), KEYRING)
        raised = False
    except security.ExtensionError:
        raised = True
    assert raised, "a changed meterStop was accepted under the original tag"


@given(flip=st.integers(0, 63), xor=st.integers(1, 15))
@settings(max_examples=200)
def test_flipping_any_tag_nibble_is_rejected(flip, xor):
    signed = _signed_stop(60_000)
    sc = dict(signed.security)
    nibbles = list(sc["tag"])
    nibbles[flip] = "%x" % (int(nibbles[flip], 16) ^ xor)
    sc["tag"] = "".join(nibbles)
    try:
        security.verify(_set_sc(signed, sc), KEYRING)
        raised = False
    except security.ExtensionError:
        raised = True
    assert raised


@given(field=st.sampled_from(["uid", "action", "legacy", "cp", "ts", "nonce"]))
@settings(max_examples=100)
def test_all_transport_context_fields_are_authenticated(field):
    signed = _signed_stop(60_000)
    if field == "uid":
        changed = replace(signed, call=OcppCall("another", signed.action, signed.payload))
    elif field == "action":
        changed = replace(signed, call=OcppCall(signed.unique_id, "MeterValues", signed.payload))
    elif field == "legacy":
        changed = replace(signed, legacy={"alg": "md5", "value": "0" * 32})
    else:
        sc = dict(signed.security)
        sc[field] = {"cp": "CP-02", "ts": sc["ts"] + 1, "nonce": "b" * 32}[field]
        changed = _set_sc(signed, sc)
    import pytest

    with pytest.raises(security.ExtensionError):
        security.verify(changed, KEYRING)
