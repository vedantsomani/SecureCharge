"""Canonical JSON: one encoding per value, strict parsing."""

from __future__ import annotations

import pytest

from securecharge.serialization import CanonicalizationError, canonical_json, parse_canonical


def test_canonical_sorts_keys_and_drops_whitespace():
    assert canonical_json({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_canonical_is_ascii_only():
    assert canonical_json({"x": "₹"}) == b'{"x":"\\u20b9"}'


def test_roundtrip_is_idempotent():
    value = {"z": [1, 2, {"k": "v"}], "a": 0, "n": None}
    data = canonical_json(value)
    assert canonical_json(parse_canonical(data)) == data


def test_floats_are_rejected_both_ways():
    with pytest.raises(CanonicalizationError):
        canonical_json({"x": 1.5})
    with pytest.raises(CanonicalizationError):
        parse_canonical(b'{"x":1.5}')


def test_bool_is_allowed_but_distinct_from_int():
    # json still encodes bools; the point is ints are not silently bools elsewhere.
    assert canonical_json({"x": True}) == b'{"x":true}'


def test_duplicate_keys_are_rejected():
    with pytest.raises(CanonicalizationError):
        parse_canonical(b'{"a":1,"a":2}')


def test_non_canonical_input_is_rejected():
    with pytest.raises(CanonicalizationError):
        parse_canonical(b'{"a": 1}')  # extra space
    with pytest.raises(CanonicalizationError):
        parse_canonical(b'{"b":1,"a":2}')  # keys out of order


def test_non_ascii_bytes_rejected():
    with pytest.raises(CanonicalizationError):
        parse_canonical('{"x":"₹"}'.encode("utf-8"))
