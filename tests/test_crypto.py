"""Primitive correctness: known-answer vectors and the hand-written HMAC."""

from __future__ import annotations

import os

import pytest

from securecharge import crypto


def test_known_hash_vectors():
    assert crypto.md5_hex(b"abc") == "900150983cd24fb0d6963f7d28e17f72"
    assert crypto.sha1_hex(b"abc") == "a9993e364706816aba3e25717850c26c9cd0d89d"
    assert crypto.sha256_hex(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert crypto.sha3_256_hex(b"") == "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"


def test_hmac_sha3_256_nist_vector():
    # NIST CAVP HMAC-SHA3-256, key length < block length.
    key = bytes(range(32))
    msg = b"Sample message for keylen<blocklen"
    expected = "4fe8e202c4f058e8dddc23d8c34e467343e23555e24fc2f025d598f558f67205"
    assert crypto.hmac_sha3_256_hex(key, msg) == expected


@pytest.mark.parametrize("n", [0, 1, 31, 32, 100, 135, 136, 137, 200])
def test_reference_hmac_matches_stdlib(n):
    key = os.urandom(n)
    msg = os.urandom(50)
    assert crypto.hmac_sha3_256_reference(key, msg) == crypto.hmac_sha3_256(key, msg)


def test_constant_time_verify():
    key = crypto.generate_key()
    tag = crypto.hmac_sha3_256_hex(key, b"data")
    assert crypto.verify_hmac_sha3_256(key, b"data", tag)
    assert not crypto.verify_hmac_sha3_256(key, b"data!", tag)
    assert not crypto.verify_hmac_sha3_256(key, b"data", "zz")  # not even hex
    assert not crypto.verify_hmac_sha3_256(crypto.generate_key(), b"data", tag)


def test_key_fingerprint_is_stable_and_hides_key():
    key = crypto.generate_key()
    fp = crypto.key_fingerprint(key)
    assert fp == crypto.key_fingerprint(key)
    assert len(fp) == 16 and key.hex()[:16] != fp
