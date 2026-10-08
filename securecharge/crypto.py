"""Hash and MAC primitives.

* A hash (MD5, SHA-256, SHA3-256) has no secret: anyone who edits a message
  can recompute it. It detects accidents, never deliberate tampering - even
  SHA3-256.
* A MAC (HMAC-SHA3-256) mixes in a secret key, so nobody without the key can
  make a valid tag for a modified message.

MD5 is additionally broken as a hash: practical collisions exist
(see securecharge.collision).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

KEY_BYTES = 32
MIN_KEY_BYTES = 16


def md5_hex(data: bytes) -> str:
    """MD5, used only to model the legacy protocol. Broken: collisions are trivial."""
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def sha1_hex(data: bytes) -> str:
    """SHA-1, also deprecated (SHAttered, 2017). Included for the comparison only."""
    return hashlib.sha1(data, usedforsecurity=False).hexdigest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha3_256_hex(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


def hmac_sha3_256(key: bytes, data: bytes) -> bytes:
    return hmac.digest(key, data, "sha3_256")


def hmac_sha3_256_hex(key: bytes, data: bytes) -> str:
    return hmac_sha3_256(key, data).hex()


def verify_hmac_sha3_256(key: bytes, data: bytes, tag_hex: str) -> bool:
    """Constant-time tag check (== would leak, via timing, how much matched)."""
    try:
        tag = bytes.fromhex(tag_hex)
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(hmac_sha3_256(key, data), tag)


def hmac_sha3_256_reference(key: bytes, data: bytes) -> bytes:
    """RFC 2104 HMAC written out by hand, for teaching:

        HMAC(K, m) = H( (K0 xor opad) || H( (K0 xor ipad) || m ) )

    K0 = key zero-padded to the block size; for SHA3-256 that is the sponge
    rate, 136 bytes. Tests check it against the standard library.
    """
    block_size = hashlib.sha3_256().block_size
    if len(key) > block_size:
        key = hashlib.sha3_256(key).digest()
    k0 = key.ljust(block_size, b"\x00")
    inner = hashlib.sha3_256(bytes(b ^ 0x36 for b in k0) + data).digest()
    return hashlib.sha3_256(bytes(b ^ 0x5C for b in k0) + inner).digest()


def generate_key() -> bytes:
    return secrets.token_bytes(KEY_BYTES)


def key_fingerprint(key: bytes) -> str:
    """Short one-way identifier: safe to display, unlike the key."""
    return hashlib.sha3_256(b"SecureCharge key fingerprint\x00" + key).hexdigest()[:16]
