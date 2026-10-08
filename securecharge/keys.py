"""Gateway key management: symmetric HMAC keys with key IDs for rotation."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping

from .crypto import MIN_KEY_BYTES, generate_key, key_fingerprint

KEY_ID_RE = re.compile(r"[A-Za-z0-9_.-]{1,32}")
ENV_VAR = "SECURECHARGE_KEYS"


class KeyConfigError(ValueError):
    pass


class Keyring:
    """Maps key IDs to secret keys.

    The gateway signs with ``active_kid``; the backend accepts any key still in
    its ring. Rotation without downtime: add the new key to the backend, switch
    the gateway to it, then retire the old key.
    """

    def __init__(self, keys: Mapping[str, bytes], active_kid: str, owners: Mapping[str, str] | None = None) -> None:
        if not keys:
            raise KeyConfigError("keyring is empty")
        for kid, key in keys.items():
            if not KEY_ID_RE.fullmatch(kid):
                raise KeyConfigError(f"invalid key id {kid!r}")
            if not isinstance(key, bytes) or len(key) < MIN_KEY_BYTES:
                raise KeyConfigError(f"key {kid!r} must be at least {MIN_KEY_BYTES} bytes")
        if active_kid not in keys:
            raise KeyConfigError(f"active key {active_kid!r} is not in the keyring")
        self._keys = dict(keys)
        self.active_kid = active_kid
        self._owners = dict(owners) if owners is not None else {kid: "CP-01" for kid in keys}
        if set(self._owners) != set(keys) or any(
            not isinstance(cp, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", cp) for cp in self._owners.values()
        ):
            raise KeyConfigError("every key must have exactly one valid charger owner")

    @classmethod
    def generate(cls, kid: str = "gw-1", charge_point_id: str = "CP-01") -> Keyring:
        return cls({kid: generate_key()}, kid, {kid: charge_point_id})

    @classmethod
    def from_env(cls, environ: Mapping[str, str] = os.environ) -> Keyring | None:
        """Parse SECURECHARGE_KEYS="gw-2:<hex>,gw-1:<hex>" (first entry is active)."""
        raw = environ.get(ENV_VAR, "").strip()
        if not raw:
            return None
        keys: dict[str, bytes] = {}
        for item in raw.split(","):
            kid, sep, hex_key = item.strip().partition(":")
            if not sep:
                raise KeyConfigError(f"{ENV_VAR} entries must look like kid:hexkey")
            try:
                keys[kid] = bytes.fromhex(hex_key)
            except ValueError:
                raise KeyConfigError(f"key {kid!r} is not valid hex") from None
        cp = environ.get("SECURECHARGE_CP_ID", "CP-01")
        return cls(keys, next(iter(keys)), {kid: cp for kid in keys})

    def authorized(self, kid: str, charge_point_id: str) -> bool:
        return self._owners.get(kid) == charge_point_id

    def key(self, kid: str) -> bytes | None:
        return self._keys.get(kid)

    @property
    def active_key(self) -> bytes:
        return self._keys[self.active_kid]

    @property
    def kids(self) -> list[str]:
        return list(self._keys)

    def with_key(self, kid: str, key: bytes, *, activate: bool = False) -> Keyring:
        return Keyring(
            {**self._keys, kid: key},
            kid if activate else self.active_kid,
            {**self._owners, kid: self._owners[self.active_kid]},
        )

    def without_key(self, kid: str) -> Keyring:
        return Keyring(
            {k: v for k, v in self._keys.items() if k != kid},
            self.active_kid,
            {k: v for k, v in self._owners.items() if k != kid},
        )

    def fingerprints(self) -> dict[str, str]:
        return {kid: key_fingerprint(key) for kid, key in self._keys.items()}

    def __repr__(self) -> str:
        # Never put key material in a repr: reprs end up in logs and tracebacks.
        return f"Keyring(active={self.active_kid!r}, fingerprints={self.fingerprints()})"
