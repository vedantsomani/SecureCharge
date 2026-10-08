"""Deterministic (canonical) JSON.

A MAC is computed over bytes, but a message is a JSON object. If the gateway
and backend encoded the same object differently, genuine messages would fail;
if one message had several encodings, parsers could disagree on its meaning.
So exactly one encoding is allowed: sorted keys, no whitespace, ASCII only,
integers only (no floats/NaN), no duplicate keys. This is the project-specific
SC-JSON-1 encoding, NOT RFC 8785/JCS (Unicode sorting/escaping differs).
"""

from __future__ import annotations

import json
from typing import Any


class CanonicalizationError(ValueError):
    """A value cannot be canonically encoded, or bytes are not canonical JSON."""


MAX_BYTES = 65_536
MAX_DEPTH = 24
MAX_INTEGER = 2**53 - 1


def _check(value: Any, path: str = "$", depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise CanonicalizationError("message nesting exceeds limit")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"{path}: object keys must be strings")
            _check(key, path, depth + 1)
            _check(item, f"{path}.{key}", depth + 1)
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _check(item, f"{path}[{index}]", depth + 1)
    elif isinstance(value, float):
        raise CanonicalizationError(f"{path}: floats are not allowed (use paise / Wh)")
    elif not isinstance(value, (str, int, type(None))):
        raise CanonicalizationError(f"{path}: unsupported type {type(value).__name__}")
    elif isinstance(value, str) and any(0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise CanonicalizationError("lone Unicode surrogate")
    elif type(value) is int and abs(value) > MAX_INTEGER:
        raise CanonicalizationError("integer outside interoperable range")


def canonical_json(value: Any) -> bytes:
    _check(value)
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode(
        "ascii"
    )
    if len(encoded) > MAX_BYTES:
        raise CanonicalizationError("message exceeds 64 KiB limit")
    return encoded


def parse_json(data: bytes | str) -> Any:
    """Strict wire parsing; whitespace/key order may differ from MAC encoding."""
    try:
        raw = data.encode("utf-8") if isinstance(data, str) else data
        if len(raw) > MAX_BYTES:
            raise CanonicalizationError("message exceeds 64 KiB limit")
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_no_duplicates,
            parse_float=_refuse_float,
            parse_constant=_refuse_constant,
        )
        _check(value)
        return value
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise CanonicalizationError(f"invalid wire JSON: {exc}") from None


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalizationError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _refuse_float(literal: str) -> float:
    raise CanonicalizationError("floats are not allowed")


def _refuse_constant(literal: str) -> float:
    raise CanonicalizationError(f"{literal} is not allowed")


def parse_canonical(data: bytes | str) -> Any:
    """Parse JSON, accepting it only if it is byte-for-byte canonical."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise CanonicalizationError("message contains non-ASCII bytes") from None
    try:
        value = json.loads(
            text,
            object_pairs_hook=_no_duplicates,
            parse_float=_refuse_float,
            parse_constant=_refuse_constant,
        )
    except CanonicalizationError:
        raise
    except (ValueError, RecursionError) as exc:
        raise CanonicalizationError(f"invalid JSON: {exc}") from None
    if canonical_json(value) != data:
        raise CanonicalizationError("valid JSON, but not in canonical form")
    return value
