"""Speed comparison for the hashes and MACs in this project.

The headline point is a cautionary one: MD5 is *fast*. Being slow is not why it
was abandoned - it was abandoned because it is broken. SHA3-256 costs a little
more per message, but on an EV message of a few hundred bytes the difference is
a handful of microseconds, far below anything a charging session would notice.
So the migration buys a large security gain at a negligible speed cost, which
is the argument this benchmark exists to make with numbers.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass
from typing import Callable

from .crypto import generate_key

_KEY = generate_key()

ALGORITHMS: dict[str, Callable[[bytes], object]] = {
    "MD5": lambda d: hashlib.md5(d, usedforsecurity=False).digest(),
    "SHA-1": lambda d: hashlib.sha1(d, usedforsecurity=False).digest(),
    "SHA-256": lambda d: hashlib.sha256(d).digest(),
    "SHA-512": lambda d: hashlib.sha512(d).digest(),
    "SHA3-256": lambda d: hashlib.sha3_256(d).digest(),
    "HMAC-SHA-256": lambda d: hmac.digest(_KEY, d, "sha256"),
    "HMAC-SHA3-256": lambda d: hmac.digest(_KEY, d, "sha3_256"),
}
SECURE = {"SHA-256", "SHA-512", "SHA3-256", "HMAC-SHA-256", "HMAC-SHA3-256"}
KEYED = {"HMAC-SHA-256", "HMAC-SHA3-256"}

# A typical signed OCPP message is a few hundred bytes; a firmware image is large.
DEFAULT_SIZES = (256, 4096, 1_048_576)


@dataclass(frozen=True)
class Row:
    algorithm: str
    size_bytes: int
    ns_per_op: float
    ops_per_sec: float
    mb_per_sec: float
    secure: bool
    keyed: bool


def _time_one(fn: Callable[[bytes], object], data: bytes, iterations: int) -> float:
    fn(data)  # warm up code paths and caches
    best = float("inf")
    for _ in range(3):  # take the best of a few batches to cut scheduler noise
        start = time.perf_counter_ns()
        for _ in range(iterations):
            fn(data)
        elapsed = time.perf_counter_ns() - start
        best = min(best, elapsed / iterations)
    return best


def _iterations_for(size: int) -> int:
    if size <= 1024:
        return 50_000
    if size <= 65_536:
        return 5_000
    return 200


def run(sizes: tuple[int, ...] = DEFAULT_SIZES, iterations: int | None = None) -> list[Row]:
    rows: list[Row] = []
    for size in sizes:
        data = bytes(bytearray((i * 131 + 7) & 0xFF for i in range(size)))
        iters = iterations or _iterations_for(size)
        for name, fn in ALGORITHMS.items():
            ns = _time_one(fn, data, iters)
            rows.append(
                Row(
                    algorithm=name,
                    size_bytes=size,
                    ns_per_op=ns,
                    ops_per_sec=1e9 / ns if ns else 0.0,
                    mb_per_sec=(size / (ns / 1e9)) / 1e6 if ns else 0.0,
                    secure=name in SECURE,
                    keyed=name in KEYED,
                )
            )
    return rows


def format_table(rows: list[Row]) -> str:
    lines = [f"{'algorithm':<16}{'size':>10}{'ns/op':>12}{'ops/sec':>14}{'MB/s':>10}  note"]
    lines.append("-" * 78)
    for r in rows:
        size = f"{r.size_bytes}B" if r.size_bytes < 1024 else f"{r.size_bytes // 1024}K"
        note = "secure" if r.secure else "BROKEN"
        if r.keyed:
            note += ", keyed MAC"
        lines.append(
            f"{r.algorithm:<16}{size:>10}{r.ns_per_op:>12.0f}{r.ops_per_sec:>14,.0f}{r.mb_per_sec:>10.0f}  {note}"
        )
    return "\n".join(lines)
