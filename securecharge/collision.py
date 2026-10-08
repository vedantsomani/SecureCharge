"""A real MD5 collision: two different 128-byte inputs with the same MD5.

The pair was published by Xiaoyun Wang and Hongbo Yu ("How to Break MD5 and
Other Hash Functions", EUROCRYPT 2005). It is embedded here as data; this
module does not search for collisions, it only shows a known one.

Because MD5 processes input block by block (Merkle-Damgard), appending the
same suffix to both inputs keeps the collision - which is why collisions in
random-looking blocks matter for real files.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from .crypto import hmac_sha3_256

COLLISION_A = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b"
    "d8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70"
)
COLLISION_B = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b"
    "d8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70"
)
EXPECTED_MD5 = "79054025255fb1a26e4bc422aef54eb4"
SAMPLE_NAMES = ("md5_collision_a.bin", "md5_collision_b.bin")
_DEMO_KEY = bytes(range(32))  # public demo key: only shows that HMAC also differs


@dataclass(frozen=True)
class CollisionReport:
    a: bytes
    b: bytes
    differing_offsets: tuple[int, ...]
    digests: dict[str, tuple[str, str]]  # algorithm -> (digest of a, digest of b)
    suffix_keeps_collision: bool

    def same(self, algorithm: str) -> bool:
        first, second = self.digests[algorithm]
        return first == second

    @property
    def md5_collides(self) -> bool:
        return self.a != self.b and self.same("MD5")


def analyse(a: bytes = COLLISION_A, b: bytes = COLLISION_B, suffix: bytes = b" | tariff: Rs 12/kWh") -> CollisionReport:
    digest_functions = {
        "MD5": lambda d: hashlib.md5(d, usedforsecurity=False).hexdigest(),
        "SHA-1": lambda d: hashlib.sha1(d, usedforsecurity=False).hexdigest(),
        "SHA-256": lambda d: hashlib.sha256(d).hexdigest(),
        "SHA3-256": lambda d: hashlib.sha3_256(d).hexdigest(),
        "HMAC-SHA3-256": lambda d: hmac_sha3_256(_DEMO_KEY, d).hex(),
    }
    return CollisionReport(
        a=a,
        b=b,
        differing_offsets=tuple(i for i, (x, y) in enumerate(zip(a, b)) if x != y),
        digests={name: (fn(a), fn(b)) for name, fn in digest_functions.items()},
        suffix_keeps_collision=digest_functions["MD5"](a + suffix) == digest_functions["MD5"](b + suffix),
    )


def write_samples(directory: str | Path) -> tuple[Path, Path]:
    """Write the pair to disk so it can be checked with certutil / md5sum."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    first, second = (directory / name for name in SAMPLE_NAMES)
    first.write_bytes(COLLISION_A)
    second.write_bytes(COLLISION_B)
    return first, second
