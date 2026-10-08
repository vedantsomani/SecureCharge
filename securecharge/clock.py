"""Injectable clocks so freshness checks can be tested deterministically."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Protocol


class Clock(Protocol):
    def now(self) -> int:
        """Current Unix time in whole seconds."""
        ...


class SystemClock:
    def now(self) -> int:
        return int(time.time())


@dataclass
class FakeClock:
    current: int

    def now(self) -> int:
        return self.current

    def advance(self, seconds: int) -> None:
        self.current += seconds


@dataclass(frozen=True)
class OffsetClock:
    """Another clock shifted by a fixed offset (a message wrapped in the past,
    or a gateway whose clock was pushed forward)."""

    base: Clock
    offset_seconds: int

    def now(self) -> int:
        return self.base.now() + self.offset_seconds
