"""Trusted charger-local adapter: vendor envelope in, SC2 envelope out."""

from __future__ import annotations
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from . import security
from .clock import Clock, SystemClock
from .keys import Keyring
from .legacy import CHECKSUMS, check_integrity
from .messages import MessageError
from .serialization import CanonicalizationError
from .transport import Envelope
from .storage import Store
from .verdict import Layer, Reason, Verdict


@dataclass(frozen=True)
class GatewayResult:
    verdict: Verdict
    message: Envelope | None = None

    @property
    def forwarded(self) -> bool:
        return self.message is not None

    @property
    def frame(self) -> dict[str, Any] | None:
        return self.message.to_frame() if self.message else None


class MigrationGateway:
    def __init__(
        self,
        keyring: Keyring,
        clock: Clock | None = None,
        store: Store | None = None,
        legacy_algorithm: str = "md5",
        nonce_factory: Callable[[], str] | None = None,
    ) -> None:
        if legacy_algorithm not in CHECKSUMS:
            raise ValueError("unknown legacy algorithm")
        self.keyring, self.clock, self.store = keyring, clock or SystemClock(), store
        self.legacy_algorithm = legacy_algorithm
        self._new_nonce = nonce_factory or security.new_nonce

    def process(self, frame: Any, charge_point_id: str = "CP-01") -> GatewayResult:
        now = self.clock.now()
        try:
            message = Envelope.from_frame(frame)
            reason, detail, checked = check_integrity(message, self.legacy_algorithm)
            if checked is None:
                return self._result(Verdict(Layer.GATEWAY, reason, detail, legacy=True), now, charge_point_id)
            signed = security.attach(
                message, self.keyring, ts=now, nonce=self._new_nonce(), charge_point_id=charge_point_id
            )
            return self._result(
                Verdict(Layer.GATEWAY, Reason.ACCEPTED, "vendor checksum checked; SC2 signed"),
                now,
                charge_point_id,
                signed,
            )
        except (MessageError, CanonicalizationError, security.ExtensionError) as exc:
            return self._result(Verdict(Layer.GATEWAY, Reason.MALFORMED, str(exc)), now, charge_point_id)

    def _result(self, verdict: Verdict, now: int, cp: str, message: Envelope | None = None) -> GatewayResult:
        if self.store:
            self.store.log(verdict, at=now, charge_point_id=cp)
        return GatewayResult(verdict, message)
