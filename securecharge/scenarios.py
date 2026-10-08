"""The demo as data: each case run through the old and new system side by side.

For every scenario the same charging session is driven through two worlds with
the same attacker action, and we record what each world billed:

* legacy lane:  charger -> [attacker] -> legacy CSMS (MD5 only)
* secure lane:  charger -> gateway -> [attacker] -> secure CSMS (HMAC-SHA3-256)

A lane is "fooled" if it accepted a maliciously altered message (or billed a
replayed one twice). The CLI, the tests and the dashboard all read these
results, so what is presented is exactly what is tested.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from . import attacks
from .backend import DEFAULT_MAX_SKEW_SECONDS, DEFAULT_TTL_SECONDS, Mode, SecureCsms
from .clock import FakeClock
from .gateway import MigrationGateway
from .keys import Keyring
from .legacy import LegacyCsms, add_legacy_integrity
from .messages import example_start, example_stop, format_inr, price_for
from .storage import Store
from .transport import Envelope

SESSION_START_AT = 1_790_000_000
STOP_AT = 1_790_000_900
METER_START = 48_000
HONEST_METER_STOP = 60_500  # 12.5 kWh sold -> Rs 150.00
FORGED_METER_STOP = 48_100  # 0.1 kWh -> Rs 1.20
HONEST_ENERGY = HONEST_METER_STOP - METER_START
FORGED_ENERGY = FORGED_METER_STOP - METER_START


class Attack(str, Enum):
    NONE = "none"
    TAMPER_KEEP_MD5 = "tamper_keep_md5"
    TAMPER_RECOMPUTE_MD5 = "tamper_recompute_md5"
    REPLAY = "replay"
    DOWNGRADE_STRIP = "downgrade_strip"
    HASH_AS_TAG = "hash_as_tag"
    FOREIGN_KEY = "foreign_key"
    EXPIRED = "expired"
    FUTURE_TIMESTAMP = "future_timestamp"
    REFRESH_TIMESTAMP = "refresh_timestamp"
    CHANGE_NONCE = "change_nonce"


TITLES: dict[Attack, str] = {
    Attack.NONE: "Honest session (no attacker)",
    Attack.TAMPER_KEEP_MD5: "Lower meterStop, keep the old MD5",
    Attack.TAMPER_RECOMPUTE_MD5: "Lower meterStop and recompute the MD5",
    Attack.REPLAY: "Replay a valid StopTransaction",
    Attack.DOWNGRADE_STRIP: "Strip the SHA-3 tag (downgrade to MD5-only)",
    Attack.HASH_AS_TAG: "Replace the tag with a plain SHA3-256 hash",
    Attack.FOREIGN_KEY: "Re-sign the tag with the attacker's own key",
    Attack.EXPIRED: "Deliver a captured message after it has expired",
    Attack.FUTURE_TIMESTAMP: "Message pre-dated from a clock pushed 1 h ahead",
    Attack.REFRESH_TIMESTAMP: "Rewrite the timestamp to make it look fresh",
    Attack.CHANGE_NONCE: "Replay with a new nonce to dodge replay detection",
}


@dataclass(frozen=True)
class LaneResult:
    name: str
    applicable: bool
    accepted: bool
    reason: str
    detail: str
    billed_paise: int | None
    fooled: bool
    note: str
    delivered: list | None = None  # the OCPP frame actually sent to this backend
    honest: list | None = None  # the untampered frame, for side-by-side display


@dataclass(frozen=True)
class ScenarioResult:
    attack: Attack
    title: str
    honest_paise: int
    forged_paise: int
    legacy: LaneResult
    secure: LaneResult

    @property
    def defended(self) -> bool:
        return not self.secure.fooled


@dataclass
class Lab:
    """One simulated deployment's configuration."""

    mode: Mode = Mode.ENFORCE
    ttl_seconds: int = DEFAULT_TTL_SECONDS
    max_skew_seconds: int = DEFAULT_MAX_SKEW_SECONDS
    algorithm: str = "md5"

    def _keyring(self) -> Keyring:
        return Keyring.generate()


# --- legacy lane -------------------------------------------------------------


def _legacy_lane(lab: Lab, attack: Attack) -> LaneResult:
    from .legacy import CHECKSUM_LABELS

    name = f"Legacy CSMS ({CHECKSUM_LABELS[lab.algorithm]} checksum)"
    if attack in (
        Attack.DOWNGRADE_STRIP,
        Attack.HASH_AS_TAG,
        Attack.FOREIGN_KEY,
        Attack.EXPIRED,
        Attack.FUTURE_TIMESTAMP,
        Attack.REFRESH_TIMESTAMP,
        Attack.CHANGE_NONCE,
    ):
        return LaneResult(
            name,
            False,
            False,
            "N/A",
            "no SHA-3 tag, timestamp or nonce exists here",
            None,
            False,
            "not applicable to the legacy system",
        )

    clock = FakeClock(STOP_AT)
    store = Store(":memory:")
    csms = LegacyCsms(store, lab.algorithm, clock=clock)
    start = add_legacy_integrity(example_start(meter_start=METER_START, at=SESSION_START_AT), lab.algorithm)
    txid = csms.receive(start.to_frame(), "CP-09").facts["transaction_id"]
    honest = add_legacy_integrity(
        example_stop(transaction_id=txid, meter_stop=HONEST_METER_STOP, at=STOP_AT), lab.algorithm
    )

    if attack is Attack.NONE:
        v = csms.receive(honest.to_frame(), "CP-09")
        return _legacy_result(name, v, malicious=False)
    if attack is Attack.TAMPER_KEEP_MD5:
        forged = attacks.tamper_meter_stop(honest, FORGED_METER_STOP, recompute_md5=False)
        v = csms.receive(forged.to_frame(), "CP-09")
        return _legacy_result(name, v, malicious=True)
    if attack is Attack.TAMPER_RECOMPUTE_MD5:
        forged = attacks.tamper_meter_stop(honest, FORGED_METER_STOP, recompute_md5=True)
        v = csms.receive(forged.to_frame(), "CP-09")
        return _legacy_result(name, v, malicious=True)
    if attack is Attack.REPLAY:
        csms.receive(honest.to_frame(), "CP-09")  # first, legitimate
        v = csms.receive(attacks.replay(honest).to_frame(), "CP-09")  # the replay
        fooled = v.accepted
        note = (
            "re-billed a replayed message"
            if fooled
            else f"no replay defense; saved only by transaction state ({v.reason.value})"
        )
        return LaneResult(
            name, True, v.accepted, v.reason.value, v.detail, v.facts["amount_paise"] if v.facts else None, fooled, note
        )
    raise AssertionError(attack)


def _legacy_result(name: str, verdict, *, malicious: bool) -> LaneResult:
    billed = verdict.facts["amount_paise"] if verdict.facts else None
    fooled = bool(malicious and verdict.accepted and billed == price_for(FORGED_ENERGY))
    if fooled:
        note = f"accepted the forged reading, billed {format_inr(billed)}"
    elif malicious:
        note = "forgery refused by the checksum"
    else:
        note = f"billed {format_inr(billed)}" if billed is not None else "accepted"
    return LaneResult(name, True, verdict.accepted, verdict.reason.value, verdict.detail, billed, fooled, note)


# --- secure lane -------------------------------------------------------------


def _secure_lane(lab: Lab, attack: Attack) -> LaneResult:
    name = f"Secure CSMS (HMAC-SHA3-256, {lab.mode.value})"
    gw_clock = FakeClock(STOP_AT)
    be_clock = FakeClock(STOP_AT)
    keyring = lab._keyring()
    store = Store(":memory:")
    gateway = MigrationGateway(keyring, clock=gw_clock, store=store, legacy_algorithm=lab.algorithm)
    csms = SecureCsms(
        keyring,
        store,
        clock=be_clock,
        mode=lab.mode,
        ttl_seconds=lab.ttl_seconds,
        max_skew_seconds=lab.max_skew_seconds,
        legacy_algorithm=lab.algorithm,
    )

    start = add_legacy_integrity(example_start(meter_start=METER_START, at=SESSION_START_AT), lab.algorithm)
    txid = csms.receive(gateway.process(start.to_frame(), "CP-01").frame, "CP-01").facts["transaction_id"]
    honest_legacy = add_legacy_integrity(
        example_stop(transaction_id=txid, meter_stop=HONEST_METER_STOP, at=STOP_AT), lab.algorithm
    )
    upgraded = Envelope.from_frame(gateway.process(honest_legacy.to_frame(), "CP-01").frame)

    malicious = attack is not Attack.NONE
    if attack in (Attack.NONE, Attack.REPLAY):
        delivered = upgraded
    elif attack is Attack.TAMPER_RECOMPUTE_MD5:
        delivered = attacks.tamper_meter_stop(upgraded, FORGED_METER_STOP, recompute_md5=True)
    elif attack is Attack.TAMPER_KEEP_MD5:
        delivered = attacks.tamper_meter_stop(upgraded, FORGED_METER_STOP, recompute_md5=False)
    elif attack is Attack.DOWNGRADE_STRIP:
        delivered = attacks.strip_extension(upgraded)
    elif attack is Attack.HASH_AS_TAG:
        delivered = attacks.tag_with_plain_hash(upgraded, FORGED_METER_STOP)
    elif attack is Attack.FOREIGN_KEY:
        delivered = attacks.resign_with_foreign_key(upgraded, FORGED_METER_STOP)
    elif attack is Attack.REFRESH_TIMESTAMP:
        # The message is old enough to be expired; the attacker rewrites sc.ts to
        # "now" to make it look fresh. Because ts is covered by the tag, this fails.
        be_clock.current = STOP_AT + lab.ttl_seconds + 60
        delivered = attacks.refresh_timestamp(upgraded, be_clock.now())
    elif attack is Attack.CHANGE_NONCE:
        delivered = attacks.change_nonce(upgraded)
    elif attack is Attack.EXPIRED:
        delivered = upgraded
        be_clock.current = STOP_AT + lab.ttl_seconds + lab.max_skew_seconds + 60
    elif attack is Attack.FUTURE_TIMESTAMP:
        # A gateway whose clock was pushed forward signs a message dated 1 h ahead.
        future_gw = MigrationGateway(
            keyring, clock=FakeClock(STOP_AT + 3600), store=store, legacy_algorithm=lab.algorithm
        )
        delivered = Envelope.from_frame(future_gw.process(honest_legacy.to_frame(), "CP-01").frame)
    else:
        raise AssertionError(attack)

    if attack is Attack.REPLAY:
        csms.receive(upgraded.to_frame(), "CP-01")  # first, legitimate
        delivered_frame = attacks.replay(upgraded).to_frame()  # the replay
        v = csms.receive(delivered_frame, "CP-01")
    else:
        delivered_frame = delivered.to_frame()
        v = csms.receive(delivered_frame, "CP-01")

    billed = v.facts["amount_paise"] if v.facts else None
    fooled = bool(malicious and v.accepted and billed is not None and billed != price_for(HONEST_ENERGY))
    if attack is Attack.REPLAY and v.accepted:
        fooled = True
    if fooled:
        note = "FOOLED"
    elif malicious and not v.accepted:
        note = f"blocked: {v.reason.value}"
    elif malicious:
        note = "accepted by migration policy without authentication"
    else:
        note = f"billed {format_inr(billed)}" if billed is not None else "accepted"
    return LaneResult(
        name,
        True,
        v.accepted,
        v.reason.value,
        v.detail,
        billed,
        fooled,
        note,
        delivered=delivered_frame,
        honest=upgraded.to_frame(),
    )


# --- public API --------------------------------------------------------------


def run(attack: Attack, lab: Lab | None = None) -> ScenarioResult:
    lab = lab or Lab()
    return ScenarioResult(
        attack=attack,
        title=TITLES[attack],
        honest_paise=price_for(HONEST_ENERGY),
        forged_paise=price_for(FORGED_ENERGY),
        legacy=_legacy_lane(lab, attack),
        secure=_secure_lane(lab, attack),
    )


def run_all(lab: Lab | None = None) -> list[ScenarioResult]:
    return [run(attack, lab) for attack in Attack]
