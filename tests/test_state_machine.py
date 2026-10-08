"""Generated multi-step sessions: model invariants survive changing delivery order."""

from hypothesis import settings
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule
from securecharge.backend import Mode, SecureCsms
from securecharge.clock import FakeClock
from securecharge.keys import Keyring
from securecharge.messages import example_start, example_stop
from securecharge.legacy import add_legacy_integrity
from securecharge.gateway import MigrationGateway
from securecharge.storage import Store
from securecharge.verdict import Reason


class ChargingMachine(RuleBasedStateMachine):
    def __init__(self):
        super().__init__()
        self.store = Store()
        self.keys = Keyring.generate()
        self.clock = FakeClock(1_790_000_900)
        self.backend = SecureCsms(self.keys, self.store, clock=self.clock, mode=Mode.MONITOR)
        self.gateway = MigrationGateway(self.keys, clock=self.clock)
        self.tx = None
        self.uid = 0
        self.enrolled = False
        self.bill_count = 0
        self.last_committed = None

    def next_uid(self):
        self.uid += 1
        return f"state-{self.uid}"

    def protect(self, call):
        return self.gateway.process(add_legacy_integrity(call).to_frame()).message

    @rule()
    def start_session(self):
        message = self.protect(example_start(unique_id=self.next_uid()))
        v = self.backend.receive(message.to_frame())
        if self.tx is None:
            assert v.accepted
            self.tx = v.facts["transaction_id"]
            self.enrolled = True
            self.last_committed = message
        else:
            assert v.reason is Reason.INVALID_MESSAGE

    @rule()
    def close_session(self):
        message = self.protect(example_stop(transaction_id=self.tx or 999999, unique_id=self.next_uid()))
        v = self.backend.receive(message.to_frame())
        if self.tx is None:
            assert v.reason is Reason.INVALID_MESSAGE
        else:
            assert v.accepted
            self.tx = None
            self.bill_count += 1
            self.enrolled = True
            self.last_committed = message

    @rule()
    def captured_replay(self):
        if self.last_committed is not None:
            assert self.backend.receive(self.last_committed.to_frame()).reason is Reason.REPLAY

    @rule()
    def try_legacy_fallback(self):
        message = add_legacy_integrity(example_start(unique_id=self.next_uid()))
        v = self.backend.receive(message.to_frame())
        if self.enrolled:
            assert v.reason is Reason.MISSING_SECURITY
        elif self.tx is None:
            assert v.accepted and v.legacy
            self.tx = v.facts["transaction_id"]
        else:
            assert v.reason is Reason.INVALID_MESSAGE

    @invariant()
    def one_bill_per_closed_session_and_monotonic_enrollment(self):
        rows = self.store.ledger_rows()
        assert len(rows) == self.bill_count
        assert len({row["transaction_id"] for row in rows}) == self.bill_count
        assert self.store.security_required("CP-01") == self.enrolled
        assert all(row["amount_paise"] == 15000 for row in rows)

    def teardown(self):
        self.store.close()


TestChargingMachine = ChargingMachine.TestCase
TestChargingMachine.settings = settings(max_examples=50, stateful_step_count=30, deadline=None)
