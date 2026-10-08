import asyncio
import json
from contextlib import suppress
import pytest
from websockets.asyncio.client import connect
from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed
from securecharge import security
from securecharge.backend import SecureCsms
from securecharge.blackbox import BlackBox
from securecharge.charger import simulate
from securecharge.deployment import ConnectionPolicy
from securecharge.gateway import MigrationGateway
from securecharge.keys import Keyring
from securecharge.messages import example_start
from securecharge.network import backend_handler, resilient_gateway_handler
from securecharge.resilience import Forwarder
from securecharge.storage import Store
from securecharge.clock import FakeClock


def test_long_outage_signs_at_delivery_time_preserving_original_event_time(tmp_path):
    async def scenario():
        keys = Keyring.generate()
        clock = FakeClock(100)
        journal = BlackBox(tmp_path / "queue.sqlite", keys)
        store = Store()
        call = example_start(at=100)
        identifier = journal.enqueue(call, "CP-01")
        clock.advance(86400)
        backend = SecureCsms(keys, store, clock=clock)
        try:
            async with serve(backend_handler(backend), "127.0.0.1", 0, subprotocols=["securecharge.sc2"]) as server:
                forwarder = Forwarder(
                    journal, MigrationGateway(keys, clock=clock), f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"
                )
                await forwarder.deliver_one()
                assert journal.response(identifier)[0] == 3
                assert journal.snapshot()["requests"][identifier]["call"][3]["timestamp"] == call.payload["timestamp"]
                assert store._rows("SELECT started_at FROM transactions")[0]["started_at"] == 100
        finally:
            journal.close()
            store.close()

    asyncio.run(scenario())


def test_separate_charger_frontend_journal_backend_and_cached_retry(tmp_path):
    async def scenario():
        keys = Keyring.generate()
        journal = BlackBox(tmp_path / "queue.sqlite", keys)
        store = Store(tmp_path / "backend.sqlite")
        policy = ConnectionPolicy(keys)
        try:
            async with serve(
                backend_handler(SecureCsms(keys, store)), "127.0.0.1", 0, subprotocols=["securecharge.sc2"]
            ) as server:
                upstream = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"
                forwarder = Forwarder(journal, MigrationGateway(keys), upstream, retry_min=0.01)
                worker = asyncio.create_task(forwarder.run())
                try:
                    async with serve(
                        policy.guard(resilient_gateway_handler(forwarder)),
                        "127.0.0.1",
                        0,
                        process_request=policy.handshake,
                        subprotocols=["ocpp1.6"],
                    ) as gateway:
                        result = await simulate(f"ws://127.0.0.1:{gateway.sockets[0].getsockname()[1]}")
                        assert result["retry_response_identical"]
                        assert len(store.ledger_rows()) == 1
                        assert len(journal.pending()) == 0 and journal.anchor()["sequence"] == 4
                finally:
                    worker.cancel()
                    with suppress(asyncio.CancelledError):
                        await worker
        finally:
            journal.close()
            store.close()

    asyncio.run(scenario())


def test_timeout_closes_connection_with_pending_request_instead_of_success(tmp_path):
    async def scenario():
        keys = Keyring.generate()
        journal = BlackBox(tmp_path / "queue.sqlite", keys)
        forwarder = Forwarder(journal, MigrationGateway(keys), "ws://127.0.0.1:1")
        call = example_start(unique_id="retain-on-timeout")
        try:
            async with serve(
                resilient_gateway_handler(forwarder, response_timeout=0.1), "127.0.0.1", 0, subprotocols=["ocpp1.6"]
            ) as server:
                async with connect(
                    f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}/CP-01", subprotocols=["ocpp1.6"], proxy=None
                ) as socket:
                    await socket.send(json.dumps(call.to_frame()))
                    with pytest.raises(ConnectionClosed) as closed:
                        await socket.recv()
                    assert closed.value.rcvd.code == 1013
            pending = journal.pending()
            assert len(pending) == 1 and pending[0]["call"] == call.to_frame()
            assert journal.response(pending[0]["id"]) is None
        finally:
            journal.close()

    asyncio.run(scenario())


def test_unauthenticated_upstream_receipt_is_fatal_not_retryable(tmp_path):
    async def scenario():
        keys = Keyring.generate()
        journal = BlackBox(tmp_path / "queue.sqlite", keys)
        journal.enqueue(example_start(), "CP-01")

        async def malicious(socket):
            from securecharge.transport import Envelope

            request = Envelope.from_frame(await socket.recv())
            frame = [3, request.unique_id, {"transactionId": 1, "idTagInfo": {"status": "Accepted"}}]
            reply = security.sign_reply(frame, request, keys, 100)
            reply["ocpp"][2]["transactionId"] = 999
            await socket.send(json.dumps(reply))

        try:
            async with serve(malicious, "127.0.0.1", 0, subprotocols=["securecharge.sc2"]) as server:
                forwarder = Forwarder(
                    journal, MigrationGateway(keys), f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"
                )
                with pytest.raises(security.BadTag):
                    await forwarder.run()
                assert len(journal.pending()) == 1 and forwarder.delivered == 0
        finally:
            journal.close()

    asyncio.run(scenario())
