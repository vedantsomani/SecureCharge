"""Real localhost WebSocket walkthrough and Raspberry Pi adapter services.

Frontend uses ocpp1.6 with unchanged CALL/CALLRESULT frames. The private
gateway/backend link uses securecharge.sc2 envelopes, not the OCPP subprotocol.
No TLS is used in the loopback experiment; remote deployment requires WSS.
"""

from __future__ import annotations
import asyncio
import json
import ssl
from typing import Any
from contextlib import suppress
from websockets.asyncio.client import connect
from websockets.asyncio.server import serve
from .backend import SecureCsms
from .gateway import MigrationGateway
from .legacy import add_legacy_integrity
from .messages import OcppCall, example_start, example_stop
from .protocol import response_for
from .serialization import parse_json, canonical_json
from .transport import Envelope
from .keys import Keyring
from .storage import Store
from . import security
from .deployment import ConnectionPolicy, charger_from_path, listener_context, upstream_context
from .blackbox import BlackBox, JournalError, QueueFull, RequestConflict
from .resilience import Forwarder


def _cp(socket: Any) -> str:
    return charger_from_path(socket.request.path)


def backend_handler(backend: SecureCsms):
    async def handle(socket):
        cp = _cp(socket)
        async for wire in socket:
            try:
                request = Envelope.from_frame(wire)
                verdict = await asyncio.to_thread(backend.receive, wire, cp)
                frame = response_for(request.call, verdict)
                reply = security.sign_reply(frame, request, backend.keyring, backend.clock.now())
                await socket.send(canonical_json(reply).decode("ascii"))
            except (ValueError, TypeError):
                await socket.close(code=1008, reason="invalid SC2 request")
                return

    return handle


def gateway_handler(gateway: MigrationGateway, backend_url: str, tls: ssl.SSLContext | None = None):
    async def handle(socket):
        cp = _cp(socket)
        async with connect(
            f"{backend_url.rstrip('/')}/{cp}",
            subprotocols=["securecharge.sc2"],
            ssl=tls,
            max_size=65536,
            open_timeout=5,
            proxy=None,
        ) as upstream:
            async for wire in socket:
                try:
                    call = OcppCall.from_frame(parse_json(wire)).validate()
                    # Trusted local vendor adapter supplies the modeled checksum.
                    result = gateway.process(add_legacy_integrity(call).to_frame(), cp)
                    if not result.forwarded:
                        await socket.send(json.dumps(response_for(call, result.verdict)))
                        continue
                    await upstream.send(result.message.to_bytes().decode("ascii"))
                    reply = parse_json(await asyncio.wait_for(upstream.recv(), timeout=10))
                    frame = security.verify_reply(reply, result.message, gateway.keyring, gateway.clock.now())
                    await socket.send(json.dumps(frame))
                except (ValueError, TypeError):
                    await socket.close(code=1008, reason="invalid frame or authentication")
                    return

    return handle


def resilient_gateway_handler(forwarder: Forwarder, *, response_timeout=20):
    async def handle(socket):
        cp = _cp(socket)
        async for wire in socket:
            try:
                call = OcppCall.from_frame(parse_json(wire)).validate()
                identifier = await asyncio.to_thread(forwarder.journal.enqueue, call, cp)
                forwarder.wake.set()
                response = await forwarder.wait_response(identifier, response_timeout)
                await socket.send(json.dumps(response))
            except TimeoutError:
                # Request may already have committed remotely. Never manufacture failure/success.
                await socket.close(code=1013, reason="request persisted; reconnect and retry SAME request ID")
                return
            except (QueueFull, RequestConflict) as exc:
                await socket.send(json.dumps([4, call.unique_id, "GenericError", str(exc), {}]))
            except JournalError:
                forwarder.wake.set()
                await socket.close(code=1011, reason="custody journal unavailable; operator action required")
                raise
            except (ValueError, TypeError):
                await socket.close(code=1008, reason="invalid OCPP frame")
                return

    return handle


async def loopback() -> dict[str, Any]:
    keyring = Keyring.generate()
    store = Store()
    backend = SecureCsms(keyring, store)
    gateway = MigrationGateway(keyring)
    try:
        async with serve(
            backend_handler(backend), "127.0.0.1", 0, subprotocols=["securecharge.sc2"], max_size=65536
        ) as csms:
            backend_port = csms.sockets[0].getsockname()[1]
            async with serve(
                gateway_handler(gateway, f"ws://127.0.0.1:{backend_port}"),
                "127.0.0.1",
                0,
                subprotocols=["ocpp1.6"],
                max_size=65536,
            ) as gw:
                gateway_port = gw.sockets[0].getsockname()[1]
                async with connect(f"ws://127.0.0.1:{gateway_port}/CP-01", subprotocols=["ocpp1.6"]) as charger:
                    start = example_start()
                    await charger.send(json.dumps(start.to_frame()))
                    opened = parse_json(await asyncio.wait_for(charger.recv(), 10))
                    txid = opened[2]["transactionId"]
                    stop = example_stop(transaction_id=txid)
                    await charger.send(json.dumps(stop.to_frame()))
                    closed = parse_json(await asyncio.wait_for(charger.recv(), 10))
                    # Retry same business request: gateway creates fresh nonce, effects cached.
                    await charger.send(json.dumps(stop.to_frame()))
                    retry = parse_json(await asyncio.wait_for(charger.recv(), 10))
                # Explicit actual-wire tamper to backend over the private transport.
                tampered = gateway.process(
                    add_legacy_integrity(example_start(unique_id="wire-tamper", connector_id=2)).to_frame()
                ).message
                bad = tampered.to_frame()
                bad["ocpp"][3]["meterStart"] += 1
                async with connect(
                    f"ws://127.0.0.1:{backend_port}/CP-01", subprotocols=["securecharge.sc2"]
                ) as attacker:
                    await attacker.send(json.dumps(bad))
                    blocked = parse_json(await asyncio.wait_for(attacker.recv(), 10))["ocpp"]
                return {
                    "transport": "actual localhost WebSockets",
                    "frontend_subprotocol": "ocpp1.6",
                    "private_subprotocol": "securecharge.sc2",
                    "tls": False,
                    "start_response": opened,
                    "stop_response": closed,
                    "retry_response": retry,
                    "tamper_response": blocked,
                    "ledger_rows": len(store.ledger_rows()),
                    "billed_paise": store.ledger_rows()[0]["amount_paise"],
                }
    finally:
        store.close()


async def run_service(
    role: str,
    keyring: Keyring,
    *,
    host: str = "127.0.0.1",
    port: int = 9000,
    database: str = "state/securecharge.sqlite",
    upstream: str = "ws://127.0.0.1:9000",
    cert: str | None = None,
    private_key: str | None = None,
    ca: str | None = None,
    client_ca: str | None = None,
    client_cert: str | None = None,
    client_key: str | None = None,
    outbox: str = "state/gateway-blackbox.sqlite",
    capacity: int = 5000,
    max_connections: int = 16,
    response_timeout: float = 20,
) -> None:
    if response_timeout <= 0:
        raise ValueError("response timeout must be positive")
    server_tls = listener_context(host, cert, private_key, client_ca)
    policy = ConnectionPolicy(keyring, mutual_tls=bool(client_ca), max_connections=max_connections)
    journal = worker = None
    if role == "backend":
        store = Store(database)
        handler = backend_handler(SecureCsms(keyring, store))
        protocols = ["securecharge.sc2"]
    else:
        client_tls = upstream_context(upstream, ca, client_cert, client_key)
        store = None
        journal = BlackBox(outbox, keyring, capacity=capacity)
        forwarder = Forwarder(journal, MigrationGateway(keyring), upstream, client_tls)
        handler = resilient_gateway_handler(forwarder, response_timeout=response_timeout)
        protocols = ["ocpp1.6"]
    try:
        async with serve(
            policy.guard(handler),
            host,
            port,
            ssl=server_tls,
            subprotocols=protocols,
            process_request=policy.handshake,
            origins=[None],
            max_size=65536,
            max_queue=4,
            compression=None,
            open_timeout=5,
            close_timeout=2,
            server_header=None,
        ):
            print(f"SecureCharge {role} listening on {host}:{port}", flush=True)
            if journal:
                worker = asyncio.create_task(forwarder.run())
                await worker  # Integrity errors stop the service rather than acknowledge corrupted state.
            else:
                await asyncio.Future()
    finally:
        if worker:
            worker.cancel()
            with suppress(asyncio.CancelledError):
                await worker
        if journal:
            journal.close()
        if store:
            store.close()
