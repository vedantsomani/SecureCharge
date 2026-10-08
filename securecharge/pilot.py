"""Reproducible black-box fault walkthrough over actual mutual-TLS WebSockets."""

from __future__ import annotations
import asyncio
import json
import hashlib
from pathlib import Path
import sqlite3
import tempfile
from contextlib import closing
from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed
from . import security
from .backend import SecureCsms
from .blackbox import BlackBox, JournalError
from .deployment import ConnectionPolicy, listener_context, upstream_context
from .gateway import MigrationGateway
from .keys import Keyring
from .messages import example_start, example_stop
from .pki import create_lab_pki
from .protocol import response_for
from .resilience import Forwarder
from .serialization import canonical_json
from .storage import Store
from .transport import Envelope


async def fault_experiment(out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=False)
    # Private keys, journal and meter/customer data never enter the public artifact directory.
    with tempfile.TemporaryDirectory(prefix="securecharge-pilot-") as private:
        root = Path(private)
        pki = create_lab_pki(root / "pki")
        keys = Keyring.generate()
        store = Store(root / "backend.sqlite")
        backend = SecureCsms(keys, store)
        journal = BlackBox(root / "blackbox.sqlite", keys)
        server_tls = listener_context("127.0.0.1", pki["server_cert"], pki["server_key"], pki["ca"])
        client_tls = upstream_context("wss://localhost", pki["ca"], pki["client_cert"], pki["client_key"])
        policy = ConnectionPolicy(keys, mutual_tls=True)
        lose_once = True

        async def endpoint(socket):
            nonlocal lose_once
            async for wire in socket:
                request = Envelope.from_frame(wire)
                verdict = await asyncio.to_thread(backend.receive, wire, "CP-01")
                if request.action == "StopTransaction" and lose_once:
                    lose_once = False
                    await socket.close(code=1011, reason="injected lost reply AFTER committed bill")
                    return
                reply = security.sign_reply(response_for(request.call, verdict), request, keys, backend.clock.now())
                await socket.send(canonical_json(reply).decode())

        try:
            async with serve(
                policy.guard(endpoint),
                "127.0.0.1",
                0,
                ssl=server_tls,
                process_request=policy.handshake,
                subprotocols=["securecharge.sc2"],
                compression=None,
            ) as server:
                port = server.sockets[0].getsockname()[1]
                forwarder = Forwarder(journal, MigrationGateway(keys), f"wss://localhost:{port}", client_tls)
                start_id = journal.enqueue(example_start(unique_id="pilot-start"), "CP-01")
                await forwarder.deliver_one()
                txid = journal.response(start_id)[2]["transactionId"]
                stop_id = journal.enqueue(example_stop(unique_id="pilot-stop", transaction_id=txid), "CP-01")
                # Actual connection refused at a bound-but-not-listening port, without relying on port 9.
                import socket

                with socket.socket() as unavailable:
                    unavailable.bind(("127.0.0.1", 0))
                    offline = Forwarder(
                        journal, MigrationGateway(keys), f"ws://127.0.0.1:{unavailable.getsockname()[1]}"
                    )
                    try:
                        await offline.deliver_one()
                    except OSError:
                        offline_retained = len(journal.pending()) == 1 and journal.response(stop_id) is None
                    else:
                        raise AssertionError("fault injection did not produce an outage")
                try:
                    await forwarder.deliver_one()
                except ConnectionClosed:
                    pass
                else:
                    raise AssertionError("lost-reply injection did not disconnect")
                committed_before_receipt = len(store.ledger_rows())
                pending_after_commit = len(journal.pending())
                journal.close()
                journal = BlackBox(root / "blackbox.sqlite", keys)
                recovered = Forwarder(journal, MigrationGateway(keys), f"wss://localhost:{port}", client_tls)
                await recovered.deliver_one()
                response = journal.response(stop_id)
                anchor = journal.anchor()
                verified = journal.snapshot(anchor)
                same_id = journal.enqueue(example_stop(unique_id="pilot-stop", transaction_id=txid), "CP-01")
                retry_cached = same_id == stop_id and journal.response(same_id) == response
                ledger_rows = len(store.ledger_rows())
                journal.close()
                # Mutate a committed custody record without access to its authentication key.
                with closing(sqlite3.connect(root / "blackbox.sqlite")) as connection:
                    body = json.loads(connection.execute("SELECT body FROM events WHERE seq=1").fetchone()[0])
                    body["call"][3]["meterStart"] += 1
                    connection.execute("UPDATE events SET body=? WHERE seq=1", (json.dumps(body),))
                    connection.commit()
                try:
                    damaged = BlackBox(root / "blackbox.sqlite", keys)
                except JournalError:
                    tamper_blocked = True
                else:
                    damaged.close()
                    tamper_blocked = False
            result = {
                "transport": "actual localhost mutual-TLS WebSockets; private temporary CA",
                "hardware": "execution host; no physical Pi/charger or power-cut measurement",
                "outage_retains_pending_without_success_ack": offline_retained,
                "backend_bill_committed_before_lost_reply": committed_before_receipt,
                "pending_after_lost_reply": pending_after_commit,
                "restart_recovered_authenticated_receipt": response[0] == 3,
                "retry_uses_same_cached_response": retry_cached,
                "ledger_rows_after_recovery": ledger_rows,
                "journal_events": verified["sequence"],
                "external_anchor_verified": True,
                "tampered_custody_record_rejected_at_startup": tamper_blocked,
                "limitations": [
                    "software-held symmetric keys",
                    "full journal rollback needs independently retained anchor",
                    "restart is journal close/reopen; separate regression test exercises abrupt process exit",
                    "no offline authorization or invented transaction ID",
                    "not OCPP certification",
                ],
            }
            from .research import environment

            result["environment"] = environment()
            result["hardware"] = "recorded execution host; no physical charger or physical power-cut measurement"
            required = [
                offline_retained,
                committed_before_receipt == 1,
                pending_after_commit == 1,
                response[0] == 3,
                retry_cached,
                ledger_rows == 1,
                tamper_blocked,
            ]
            if not all(required):
                raise AssertionError("pilot fault experiment did not satisfy its invariants")
            (out / "pilot-results.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
            source_root = Path(__file__).resolve().parent.parent
            sources = [
                *source_root.glob("securecharge/*.py"),
                *source_root.glob("tests/*.py"),
                *source_root.glob("scripts/*.py"),
                source_root / "dashboard.py",
                source_root / "pyproject.toml",
                *source_root.glob("requirements*.txt"),
            ]
            manifest = {
                "artifact_sha256": {
                    "pilot-results.json": hashlib.sha256((out / "pilot-results.json").read_bytes()).hexdigest()
                },
                "source_sha256": {
                    str(file.relative_to(source_root)).replace("\\", "/"): hashlib.sha256(file.read_bytes()).hexdigest()
                    for file in sorted(sources)
                },
            }
            (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            return result
        finally:
            # Journal may already be closed during deliberate tamper injection.
            journal.close()
            store.close()
