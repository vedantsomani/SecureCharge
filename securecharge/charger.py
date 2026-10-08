"""Lab charger client for a separate Pi gateway; no physical charging control."""

from __future__ import annotations
import asyncio
import json
import time
import uuid
from urllib.parse import urlsplit
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed
from .deployment import upstream_context
from .messages import example_start, example_stop
from .serialization import parse_json
from .security import CP_RE


async def simulate(gateway: str, cp: str = "CP-01", *, ca=None, cert=None, key=None, pause=0, timeout=180) -> dict:
    if not CP_RE.fullmatch(cp) or pause < 0 or timeout <= 0:
        raise ValueError("invalid simulation options")
    tls = upstream_context(gateway, ca, cert, key)
    url = urlsplit(gateway)._replace(path="/" + cp).geturl()
    prefix = uuid.uuid4().hex[:16]

    async def exchange(call):
        async def retry():
            while True:
                try:
                    async with connect(
                        url,
                        ssl=tls,
                        subprotocols=["ocpp1.6"],
                        compression=None,
                        proxy=None,
                        open_timeout=5,
                        close_timeout=2,
                        max_size=65536,
                    ) as socket:
                        await socket.send(json.dumps(call.to_frame()))
                        response = parse_json(await socket.recv())
                        if response[1] != call.unique_id or response[0] not in (3, 4):
                            raise ValueError("response does not match request")
                        return response
                except (OSError, ConnectionClosed):
                    await asyncio.sleep(1)

        return await asyncio.wait_for(retry(), timeout)

    start = example_start(unique_id=prefix + "-start", at=int(time.time()))
    opened = await exchange(start)
    if opened[0] != 3:
        raise ValueError("StartTransaction rejected: " + str(opened))
    print("CSMS confirmed StartTransaction; disconnect backend now to demonstrate recovery.", flush=True)
    await asyncio.sleep(pause)
    stop = example_stop(unique_id=prefix + "-stop", transaction_id=opened[2]["transactionId"], at=int(time.time()))
    closed = await exchange(stop)
    retried = await exchange(stop)
    return {
        "charger": cp,
        "start": opened,
        "stop": closed,
        "retry": retried,
        "retry_response_identical": closed == retried,
        "physical_energy_measured": False,
    }
