"""Recoverable forwarding: persist first, freshly sign retries, verify receipts."""

from __future__ import annotations
import asyncio
import logging
import random
from urllib.parse import urlsplit
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed
from .blackbox import BlackBox, JournalError
from .gateway import MigrationGateway
from .legacy import add_legacy_integrity
from .messages import OcppCall
from .serialization import parse_json

logger = logging.getLogger(__name__)


class Forwarder:
    def __init__(
        self, journal: BlackBox, gateway: MigrationGateway, upstream: str, tls=None, *, retry_min=0.5, retry_max=30
    ):
        if retry_min <= 0 or retry_max < retry_min:
            raise ValueError("invalid retry interval")
        self.journal, self.gateway, self.upstream, self.tls = journal, gateway, upstream.rstrip("/"), tls
        self.retry_min, self.retry_max = retry_min, retry_max
        self.wake = asyncio.Event()
        self.last_error = None
        self.attempts = 0
        self.delivered = 0

    async def deliver_one(self) -> bool:
        pending = await asyncio.to_thread(self.journal.pending)
        if not pending:
            return False
        item = pending[0]
        call = OcppCall.from_frame(item["call"])
        result = self.gateway.process(add_legacy_integrity(call).to_frame(), item["cp"])
        if not result.forwarded:
            raise JournalError("queued call cannot be authenticated with current gateway key")
        self.attempts += 1
        # No path appending to an arbitrary base URL; deployment validation rejects paths.
        url = urlsplit(self.upstream)._replace(path="/" + item["cp"]).geturl()
        async with connect(
            url,
            ssl=self.tls,
            subprotocols=["securecharge.sc2"],
            max_size=65536,
            max_queue=4,
            compression=None,
            proxy=None,
            open_timeout=5,
            close_timeout=2,
        ) as socket:
            await socket.send(result.message.to_bytes().decode("ascii"))
            reply = parse_json(await asyncio.wait_for(socket.recv(), 10))
            await asyncio.to_thread(self.journal.confirm, item["id"], result.message, reply, self.gateway.clock.now())
        self.delivered += 1
        self.last_error = None
        return True

    async def run(self):
        delay = self.retry_min
        while True:
            self.wake.clear()
            try:
                if await self.deliver_one():
                    delay = self.retry_min
                    continue
                await self.wake.wait()
            except (OSError, TimeoutError, ConnectionClosed) as exc:
                # Never retry malformed or unauthenticated receipts. Those are fatal.
                self.last_error = type(exc).__name__
                logger.warning("upstream unavailable (%s); request remains in custody", self.last_error)
                try:
                    await asyncio.wait_for(self.wake.wait(), delay + random.SystemRandom().uniform(0, delay / 4))
                except TimeoutError:
                    pass
                delay = min(delay * 2, self.retry_max)

    async def wait_response(self, identifier: str, timeout: float = 20) -> list:
        async def wait():
            while True:
                frame = await asyncio.to_thread(self.journal.response, identifier)
                if frame is not None:
                    return frame
                await asyncio.sleep(0.05)

        return await asyncio.wait_for(wait(), timeout)
