"""Explicit transport policy for a bounded lab/pilot service, not certification."""

from __future__ import annotations
import asyncio
from http import HTTPStatus
import ssl
import time
from urllib.parse import urlsplit
from . import security
from .keys import Keyring

LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def charger_from_path(path: str) -> str:
    parsed = urlsplit(path)
    cp = parsed.path.removeprefix("/")
    if parsed.query or parsed.fragment or parsed.netloc or parsed.path != "/" + cp or not security.CP_RE.fullmatch(cp):
        raise ValueError("expected /CHARGER-ID without query or extra path")
    return cp


def upstream_context(url: str, ca=None, cert=None, key=None) -> ssl.SSLContext | None:
    parsed = urlsplit(url)
    if parsed.scheme not in ("ws", "wss") or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("invalid upstream URL")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("upstream must be an origin URL without path or query")
    _ = parsed.port  # Validate port, including malformed/overflow values.
    if parsed.scheme == "ws":
        if parsed.hostname not in LOOPBACK:
            raise ValueError("remote backend connections require wss://")
        if cert or key or ca:
            raise ValueError("TLS client options require wss://")
        return None
    if not cert or not key:
        raise ValueError("wss:// requires --client-cert and --client-key for mutual TLS")
    context = ssl.create_default_context(cafile=ca)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    return context


def listener_context(host: str, cert=None, key=None, client_ca=None) -> ssl.SSLContext | None:
    if host not in LOOPBACK and (not cert or not key or not client_ca):
        raise ValueError("non-loopback listeners require TLS and --client-ca (mutual TLS)")
    if not cert and not key:
        if client_ca:
            raise ValueError("--client-ca requires server certificate/key")
        return None
    if not cert or not key:
        raise ValueError("both TLS certificate and private key are required")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    if client_ca:
        context.load_verify_locations(client_ca)
        context.verify_mode = ssl.CERT_REQUIRED
    return context


class ConnectionPolicy:
    def __init__(self, keyring: Keyring, *, mutual_tls=False, max_connections=16, rate=20, burst=40):
        if min(max_connections, rate, burst) < 1:
            raise ValueError("connection/rate limits must be positive")
        self.keyring, self.mutual_tls = keyring, mutual_tls
        self.max_connections, self.rate, self.burst = max_connections, rate, burst
        self.active = 0

    def handshake(self, socket, request):
        try:
            cp = charger_from_path(request.path)
            if not any(self.keyring.authorized(kid, cp) for kid in self.keyring.kids):
                raise ValueError("unprovisioned charger")
            if self.mutual_tls:
                tls = socket.transport.get_extra_info("ssl_object")
                certificate = tls.getpeercert() if tls else {}
                principals = [value for kind, value in certificate.get("subjectAltName", ()) if kind == "URI"]
                if principals != ["urn:securecharge:charger:" + cp]:
                    raise ValueError("certificate charger identity mismatch")
        except ValueError:
            return socket.respond(HTTPStatus.FORBIDDEN, "charger connection not authorized\n")
        if self.active >= self.max_connections:
            return socket.respond(HTTPStatus.SERVICE_UNAVAILABLE, "connection capacity reached\n")
        return None

    def guard(self, handler):
        policy = self

        class LimitedSocket:
            def __init__(self, socket):
                self.socket, self.tokens, self.last = socket, float(policy.burst), time.monotonic()

            def __getattr__(self, name):
                return getattr(self.socket, name)

            def __aiter__(self):
                return self

            async def __anext__(self):
                from websockets.exceptions import ConnectionClosed

                try:
                    wire = await asyncio.wait_for(self.socket.recv(), 120)
                except ConnectionClosed:
                    raise StopAsyncIteration from None
                except TimeoutError:
                    await self.socket.close(code=1008, reason="idle timeout")
                    raise StopAsyncIteration from None
                now = time.monotonic()
                self.tokens = min(float(policy.burst), self.tokens + (now - self.last) * policy.rate)
                self.last = now
                if self.tokens < 1:
                    await self.socket.close(code=1008, reason="message rate exceeded")
                    raise StopAsyncIteration
                self.tokens -= 1
                return wire

        async def limited(socket):
            if self.active >= self.max_connections:
                await socket.close(code=1013, reason="connection capacity reached")
                return
            self.active += 1
            try:
                await handler(LimitedSocket(socket))
            finally:
                self.active -= 1

        return limited
