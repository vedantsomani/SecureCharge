import asyncio
import ssl
import pytest
from websockets.asyncio.client import connect
from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed, InvalidStatus, InvalidMessage
from securecharge.deployment import ConnectionPolicy, listener_context, upstream_context
from securecharge.keys import Keyring
from securecharge.pki import create_lab_pki


@pytest.mark.parametrize(
    "url",
    [
        "ws://127.0.0.1:9000.evil.example",
        "ws://127.0.0.1.evil.example:9000",
        "ws://localhost@evil.example:9000",
        "ws://10.0.0.2:9000",
        "wss://example/path",
        "ws://localhost:9000?redirect=x",
        "ws://localhost:99999",
        "https://localhost:9000",
    ],
)
def test_remote_plaintext_and_ambiguous_origins_rejected(url):
    with pytest.raises(ValueError):
        upstream_context(url)


def test_exposed_listener_requires_client_authentication():
    with pytest.raises(ValueError, match="mutual TLS"):
        listener_context("0.0.0.0", "unused.pem", "unused-key.pem")
    with pytest.raises(ValueError, match="client-cert"):
        upstream_context("wss://backend.example")


def test_mutual_tls_authorizes_identity_and_rejects_missing_cert(tmp_path):
    pki = create_lab_pki(tmp_path / "pki", charger="CP-01")
    wrong_ca = create_lab_pki(tmp_path / "other")
    keys = Keyring({"a": b"a" * 32, "b": b"b" * 32}, "a", {"a": "CP-01", "b": "CP-02"})
    server_tls = listener_context("127.0.0.1", pki["server_cert"], pki["server_key"], pki["ca"])
    tls = upstream_context("wss://localhost", pki["ca"], pki["client_cert"], pki["client_key"])
    anonymous = ssl.create_default_context(cafile=pki["ca"])
    untrusted = upstream_context("wss://localhost", wrong_ca["ca"], pki["client_cert"], pki["client_key"])
    policy = ConnectionPolicy(keys, mutual_tls=True)

    async def scenario():
        async def echo(socket):
            async for data in socket:
                await socket.send(data)

        async with serve(
            policy.guard(echo), "127.0.0.1", 0, ssl=server_tls, process_request=policy.handshake
        ) as server:
            origin = f"wss://localhost:{server.sockets[0].getsockname()[1]}"
            async with connect(origin + "/CP-01", ssl=tls, proxy=None) as socket:
                await socket.send("authorized")
                assert await socket.recv() == "authorized"
            with pytest.raises(InvalidStatus) as error:
                async with connect(origin + "/CP-02", ssl=tls, proxy=None):
                    pass
            assert error.value.response.status_code == 403
            for path in ("/UNKNOWN", "/CP-01/extra", "/CP-01?x=1"):
                with pytest.raises(InvalidStatus):
                    async with connect(origin + path, ssl=tls, proxy=None):
                        pass
            with pytest.raises((OSError, ConnectionClosed, InvalidMessage, EOFError)):
                async with connect(origin + "/CP-01", ssl=anonymous, proxy=None) as socket:
                    await socket.send("unauthorized")
                    await socket.recv()
            with pytest.raises(ssl.SSLCertVerificationError):
                async with connect(origin + "/CP-01", ssl=untrusted, proxy=None):
                    pass
        assert policy.active == 0

    asyncio.run(scenario())


def test_connection_capacity_and_rate_limit(tmp_path):
    policy = ConnectionPolicy(Keyring.generate(), max_connections=1, rate=1, burst=1)

    async def scenario():
        async def echo(socket):
            async for data in socket:
                await socket.send(data)

        async with serve(policy.guard(echo), "127.0.0.1", 0, process_request=policy.handshake) as server:
            url = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}/CP-01"
            async with connect(url, proxy=None) as first:
                with pytest.raises(InvalidStatus) as error:
                    async with connect(url, proxy=None):
                        pass
                assert error.value.response.status_code == 503
                await first.send("one")
                assert await first.recv() == "one"
                await first.send("two")
                with pytest.raises(ConnectionClosed) as closed:
                    await first.recv()
                assert closed.value.rcvd.code == 1008
        assert policy.active == 0

    asyncio.run(scenario())
