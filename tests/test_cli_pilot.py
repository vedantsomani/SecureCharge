"""Exercise installed-style CLI wiring as separate actual service processes."""

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from securecharge.blackbox import BlackBox
from securecharge.cli import load_keyring
from securecharge.pki import create_lab_pki
from securecharge.storage import Store


def test_cli_backend_gateway_charger_mutual_tls_and_persistent_audit(tmp_path):
    root = Path(__file__).resolve().parent.parent
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    keys = tmp_path / "pilot.keys.json"
    subprocess.run(
        [sys.executable, "-m", "securecharge", "keygen", "--out", str(keys)],
        cwd=root,
        capture_output=True,
        check=True,
        timeout=15,
        creationflags=flags,
    )
    pki = create_lab_pki(tmp_path / "pki")
    with socket.socket() as first, socket.socket() as second:
        first.bind(("127.0.0.1", 0))
        second.bind(("127.0.0.1", 0))
        backend_port, gateway_port = first.getsockname()[1], second.getsockname()[1]
    processes = []
    db, outbox = tmp_path / "backend.sqlite", tmp_path / "blackbox.sqlite"

    def launch(arguments, port):
        process = subprocess.Popen(
            [sys.executable, "-m", "securecharge", "serve", *arguments],
            cwd=root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            creationflags=flags,
        )
        processes.append(process)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError(process.stderr.read().decode())
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    return
            except OSError:
                time.sleep(0.05)
        raise AssertionError("service did not become ready")

    try:
        launch(
            [
                "backend",
                "--keys",
                str(keys),
                "--port",
                str(backend_port),
                "--database",
                str(db),
                "--cert",
                pki["server_cert"],
                "--tls-key",
                pki["server_key"],
                "--client-ca",
                pki["ca"],
            ],
            backend_port,
        )
        launch(
            [
                "gateway",
                "--keys",
                str(keys),
                "--port",
                str(gateway_port),
                "--outbox",
                str(outbox),
                "--upstream",
                f"wss://localhost:{backend_port}",
                "--ca",
                pki["ca"],
                "--client-cert",
                pki["client_cert"],
                "--client-key",
                pki["client_key"],
            ],
            gateway_port,
        )
        client = subprocess.run(
            [
                sys.executable,
                "-m",
                "securecharge",
                "charger-demo",
                "--gateway",
                f"ws://127.0.0.1:{gateway_port}",
                "--timeout",
                "30",
            ],
            cwd=root,
            capture_output=True,
            check=True,
            timeout=40,
            creationflags=flags,
        )
        result = json.loads(client.stdout.decode().split("\n", 1)[1])
        assert result["retry_response_identical"]
    finally:
        for process in reversed(processes):
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
            process.stderr.close()
    store = Store(db)
    journal = BlackBox(outbox, load_keyring(keys))
    try:
        assert len(store.ledger_rows()) == 1 and store.ledger_rows()[0]["amount_paise"] == 15000
        assert journal.anchor()["sequence"] == 4 and not journal.pending()
    finally:
        journal.close()
        store.close()
    audit = subprocess.run(
        [
            sys.executable,
            "-m",
            "securecharge",
            "blackbox-audit",
            "--keys",
            str(keys),
            "--outbox",
            str(outbox),
            "--export-anchor",
            str(tmp_path / "anchor.json"),
        ],
        cwd=root,
        capture_output=True,
        check=True,
        timeout=15,
        creationflags=flags,
    )
    assert b"Verified 4 custody events; 0 pending requests" in audit.stdout
