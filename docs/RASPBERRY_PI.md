# Raspberry Pi retrofit deployment and real measurements

This profile runs the gateway on your Pi. No physical charger measurements or
Pi performance numbers are claimed until you execute it there. It does not
provide a GPIO/serial adapter for a real energy meter or modify charger firmware.

## 1. Prepare the Pi

Use Raspberry Pi OS 64-bit with Python 3.11 or later. Copy the project without
the Windows `.venv`, private keys, state databases or cached bytecode.

```bash
sudo apt update
sudo apt install python3-venv python3-pip
cd ~/securecharge
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
.venv/bin/python -m securecharge network-demo
.venv/bin/python scripts/run_pilot.py --no-dashboard
```

Package installation is the only setup that needs administrator access; the
prototype runs as an ordinary user. The loopback experiment creates both endpoints
on the Pi and verifies standard responses, tamper rejection and one-bill retries.

## 2. Generate and protect a charger-specific key

```bash
.venv/bin/python -m securecharge keygen --out secrets/pi.keys.json --charger CP-01 --kid pi-01-v1
chmod 600 secrets/pi.keys.json
```

The command creates a new file exclusively and never prints key bytes. Treat the
file as a secret; transfer its contents to the backend through a protected channel.
Unix creation mode is 0600; Windows users must set an appropriate filesystem ACL.
Each key ID is mapped to exactly one charger. A backend key configuration may
contain several charger-owned keys; the gateway configuration needs its own key.
For rotation, add a new key/owner to the backend, switch the gateway's active ID,
wait beyond the permitted in-flight interval, then remove the retired key.

## 3. Run separate local services

Terminal 1:

```bash
.venv/bin/python -m securecharge serve backend --keys secrets/pi.keys.json --port 9000 --database state/pi.sqlite
```

Terminal 2:

```bash
.venv/bin/python -m securecharge serve gateway --keys secrets/pi.keys.json --port 9001 --upstream ws://127.0.0.1:9000
```

Terminal 3:

```bash
.venv/bin/python -m securecharge charger-demo --gateway ws://127.0.0.1:9001 --pause-before-stop 15
```

The frontend charger simulator connects to `ws://127.0.0.1:9001/CP-01` using
`ocpp1.6`. The private link uses `securecharge.sc2`. The gateway assumes its local
input is trusted and models the vendor checksum internally. A real charger needs
a correctly engineered trusted adapter for its actual vendor checksum format.

## 4. Connect a remote backend using WSS

Supply a valid server certificate/key on the backend:

```bash
.venv/bin/python -m securecharge serve backend --keys secrets/backend.keys.json --host 0.0.0.0 --port 9000 --database state/backend.sqlite --cert certs/server.pem --tls-key certs/server-key.pem --client-ca certs/client-ca.pem
```

On the Pi, connect with the relevant CA trust file:

```bash
.venv/bin/python -m securecharge serve gateway --keys secrets/pi.keys.json --port 9001 --upstream wss://your-backend-host:9000 --ca certs/backend-ca.pem --client-cert certs/gateway.pem --client-key certs/gateway-key.pem --outbox state/blackbox.sqlite
```

Certificate identity must match the backend host. The client certificate must
have URI SAN `urn:securecharge:charger:CP-01`. The service rejects remote plaintext
upstreams and requires client certificates on exposed listeners. Identity authorization,
connection and message bounds are implemented; full certificate lifecycle/revocation,
fleet operations and complete OCPP security-profile validation remain deployment work.
Use [the pilot guide](PILOT.md) for short-lived lab certificates and exact commands.

Both service files under `deploy/` are hardened **templates**. Set the real
backend hostname, service account, installation path and certificate files before
installing it. Its example `.invalid` hostname intentionally cannot be deployed
unchanged. The systemd template has not been executed in this Windows workspace.

## 5. Collect paper-quality hardware evidence

```bash
.venv/bin/python scripts/measure_pi.py --out artifacts/pi-run-01 --samples 500
.venv/bin/python scripts/measure_pi.py --out artifacts/pi-run-02 --samples 500
.venv/bin/python scripts/measure_pi.py --out artifacts/pi-run-03 --samples 500
.venv/bin/python scripts/verify_artifacts.py artifacts/pi-run-01
```

The Pi script requires an actual Raspberry Pi board model. It refuses to label
desktop observations as Pi data. Every directory must be new. Use three independent
runs; compare run-level medians rather than treating every within-run observation
as an independent device. Record model, RAM, OS, Python/OpenSSL versions, power
supply, cooling, CPU governor, ambient conditions and other processes.

For thermal context where `vcgencmd` is available:

```bash
vcgencmd measure_temp
vcgencmd get_throttled
```

Save these observations beside the results before and after each run. Do not infer
power/energy use from latency: use an external power instrument if you report it.
`tracemalloc` numbers are Python allocation peaks, not complete RSS/firmware RAM.
No firmware flash-size number can be inferred from a Python gateway benchmark.

## 6. Demonstrate the retrofit

Show the Pi acting as a gateway, its saved experiment metadata, the valid OCPP
messages, collision substitution and checksum recomputation as separate attacks,
and the durable CSMS refusing tampering/replay. Disconnect/restart the backend and
show retained enrollment and replay protection. A live physical meter/charger
demonstration is additional work, not implied by the loopback simulator.

The black box preserves requests and verified receipts across outages, with no
invented success responses. Collect a real Pi `pilot-demo` run, inspect the four
custody events/one-bill result, export an independently retained anchor, and measure
actual process/power-loss behavior. The current automated run models outage/lost
reply/reopen on its recorded host; it is not a physical power-cut result.
