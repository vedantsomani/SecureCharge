# SecureCharge Pi black box: deployment and validation contract

The distinctive experiment is **bill integrity across a network outage and a lost
acknowledgement**, with an authenticated custody record for each accepted CSMS
response. The gateway persists the original OCPP CALL, freshly signs only when
forwarding, and retains the verified response. This combines SHA-3 migration,
recovery and evidence in one retrofit boundary. It is an engineering contribution;
no claim is made that durable queues, mutual TLS or HMAC chains are new inventions.

## Run the reproducible fault experiment

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe scripts/run_pilot.py
```

On the Pi, use `.venv/bin/python` instead. The script creates actual mutual-TLS
WebSocket endpoints with a private, temporary lab CA, then:

1. Obtains a real CSMS StartTransaction response.
2. Persists StopTransaction while an upstream endpoint is unavailable.
3. Reconnects; lets the backend commit its bill; deliberately loses the reply.
4. Closes and reopens the custody database to model gateway restart.
5. Freshly authenticates the same request and recovers its CSMS result.
6. Checks one ledger entry, four authenticated custody events and a cached retry.
7. Modifies a journal record and checks that reopening rejects the alteration.

The automated suite also runs a separate child process that exits abruptly after
its queue commit. This is a process-crash regression, **not a physical power-cut
measurement**. Private CA keys and state stay in a temporary private directory;
only results and content/source manifests are exported. Use a new output directory
for every run. The dashboard's **Pi black box** tab reads the measured results.

## Two local services, ready to move onto the Pi

Generate keys and short-lived lab certificates once:

```bash
python -m securecharge keygen --out secrets/pi.keys.json --charger CP-01 --kid pi-01-v1
python -m securecharge lab-pki --out secrets/lab-pki --charger CP-01 --hostname localhost
```

Terminal 1, backend:

```bash
python -m securecharge serve backend --keys secrets/pi.keys.json --port 9000 --database state/backend.sqlite --cert secrets/lab-pki/backend.pem --tls-key secrets/lab-pki/backend-key.pem --client-ca secrets/lab-pki/ca.pem
```

Terminal 2, gateway:

```bash
python -m securecharge serve gateway --keys secrets/pi.keys.json --port 9001 --upstream wss://localhost:9000 --ca secrets/lab-pki/ca.pem --client-cert secrets/lab-pki/gateway.pem --client-key secrets/lab-pki/gateway-key.pem --outbox state/blackbox.sqlite
```

Terminal 3, simulator:

```bash
python -m securecharge charger-demo --gateway ws://127.0.0.1:9001 --pause-before-stop 15 --timeout 180
```

After the client reports a confirmed start, stop the backend during the pause.
The Pi retains the stop request. Restart the backend within the simulator's
180-second deadline; the same StopTransaction request ID is retried and its
confirmed response recovered. Compare the custody audit and backend ledger.
Run a new simulator command for a new transaction; request IDs are random.

For a Pi/desktop split, provision a server certificate whose SAN matches the
desktop hostname/IP, bind the backend with `--host 0.0.0.0`, and configure the Pi
with `wss://that-host:9000`. The lab generator's `--hostname` supports a DNS name;
production certificate issuance belongs to an operated PKI. Copy only the public
CA, gateway certificate/key and charger HMAC configuration to the Pi. Keep the CA
private key offline. Never publish any private keys or customer/meter journals.

## Authentication and bounded transport

Incoming mutual-TLS certificates must contain exactly one URI SAN:
`urn:securecharge:charger:CP-01`, matching the URL `/CP-01` and a provisioned key
owner. Unprovisioned or mismatched devices are refused before WebSocket upgrade.
Remote listeners require server TLS **and** a trusted client CA. WSS upstreams
require a client certificate/key and verify the server hostname/trust chain.
TLS is at least 1.2. The trusted legacy frontend stays on loopback unless explicitly
configured with mutual TLS; older firmware may require a local serial/network
adapter rather than supporting client certificates itself.

Default limits: 16 active connections, 20 application messages/second with a burst
of 40 per connection, 64 KiB transport messages, four buffered WebSocket frames,
120-second application idle timeout, no WebSocket compression or proxy discovery,
and no browser Origin. These are bounded pilot controls, not a DDoS protection
service. Apply firewall rules and restrict the trusted local charger boundary.

## Custody semantics and failure behavior

The SQLite journal uses WAL, `synchronous=FULL` and atomic append transactions.
Each event authenticates its journal ID, sequence, previous event tag, key ID and
body using a separate HMAC-SHA3-256 domain. Events are `queued` and `confirmed`.
Confirmation includes the SC2 request and authenticated backend response. Event
timestamps remain distinct from original meter-event timestamps. An old pending
request is re-signed at delivery; meter-event dates are never rewritten.

There are **no invented local success responses, transaction IDs or bills**.
A request waiting over the response deadline closes its connection with 1013,
instructing the charger to retry the same request ID. It can still complete later
at the backend. A full journal or reused ID with different data returns an error
before queuing. Corrupted custody state or an unauthenticated response fails closed.
Transient transport failures use bounded exponential delay and cryptographic jitter.
Backend business errors are authenticated terminal responses, retained like successes.

This preserves custody and eventual reconciliation; it does not implement offline
charging authorization. A real charger's local authorization, offline transaction
buffering, retry behavior, timeouts and request-ID lifetime must be validated.
The current backend's request cache retains IDs indefinitely; charger UID reuse
requires session/retention engineering before deployment. The local input adapter
must verify the actual vendor checksum/record format instead of the simulator's
modeled checksum.

## Audit, anchors and key rotation

```bash
python -m securecharge blackbox-audit --keys secrets/pi.keys.json --outbox state/blackbox.sqlite --export-anchor evidence/anchor-001.json
python -m securecharge blackbox-audit --keys secrets/pi.keys.json --outbox state/blackbox.sqlite --anchor evidence/anchor-001.json
```

Retain the anchor **outside the Pi**, through an independently protected process.
It pins a journal identity, sequence and head. Prefix modification/reordering is
detectable using the journal key alone; deletion of a valid suffix, replacement
with an earlier snapshot or a wholly new journal needs an independent known anchor.
The prototype exports anchors; it does not automatically deliver them to an
independent witness. An older anchor cannot detect deletion of later unanchored
events. HMAC holders can forge evidence: this is not public-key non-repudiation.

Retain historical verification keys on the protected audit/gateway side while
removing retired acceptance keys from the online backend. Do not delete required
verification keys or archives and then claim old receipts still verify. A gateway
signs with one charger-owned active key; use a separate gateway/journal per charger.

The default capacity is **5,000 retained requests / 10,000 custody events**, with
16 KiB per original CALL. Completed evidence counts toward capacity. The verifier
scans the bounded journal, so performance near capacity needs measurement. Pilot
operators must export and independently anchor a closed journal, verify no pending
requests remain, stop the service, preserve the archive and keys, and start a new
journal under a controlled rotation. Automated retention/rotation is not implemented.
Large SignedData/transactionData messages may require a separately evaluated
larger limit. Do not silently remove limits or discard pending records.

## Move from lab pilot to real charging hardware

The systemd templates under `deploy/` provide isolated service users and writable
state directories; they have not been executed on this Windows host. Install and
verify them on the Pi/backend, supply actual certificate paths/hostname, set secret
permissions, monitor disk space and certificate expiry, and use reliable storage
plus a UPS. SQLite durability assumes the OS/filesystem/storage honor sync requests.

Before a public charging deployment, validate the specific charger and vendor
adapter, provision/revoke certificates and keys, establish clock synchronization,
implement session-aware cache retention, verify supported OCPP actions/security
profiles, measure sustained/full-journal load and actual power-cut recovery,
complete metrology/privacy requirements, and obtain an independent security review.
Those activities are an explicit boundary, not completed measurements in this build.

## Sources

- OCA security requirements and deployment context: https://openchargealliance.org/ocpp-info-whitepapers/ocpp-1-6-security-whitepaper-4th-edition/
- SQLite WAL and FULL durability: https://www.sqlite.org/pragma.html#pragma_synchronous and https://www.sqlite.org/wal.html
- Python certificate verification: https://docs.python.org/3/library/ssl.html
- websockets 15 transport bounds and handshake hooks: https://websockets.readthedocs.io/en/15.0/reference/asyncio/server.html
