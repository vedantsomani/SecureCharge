# SecureCharge Research Lab

**MD5-to-SHA-3 Migration and Collision Risk Analysis in Legacy EV Firmware**

SecureCharge is a reproducible research prototype for problem statement #18.
It combines a real MD5 collision substitution in a specified legacy meter-record
model, an authenticated SHA-3 retrofit, strict OCPP 1.6 parser compatibility,
durable accounting, actual WebSocket transport, and a Raspberry Pi gateway profile
with mutual TLS and an authenticated outage-recovery custody journal.

**Status:** working software and measured desktop experiments. Raspberry Pi
deployment instructions are included; Pi measurements must be collected on the
actual board. This is not a certified CSMS, peer-reviewed paper, or newly discovered
vendor vulnerability.

## Start here

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe scripts/run_demo.py
```

Linux / Raspberry Pi:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python scripts/run_demo.py
```

Use the environment's Python for all commands. `scripts/run_demo.py` runs the
collision lab, attack catalogue, and network demonstration, then starts the dashboard.
Pass `--no-dashboard` for an automated presentation check.

For the Pi black-box fault experiment and dashboard:

```powershell
.\.venv\Scripts\python.exe scripts/run_pilot.py
```

This uses actual mutual-TLS WebSockets, persists a request during an outage,
deliberately loses a reply after billing commits, reopens the journal and recovers
the authenticated result with one bill. See [the pilot guide](docs/PILOT.md) for
separate services, certificate setup, evidence anchors and a Pi/desktop split.

## What the project actually demonstrates

| Experiment | Precise finding |
|---|---|
| Checksum recomputation | MD5, SHA-1, SHA-256 and SHA3-256 **all** allow forgery when used without a key |
| Published binary collision | Different 128-byte inputs share MD5 `79054025255fb1a26e4bc422aef54eb4` |
| OCPP SignedData collision model | The same **pinned MD5 of decoded binary records** accepts different meter readings in schema-valid OCPP messages |
| SC2 authentication | HMAC-SHA3-256 rejects changed business fields, checksum metadata, identity, nonce and signing timestamp |
| Accounting | One bill per transaction under concurrent delivery; storage faults roll back nonce and business effects together |
| Retry recovery | A fresh envelope around an identical request returns the original result without repeating effects |
| Parser compatibility | The embedded OCPP CALL stays unchanged; an adapter removes the outer wrapper before the standard parser |
| Transport | Real localhost WebSockets exchange CALL/CALLRESULT/CALLERROR; responses are authenticated on the private link |
| Migration | First accepted signed request enrolls a charger; enrollment survives restart and prevents later unsigned fallback |
| Pi black box | Sealed custody journal retains pending requests and verified responses; abrupt process exit is regression-tested |
| Lost-reply recovery | Backend commits, reply is dropped, journal reopens and one bill remains after retransmission |
| Device authentication | Mutual TLS binds a provisioned charger URI SAN to its URL before upgrade; mismatched/anonymous clients are refused |
| Evidence integrity | HMAC-SHA3 chain detects changed/reordered custody events; an independently retained anchor is required for suffix rollback |

The headline recomputation demo retains the familiar **12.5 kWh / INR 150.00**
honest bill versus **INR 1.20** forged legacy bill. The genuine collision experiment
is separate: the records differ by **128 Wh**, giving **INR 150.00 vs INR 148.46**
at INR 12/kWh. Its expected MD5 never changes. No new collisions are generated.

## Why the OCPP 1.6 wrapper changed

OCPP 1.6 does **not** have the OCPP 2.0.1 `customData` extension slot. SC2 therefore
keeps transport metadata outside the OCPP payload:

```text
Legacy OCPP charger / local vendor adapter
          ↓ unchanged OCPP CALL + modeled checksum
Trusted charger-local gateway
          ↓ SC2 outer envelope (private transport)
CSMS security adapter: authenticate → validate → atomic accounting
          ↓ unchanged OCPP CALL / standard response
Existing OCPP 1.6 parser
```

The outer envelope is a proprietary adapter protocol, **not an OCPP message**.
Both ends of the upgraded link require adapters. Parser compatibility does not
mean an unaware backend validates a MAC. Five OCPP actions are currently supported:
StartTransaction, StopTransaction, MeterValues, Heartbeat and BootNotification.

```json
{
  "format": "SecureCharge/2",
  "ocpp": [2, "msg-0001", "StartTransaction", {
    "connectorId": 1, "idTag": "RFID-1234", "meterStart": 48000,
    "timestamp": "2026-10-03T00:00:00Z"
  }],
  "legacy": {"alg": "md5", "value": "<vendor-checksum>"},
  "security": {
    "v": "SC2", "kid": "gw-1", "cp": "CP-01", "ts": 1790985600,
    "nonce": "<32-lowercase-hex>", "tag": "<64-lowercase-hex>"
  }
}
```

MAC inputs cover the complete embedded CALL, modeled legacy metadata, charger
identity, key ID, nonce, version and signing timestamp. SC-JSON-1 is our explicit
integer-only deterministic JSON profile; it is **not RFC 8785/JCS**. Wire whitespace
may vary, but duplicate keys, floats, lone surrogates, oversized messages and deep
nesting are rejected. HMAC-SHA-256 is a valid secure baseline; SHA-3 is chosen to
meet the problem statement, not because SHA-256 HMAC is broken.

## Collision model and scientific limits

MVR-128 is a deliberately specified **synthetic vendor meter record**: 128 bytes,
a big-endian 31-bit Wh counter at offsets 16-19, and otherwise opaque vendor data.
The published Wang-Yu pair fits this grammar. Base64 transports the records in
OCPP 1.6 `transactionData[].sampledValue[]` with `format: SignedData`.

The modeled legacy verifier checks a trusted, previously pinned MD5 of the
**decoded record**, and checks that its counter agrees with `meterStop`. Record B
substitutes for A without changing the expected MD5. SHA-256/SHA3-256 distinguish
the records, and SC2 authenticates the whole message.

**Neither the base64 strings nor the JSON messages collide.** This demonstrates
the risk of a weak binary-record hashing boundary inside a valid OCPP message.
It does not establish a chosen-prefix collision in arbitrary JSON, nor prove
that real OCPP vendors implement MVR-128. MD5 is not mandated by OCPP.

## Commands and reproducible evidence

```bash
python -m securecharge demo
python -m securecharge collision
python -m securecharge collision-lab
python -m securecharge network-demo
python -m securecharge pilot-demo --out artifacts/new-pilot
python scripts/verify_artifacts.py artifacts/new-pilot
python -m securecharge risk
python -m securecharge research --out artifacts/new-run --samples 200 --seed 18
python scripts/verify_artifacts.py artifacts/new-run
python -m pytest -q
python -m ruff check securecharge tests scripts dashboard.py
```

Each research run writes raw hash/MAC and pipeline samples, scenario CSV, results
JSON, collision fixtures, PNG/SVG figures, a methods summary, environment metadata,
and SHA-256 manifests. Algorithm order is randomized. Median, p95, p99 and 95%
bootstrap intervals are reported. Cryptographic nonces are never seeded by the
experiment seed. An existing experiment database is never overwritten.

Measured pipeline scope: StartTransaction checksum + gateway + serialization +
backend/SQLite. StopTransaction closes the session outside that timer. Python
allocation measurements run separately from latency sampling. They are not RSS,
embedded flash, energy consumption, or firmware RAM measurements.

To rebuild the measured manuscript and PDF from a new run:

```bash
python -m pip install -r requirements-paper.txt
python -m pytest --junitxml=artifacts/validation.xml
python scripts/build_paper.py --results artifacts/new-run/results.json --pilot artifacts/new-pilot/pilot-results.json
```

The builder fills reported values from the experiment and test report. Inspect
the rendered pages in `tmp/paper/` before handing in an updated PDF.

## Hand-in materials

- [Architecture and message contract](docs/ARCHITECTURE.md)
- [Threat model and conditional security arguments](docs/SECURITY_MODEL.md)
- [Requirement-to-evidence mapping](docs/REQUIREMENTS.md)
- [Research paper draft](docs/PAPER.md)
- [Raspberry Pi setup and measurement guide](docs/RASPBERRY_PI.md)
- [Pi black box pilot, certificates and outage recovery](docs/PILOT.md)
- [Presentation and viva walkthrough](docs/DEMO_GUIDE.md)
- Measured exports under `artifacts/`; paper PDF under `output/pdf/`.

## Operational limits

The charger-to-gateway boundary must be trusted; a gateway can authenticate an
already false meter reading. HMAC is symmetric and offers no non-repudiation.
Keys need protected provisioning/storage; each key is authorized for one charger.
Clock correctness, key compromise, physical meter fraud, authenticated denial of
service, database exhaustion, and hostile firmware are not solved by this wrapper.
The backend audit table is ordinary telemetry. The Pi custody journal authenticates
events; independent anchors are necessary to detect complete/tail rollback.

The original loopback uses plaintext localhost; the pilot experiment uses actual
mutual TLS. Exposed services require client certificates and enforce provisioned
identity and basic connection/message bounds. Deployment still requires complete
OCPP security-profile engineering, certificate lifecycle, sustained load/retention
validation and independent review. See the pilot guide for exact limits.

Request IDs must be unique per charger over retained request history. A rewrapped
request with a fresh nonce and identical CALL returns a cached result; conflicting
reuse is rejected. Cache retention/session namespaces for chargers that reuse IDs
need deployment-specific design. There is no claim of universal OCPP behavioral
compatibility, cross-platform CI execution, or hardware performance before testing.

## Primary references

- [OCA: Customizing OCPP implementations](https://openchargealliance.org/wp-content/uploads/2025/05/OCA-Customizing-OCPP-Implementations.pdf)
- [OCA: OCPP 1.6 Security Whitepaper, edition 4](https://openchargealliance.org/ocpp-info-whitepapers/ocpp-1-6-security-whitepaper-4th-edition/)
- [RFC 6151: MD5 security considerations](https://www.rfc-editor.org/rfc/rfc6151.html)
- [NIST FIPS 202: SHA-3](https://csrc.nist.gov/pubs/fips/202/final)
- [RFC 2104: HMAC](https://www.rfc-editor.org/rfc/rfc2104.html)
- [Published MD5 collision demonstration and provenance](https://www.mscs.dal.ca/~selinger/md5collision/)
- [Leurent and Peyrin: SHA-1 is a Shambles, USENIX 2020](https://www.usenix.org/conference/usenixsecurity20/presentation/leurent)

The paper identifies the contribution as an experimental retrofit artifact and
hash-boundary analysis, not a novel cryptographic primitive or a reviewed result.
