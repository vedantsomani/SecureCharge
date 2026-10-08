# Threat model and conditional security arguments

## Assets, adversary and assumptions

Assets are billing payload integrity, charger identity, exactly-once transaction
effects, monotonic migration enrollment, and recovery after a lost response.
The adversary controls the gateway/adapter link: observes, modifies, duplicates,
drops or reorders traffic. They know algorithms, messages and published fixtures.
They do not possess an uncompromised charger's key.

Assumptions: the local charger/gateway path and measurement source are trusted;
key provisioning protects 256-bit random keys; clocks are sufficiently accurate;
SQLite provides its documented transaction semantics; the backend host is trusted;
receiving charger identity comes from an authorized connection in deployment.
Remote service connections require mutual TLS; a provisioned certificate URI SAN
must match the receiving charger URL and key owner before WebSocket upgrade.
The plain loopback demonstration retains its explicitly local trust boundary.
The implemented connection policy is not complete OCPP certification or PKI lifecycle.

## Authentication argument

For a fixed SC-JSON-1 input, changes to the complete CALL, legacy metadata, version,
key ID, nonce, timestamp or charger produce different authenticated bytes, unless
the structured values are identical. Duplicate keys and invalid types are rejected
before any effects. Under the assumed unforgeability of HMAC-SHA3-256 and protected
keys, a changed authenticated input requires a MAC forgery. Tag comparisons use
`hmac.compare_digest`. This is a conditional argument, not a new proof of HMAC.

Keyless checksum recomputation does not require a collision or second preimage.
SHA3-256 as a keyless checksum is still forgeable in that model. SHA-256/HMAC is
also a valid authentication choice; the problem statement motivates selecting
SHA-3. SHA3-256 is the FIPS 202 instance, not interchangeable raw Keccak-256.

Request and reply domain labels differ. Replies also bind the outstanding request
nonce and response ID, preventing a captured reply from answering a fresh request.

## Replay and idempotency argument

Acceptance requires `-skew ≤ now - signed_ts ≤ TTL`. Replay state is committed
under a composite `(key_id, nonce)` primary key within the same transaction as
effects. Concurrent identical copies cannot both claim that key. A failed commit
does not retain a nonce without its corresponding effect.

Nonces are purged only when their signed timestamp is older than TTL + skew,
so under the trusted-clock assumption their messages cannot pass freshness again.
Keys have separate nonce namespaces, so one compromised/authorized charger cannot
pre-claim another key's nonce in the global replay store.

A legitimate retransmission freshly signed by the gateway uses a new nonce.
Its unchanged CALL is matched against the retained charger/UID cache and returns
saved facts without repeating effects. Conflicting CALL data under that retained
ID is refused. Unique ledger and open-connector constraints provide independent
accounting guards. Request-ID reuse by real chargers needs a session/retention policy.

## Migration argument

Enrollment is committed only alongside an accepted signed request. Every legacy
acceptance checks the persisted enrollment inside a write transaction. Therefore
a network adversary cannot remove a tag to make an enrolled charger eligible for
legacy fallback, including during a concurrent enrollment or after restart.
An un-enrolled charger in monitor/warn remains vulnerable by explicit policy.

## What tests do and do not establish

Known-answer vectors check primitive implementation usage. Generated mutations
exercise encoding and signing coverage. Race, restart and fault-injection tests
exercise the actual persistent implementation. None of these establish universal
cryptographic security, physical measurement authenticity, production resilience,
or a formally machine-checked protocol proof.

## Custody and outage recovery

The Pi pilot authenticates each append-only journal event under a separate
HMAC-SHA3-256 domain, including journal identity, sequence, previous tag and body.
An original CALL is persisted before forwarding. A confirmed event is appended
only after verifying the backend reply against its fresh SC2 request. Recovery
re-signs the same CALL without rewriting its meter-event timestamps. Backend
idempotency recovers a lost acknowledgement without a second bill. The frontend
does not manufacture success during an outage; it closes after a bounded wait and
requires retransmission with the same request ID.

Under protected keys, event modification/reordering or deletion within the chain
is detectable. Whole-journal rollback or removal of a valid suffix requires an
independently retained external anchor. Export is implemented; automatic independent
witness delivery is not. HMAC holders can forge receipts/journal events, so this
evidence is not third-party non-repudiation. Historical audit needs historical
verification keys. The backend's ordinary audit table remains unsealed; the gateway
custody journal is a distinct, authenticated evidence source.

The bounded journal scans retained events during verification; load near capacity,
storage exhaustion, controlled evidence rotation and physical power loss require
pilot validation. FULL/WAL durability relies on honest filesystem/storage sync.
The gateway is not an offline authorization engine or independent energy meter.

## Out of scope and residual risks

Compromised keys/endpoints, malicious firmware, physical meter fraud, inaccurate
or adversary-controlled clocks, non-repudiation, authorized flooding, host/storage
compromise, audit-log deletion, database growth, device provisioning scale, legal
metrology and complete OCPP compliance are out of scope. Byte limits reduce parser
resource abuse but do not constitute a complete denial-of-service defense.

For any publication, state these assumptions next to the security claims and
identify the collision format as a synthetic model. Do not claim an exploit of
a named vendor, arbitrary JSON collision generation, or production readiness.
