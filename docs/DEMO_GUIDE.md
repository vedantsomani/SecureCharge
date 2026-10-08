# Presentation and viva guide

## Seven-minute walkthrough

| Time | Demonstration | Claim to say aloud |
|---|---|---|
| 0:00-0:45 | Problem statement and trust-boundary diagram | Legacy retrofit; MD5 is modeled vendor behavior, not an OCPP requirement |
| 0:45-1:45 | Genuine collision substitution | Same pinned MD5 of decoded records, different Wh values; both OCPP messages valid |
| 1:45-2:30 | INR 150 vs INR 1.20 checksum-forgery demo | Recomputing an unkeyed checksum is a different vulnerability |
| 2:30-3:30 | Inspect SC2 and unchanged OCPP CALL | Outer adapter transport avoids illegal OCPP 1.6 customData fields |
| 3:30-4:30 | Replay, charger relabel, downgrade | Signed identity + nonce + durable enrollment; failures have named reasons |
| 4:30-5:30 | Network demo and concurrent/restart/fault tests | Real WebSockets, cached retry, atomic state, one bill per transaction |
| 5:30-6:30 | Evidence tab and Pi run metadata | Distributions and raw data; hardware numbers only from that actual host |
| 6:30-7:00 | Limitations and research contribution | Experimental artifact and hash-boundary analysis, not a new hash/MAC or vendor exploit |

## Likely viva questions

**Why not replace MD5 with a SHA3 checksum?** Anyone who edits an unkeyed message
can recompute any checksum. Collision resistance and message authentication solve
different problems. The retrofit needs a MAC or signature.

**Why SHA-3 rather than SHA-256 HMAC?** The PS requests SHA-3. FIPS 202 provides a
sponge-based implementation; HMAC-SHA-256 remains a valid secure baseline. The
length-extension objection applies to naive secret-prefix designs, not HMAC.

**Where is the collision?** In the decoded 128-byte vendor record, with a fixed
expected MD5. The base64 text and full JSON are different and do not collide.
The vendor format is a published research fixture of our model, not real firmware.

**Is this truly backward-compatible?** It preserves the OCPP CALL delivered to an
existing strict parser. Both ends of the new private link require adapters; an old
backend cannot enforce a MAC it does not understand. We claim parser compatibility
for our supported action profile, not complete certification or every charger's behavior.

**How can a retry work if you block replay?** A recorded exact envelope is rejected.
A trusted gateway can wrap an identical request with a new nonce, which returns
the retained request result without repeating business effects.

**What happens if the database fails?** The request's nonce, effects, cached facts,
enrollment and audit record are one transaction. Fault injection verifies rollback.
A failed request can be retried with its original envelope if it remains fresh.

**Does the gateway prove the meter is honest?** No. It proves an authorized key
holder authenticated the message after the trusted local measurement boundary.

**Is this research novelty?** The contribution is the reproducible integration,
explicit decoded-record attack boundary and migration/accounting evaluation.
HMAC-SHA3-256, nonce replay guards and gateways are established techniques. Novelty
and suitability for a venue need supervisor and related-work review.

## Distinctive live demonstration: the charging black box

Run `python scripts/run_pilot.py`, then open **Pi black box**. Explain the harder
real-world question: "If a charger loses connectivity and the bill commits but
the acknowledgement disappears, can we recover one bill and verify its custody?"
Show the actual mutual-TLS experiment's pending request, lost acknowledgement,
reopened journal, one bill, authenticated receipt and rejected storage mutation.

For a physical Pi demonstration, follow `PILOT.md` and use separate backend,
gateway and charger terminals. Stop/restart the backend during a confirmed
session. Show the Pi's retained request and recovered receipt, then export an
independent anchor. State that this preserves custody/reconciliation and does
not invent offline authorization. Explain why a locally kept hash chain cannot
detect complete rollback without an independent anchor, and why symmetric evidence
is not non-repudiation. These limits are part of the security argument.

The contribution is the evaluated integration of collision boundaries, parser
compatibility, authenticated custody and accounting recovery. Do not claim that
the underlying techniques are unprecedented or that other students cannot reproduce them.

## Presentation preparation

Use `python scripts/run_demo.py`. Keep a fresh terminal for the network demo and
the recorded artifact directory available offline. Generate your Pi artifacts on
the actual board before placing Pi timing values in slides or the paper. The
paper draft must list your real authors/affiliation and describe only measured results.
