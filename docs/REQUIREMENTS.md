# Problem statement to implementation and evidence

| PS element | Implementation | Reproducible evidence | Boundary |
|---|---|---|---|
| MD5 | `crypto`, `legacy`, `collision` | Known answers, published digest pair | MD5 use is modeled vendor behavior |
| SHA-1 | Legacy comparison and benchmarks | Recomputable checksum baseline | No SHA-1 collision generated |
| SHA-256 | Record comparison, checksum and HMAC benchmark | Different record digests; checksum still forgeable | Secure HMAC baseline, not claimed broken |
| SHA-3 / Keccak | FIPS 202 SHA3-256, HMAC-SHA3-256 | NIST vector and reference-HMAC equivalence | Raw Keccak-256 is a different domain variant |
| Legacy EV firmware retrofitting | Charger-local Raspberry Pi gateway + CSMS adapter | Runnable services, Pi setup and measurement script | Actual Pi/charger results pending local execution |
| OCPP 1.6 message formats | Strict independent action schemas, CALL and responses | Original frame unchanged after unwrap; real WebSockets | Five actions, not full CSMS certification |
| Targeted collision risk | MVR-128 decoded binary meter record in SignedData | Same pinned MD5, different readings and bills | Explicit synthetic format; JSON itself does not collide |
| Backward-compatible integrity upgrade | SC2 outer transport, unchanged embedded OCPP | Parser schema test and loopback flow | Both private transport ends require adapters |
| Security improvement | Identity/MAC/freshness/replay + monotonic policy | Mutations, concurrency, restart, rotation, fault tests | Trusted local source, clocks, keys and backend |
| Research evaluation | Raw samples, intervals, metadata, figures, manifests | `research --out ...` and artifact verifier | Single-host bootstrap, not fleet/hardware extrapolation |
| Real deployment pilot | Mutual TLS, certificate/URL/key binding, bounded connections and buffers | Actual TLS identity and rate/capacity tests | Private lab CA; full PKI lifecycle/certification pending |
| Distinctive recovery contribution | Pi custody journal, authenticated replies and durable forwarding | Actual outage/lost-reply/reopen experiment; separate abrupt child-process exit test | No invented offline acceptance; real charger retry behavior must be validated |
| Evidence integrity | Domain-separated SHA-3 HMAC chain and exported anchor | Record modification/reordering and suffix rollback tests | Protected keys and independent anchors; no non-repudiation |

## Claims that should not appear in the submission

- "OCPP 1.6 customData is an official extension slot."
- "Recomputing MD5 is a collision or second-preimage attack."
- "The full JSON collision was generated." The experiment hashes decoded records.
- "SHA-1 is safe because it distinguishes the Wang-Yu MD5 pair."
- "HMAC-SHA-256 suffers from secret-prefix length extension."
- "The audit log is tamper-proof" or "gateway signatures prove truthful meters."
- "Published / peer reviewed / Pi tested" without that corresponding evidence.

## Acceptance checklist

Run tests and formatting checks, reproduce loopback, generate a fresh artifact
directory, verify all manifest hashes, inspect both figures and the paper PDF,
and execute `scripts/measure_pi.py` on the actual board before inserting Pi claims.
