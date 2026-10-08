# Measured research results

Hardware class: **host-desktop-or-server**. Board: unavailable.
Python 3.14.7; Windows-11-10.0.26200-SP0. Measurement time: 2026-10-03T00:00:08.554317+00:00.

200 observations per configuration; seed 18. Pipeline storage: SQLite WAL file.
Start request median **1.737 ms**, p95 **2.037 ms**. Stop is outside this timer.
Envelope adds **282 bytes** for this start message.
Python allocation peak for an additional start+stop: 11390 bytes (not RSS/firmware RAM).

All four unkeyed checksum baselines permit recomputation forgery. The collision
substitution uses an unchanged pinned MD5 of decoded MVR-128 records. Both OCPP
messages validate; their JSON digests are different. The SC2 tag rejects substitution.
Actual localhost WebSockets return standard OCPP responses; retry creates one bill.

No Pi hardware measurements are claimed unless board_model identifies a Pi.
This is a single-host experiment, not a deployment-scale or universal security proof.
See raw CSV files and results.json for methods, distributions and scope.
