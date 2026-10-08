"""Collision risk analysis for MD5/SHA-1 in a legacy EV charging system.

This is the written half of problem statement #18: an inventory of the places a
legacy charge-point management system (CSMS) tends to rely on a weak hash, what
breaks if that hash is collided or forged, and what to migrate each one to. It
is reference data - the CLI and dashboard render it, and the README cites it.

Two different MD5 weaknesses appear below and should not be conflated:

* Collision     - the attacker controls *both* messages and makes them share a
                  hash. Practical for MD5 since 2004; chosen-prefix collisions
                  (two meaningful, attacker-chosen documents) since 2007, as
                  used to forge a CA certificate in the Flame malware (2012).
* Keyless checksum forgery (NOT a second-preimage attack) - the attacker edits one
                  existing message and recomputes the hash. This needs no
                  collision at all; it works against *any* unkeyed hash,
                  including SHA-256 or SHA3-256, and is defeated only by a MAC.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class RiskItem:
    area: str
    weak_use: str
    threat: str
    consequence: str
    severity: str  # Critical / High / Medium
    weakness: str  # "collision" or "keyless-forgery"
    replacement: str
    standard: str


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2}

INVENTORY: list[RiskItem] = [
    RiskItem(
        area="StopTransaction integrity",
        weak_use="MD5 checksum over the billing payload (meterStop, transactionId)",
        threat="Edit meterStop, recompute the MD5",
        consequence="Energy is delivered but billed at a fraction of its value (revenue loss)",
        severity="Critical",
        weakness="keyless-forgery",
        replacement="HMAC-SHA3-256 over the payload, keyed per gateway",
        standard="RFC 2104 (HMAC), FIPS 202 (SHA-3)",
    ),
    RiskItem(
        area="Firmware update authenticity",
        weak_use="MD5 digest used to 'verify' a downloaded firmware image",
        threat="Chosen-prefix MD5 collision between a benign and a malicious image",
        consequence="Malicious firmware passes the integrity check and is installed",
        severity="Critical",
        weakness="collision",
        replacement="Signature (e.g. Ed25519) over a SHA3-256 digest",
        standard="FIPS 202, NIST SP 800-131A",
    ),
    RiskItem(
        area="OCPP message authentication",
        weak_use="No per-message authentication; integrity left to a bare hash",
        threat="Replay or inject messages on the CSMS link",
        consequence="Duplicate or forged sessions, meter fraud, free charging",
        severity="High",
        weakness="keyless-forgery",
        replacement="HMAC-SHA3-256 with a timestamp and a nonce (this project)",
        standard="RFC 2104, OCPP 1.6 Security Whitepaper",
    ),
    RiskItem(
        area="Software / config distribution",
        weak_use="MD5 'fingerprint' published next to a download",
        threat="Identical-prefix or chosen-prefix collision",
        consequence="A tampered package matches the published fingerprint",
        severity="High",
        weakness="collision",
        replacement="SHA-256 or SHA3-256 fingerprints, ideally signed",
        standard="RFC 6151 (MD5 considered harmful)",
    ),
    RiskItem(
        area="TLS / certificate chain",
        weak_use="Legacy certificates with MD5 or SHA-1 signatures",
        threat="Chosen-prefix collision to forge a CA-signed certificate",
        consequence="Impersonation of the CSMS; man-in-the-middle on all chargers",
        severity="Critical",
        weakness="collision",
        replacement="SHA-256+ certificates; reject MD5/SHA-1 signatures",
        standard="RFC 6194 (SHA-1), CA/B Forum baseline requirements",
    ),
    RiskItem(
        area="Idempotency / dedup keys",
        weak_use="MD5 of a message used as its unique id in logs or a cache",
        threat="Collision forces two different messages to one id",
        consequence="One message masks another; audit and dedup become unreliable",
        severity="Medium",
        weakness="collision",
        replacement="SHA-256 or SHA3-256 as the identifier",
        standard="NIST SP 800-131A",
    ),
    RiskItem(
        area="Stored credential hashing",
        weak_use="MD5 (often unsalted) over RFID idTags or API secrets",
        threat="Precomputed/rainbow-table and brute-force recovery",
        consequence="Credential recovery enabling cloned tags or API access",
        severity="High",
        weakness="keyless-forgery",
        replacement="A password KDF (scrypt/Argon2); HMAC for API keys",
        standard="NIST SP 800-132, OWASP storage guidance",
    ),
]

REFERENCES: list[str] = [
    "RFC 1321 - The MD5 Message-Digest Algorithm (1992)",
    "Wang & Yu - How to Break MD5 and Other Hash Functions, EUROCRYPT 2005",
    "Stevens, Lenstra & de Weger - Chosen-prefix collisions for MD5 (2007)",
    "RFC 6151 - Updated Security Considerations for MD5 and HMAC-MD5 (2011)",
    "RFC 6194 - Security Considerations for the SHA-1 message digest (2011)",
    "Stevens et al. - The first collision for full SHA-1 (SHAttered, 2017)",
    "Leurent & Peyrin - SHA-1 is a Shambles: chosen-prefix collisions (2020)",
    "FIPS 180-4 - Secure Hash Standard (SHA-1, SHA-2)",
    "FIPS 202 - SHA-3 Standard: Permutation-Based Hash (Keccak)",
    "RFC 2104 - HMAC: Keyed-Hashing for Message Authentication",
    "NIST SP 800-131A Rev.2 - Transitioning the Use of Cryptographic Algorithms",
    "NIST SP 800-185 - SHA-3 Derived Functions (KMAC)",
    "RFC 8785 - JSON Canonicalization Scheme (JCS)",
]


@dataclass(frozen=True)
class RiskSummary:
    items: list[RiskItem] = field(default_factory=lambda: list(INVENTORY))
    references: list[str] = field(default_factory=lambda: list(REFERENCES))

    def sorted_items(self) -> list[RiskItem]:
        return sorted(self.items, key=lambda i: (SEVERITY_ORDER[i.severity], i.area))

    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in self.items:
            counts[item.severity] = counts.get(item.severity, 0) + 1
        return counts


def summary() -> RiskSummary:
    return RiskSummary()


def format_report(report: RiskSummary | None = None) -> str:
    report = report or summary()
    lines = ["MD5 / SHA-1 COLLISION RISK ANALYSIS - Legacy EV CSMS", "=" * 56, ""]
    for item in report.sorted_items():
        lines += [
            f"[{item.severity}] {item.area}  ({item.weakness})",
            f"    weak use   : {item.weak_use}",
            f"    threat     : {item.threat}",
            f"    impact     : {item.consequence}",
            f"    migrate to : {item.replacement}",
            f"    standard   : {item.standard}",
            "",
        ]
    counts = report.by_severity()
    tally = ", ".join(f"{n} {sev}" for sev, n in sorted(counts.items(), key=lambda kv: SEVERITY_ORDER[kv[0]]))
    lines += [f"Totals: {tally}", "", "References:"]
    lines += [f"  - {ref}" for ref in report.references]
    return "\n".join(lines)
