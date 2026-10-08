"""SecureCharge - migrating legacy MD5-checked EV charging messages to
authenticated HMAC-SHA3-256 envelopes with replay and freshness protection.

    old charger --> trusted adapter / black box --(SC2 envelope)--> secure backend

Research prototype with strict OCPP 1.6 schemas, SC2 outer transport,
real localhost WebSockets and a Raspberry Pi gateway deployment profile.
"""

__version__ = "2.1.0"
