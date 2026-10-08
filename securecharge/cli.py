"""Command-line demo: ``python -m securecharge <command>``.

Commands:
    demo        run every attack scenario, old system vs new, side by side
    collision   show the published MD5 collision pair and what each hash says
    benchmark   compare hash / MAC speed (MD5, SHA-1, SHA-256, SHA3-256, HMAC)
    risk        print the MD5/SHA-1 collision risk analysis
    all         collision, demo, risk (skips the slower benchmark)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _utf8_stdout() -> None:
    # Windows consoles default to cp1252 and cannot print the rupee sign.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass


def _rule(char: str = "=", width: int = 92) -> str:
    return char * width


def cmd_demo(_: argparse.Namespace) -> int:
    from .messages import format_inr
    from .scenarios import run_all

    rows = run_all()
    honest, forged = rows[0].honest_paise, rows[0].forged_paise
    print(_rule())
    print("SecureCharge - legacy MD5 CSMS  vs  HMAC-SHA3-256 migration gateway")
    print(_rule())
    print(
        f"Honest session: 12.5 kWh -> {format_inr(honest)}.   "
        f"Attacker's target: {format_inr(forged)} for the same energy.\n"
    )

    def clip(text: str, size: int = 44) -> str:
        return text if len(text) <= size else text[: size - 1] + "…"

    width = max(len(r.title) for r in rows)
    print(f"  {'SCENARIO':<{width}}  {'LEGACY (MD5 only)':<54}  SECURE (HMAC-SHA3-256)")
    print("  " + "-" * (width + 54 + 26))
    for r in rows:
        legacy_mark = "FOOLED" if r.legacy.fooled else "  ok  " if r.legacy.applicable else "  --  "
        secure_mark = "FOOLED" if r.secure.fooled else "  ok  "
        legacy_cell = f"[{legacy_mark}] {clip(r.legacy.note)}"
        print(f"  {r.title:<{width}}  {legacy_cell:<54}  [{secure_mark}] {clip(r.secure.note)}")

    legacy_fooled = sum(r.legacy.fooled for r in rows)
    secure_fooled = sum(r.secure.fooled for r in rows)
    print("\n" + _rule("-"))
    print(f"Legacy system fooled in {legacy_fooled} scenario(s); secure system fooled in {secure_fooled}.")
    if secure_fooled == 0:
        print("All non-honest catalogue scenarios were rejected by the secure CSMS.")
    return 0


def cmd_collision(args: argparse.Namespace) -> int:
    from . import collision

    report = collision.analyse()
    print(_rule())
    print("MD5 COLLISION - two different 128-byte inputs, one MD5 digest")
    print("(published pair, Wang & Yu, EUROCRYPT 2005)")
    print(_rule())
    print(f"Input A and B differ at byte offsets: {list(report.differing_offsets)}")
    print(f"Inputs identical? {report.a == report.b}\n")
    for algorithm, (da, db) in report.digests.items():
        verdict = "COLLISION (same digest!)" if da == db else "different on this pair"
        print(f"  {algorithm:<16} A={da[:32]}...")
        print(f"  {'':<16} B={db[:32]}...  -> {verdict}")
    print(f"\nAppending a common suffix keeps the MD5 collision: {report.suffix_keeps_collision}")
    print("MD5 collides; SHA-256, SHA3-256 and the keyed HMAC all separate the two inputs.")
    if args.write:
        a, b = collision.write_samples(args.write)
        print(f"\nWrote {a} and {b}")
        print("Verify on Windows:  certutil -hashfile <file> MD5")
    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    from . import benchmark

    print(_rule())
    print("HASH / MAC SPEED  (best of several batches; higher ops/sec is faster)")
    print(_rule())
    print(benchmark.format_table(benchmark.run()))
    print("\nNote: MD5 is among the fastest here. Speed is not the problem - it is broken.")
    return 0


def cmd_risk(_: argparse.Namespace) -> int:
    from . import riskanalysis

    print(riskanalysis.format_report())
    return 0


def cmd_all(args: argparse.Namespace) -> int:
    cmd_collision(args)
    print("\n")
    cmd_demo(args)
    print("\n")
    cmd_risk(args)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m securecharge", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("demo", help="run every attack scenario side by side").set_defaults(func=cmd_demo)
    coll = sub.add_parser("collision", help="show the MD5 collision pair")
    coll.add_argument("--write", type=Path, metavar="DIR", help="write the colliding files to DIR")
    coll.set_defaults(func=cmd_collision)
    sub.add_parser("benchmark", help="compare hash/MAC speed").set_defaults(func=cmd_benchmark)
    sub.add_parser("risk", help="print the collision risk analysis").set_defaults(func=cmd_risk)
    sub.add_parser("collision-lab", help="OCPP SignedData collision substitution research model").set_defaults(
        func=cmd_collision_lab
    )
    sub.add_parser("network-demo", help="real localhost WebSocket flow").set_defaults(func=cmd_network)
    pilot = sub.add_parser("pilot-demo", help="actual mutual-TLS custody, outage and lost-reply fault experiment")
    pilot.add_argument("--out", type=Path, required=True)
    pilot.set_defaults(func=cmd_pilot)
    pki = sub.add_parser("lab-pki", help="generate a short-lived PRIVATE LAB CA and pilot certificates")
    pki.add_argument("--out", type=Path, required=True)
    pki.add_argument("--charger", default="CP-01")
    pki.add_argument("--hostname", default="localhost")
    pki.set_defaults(func=cmd_pki)
    audit = sub.add_parser("blackbox-audit", help="verify custody chain and optionally an external anchor")
    audit.add_argument("--keys", type=Path, required=True)
    audit.add_argument("--outbox", type=Path, required=True)
    audit.add_argument("--anchor", type=Path)
    audit.add_argument("--export-anchor", type=Path)
    audit.set_defaults(func=cmd_audit)
    charger = sub.add_parser("charger-demo", help="simulate a charger against a separate local/Pi gateway")
    charger.add_argument("--gateway", default="ws://127.0.0.1:9001")
    charger.add_argument("--charger", default="CP-01")
    charger.add_argument("--ca")
    charger.add_argument("--client-cert")
    charger.add_argument("--client-key")
    charger.add_argument("--pause-before-stop", type=float, default=0)
    charger.add_argument("--timeout", type=float, default=180)
    charger.set_defaults(func=cmd_charger)
    research = sub.add_parser("research", help="export raw measurements, figures, metadata and manifests")
    research.add_argument("--out", type=Path, required=True)
    research.add_argument("--samples", type=int, default=200)
    research.add_argument("--seed", type=int, default=18)
    research.add_argument("--memory", action="store_true", help="use memory SQLite rather than durable file")
    research.set_defaults(func=cmd_research)
    keygen = sub.add_parser("keygen", help="generate a local private key configuration")
    keygen.add_argument("--out", type=Path, required=True)
    keygen.add_argument("--charger", default="CP-01")
    keygen.add_argument("--kid", default="gw-1")
    keygen.set_defaults(func=cmd_keygen)
    service = sub.add_parser("serve", help="run a Raspberry Pi gateway or backend adapter")
    service.add_argument("role", choices=["gateway", "backend"])
    service.add_argument("--keys", type=Path, required=True)
    service.add_argument("--host", default="127.0.0.1")
    service.add_argument("--port", type=int, default=9000)
    service.add_argument("--database", default="state/securecharge.sqlite")
    service.add_argument("--upstream", default="ws://127.0.0.1:9000")
    service.add_argument("--cert")
    service.add_argument("--tls-key")
    service.add_argument("--ca")
    service.add_argument("--client-ca", help="CA for required incoming client certificates")
    service.add_argument("--client-cert", help="gateway's outgoing mutual-TLS client certificate")
    service.add_argument("--client-key", help="gateway's outgoing mutual-TLS private key")
    service.add_argument("--outbox", default="state/gateway-blackbox.sqlite")
    service.add_argument("--capacity", type=int, default=5000)
    service.add_argument("--max-connections", type=int, default=16)
    service.add_argument("--response-timeout", type=float, default=20)
    service.set_defaults(func=cmd_serve)
    allp = sub.add_parser("all", help="collision + demo + risk")
    allp.add_argument("--write", type=Path, help=argparse.SUPPRESS)
    allp.set_defaults(func=cmd_all)
    return parser


def cmd_collision_lab(_: argparse.Namespace) -> int:
    import json
    from .collision_lab import report

    print(json.dumps(report(), indent=2))
    return 0


def cmd_network(_: argparse.Namespace) -> int:
    import asyncio
    import json
    from .network import loopback

    print(json.dumps(asyncio.run(loopback()), indent=2))
    return 0


def cmd_research(args: argparse.Namespace) -> int:
    from .research import run

    result = run(args.out, samples=args.samples, seed=args.seed, durable=not args.memory)
    print(f"Research artifacts written to {args.out}")
    print(f"Measured hardware: {result['environment']['hardware_class']}")
    return 0


def cmd_pilot(args: argparse.Namespace) -> int:
    import asyncio
    import json
    from .pilot import fault_experiment

    print(json.dumps(asyncio.run(fault_experiment(args.out)), indent=2))
    return 0


def cmd_pki(args: argparse.Namespace) -> int:
    from .pki import create_lab_pki

    create_lab_pki(args.out, args.charger, args.hostname)
    print(
        f"PRIVATE LAB certificates created at {args.out}; keep ca-key.pem offline. Leaf certificates expire in 7 days."
    )
    return 0


def cmd_charger(args: argparse.Namespace) -> int:
    import asyncio
    import json
    from .charger import simulate

    print(
        json.dumps(
            asyncio.run(
                simulate(
                    args.gateway,
                    args.charger,
                    ca=args.ca,
                    cert=args.client_cert,
                    key=args.client_key,
                    pause=args.pause_before_stop,
                    timeout=args.timeout,
                )
            ),
            indent=2,
        )
    )
    return 0


def load_keyring(path: Path):
    import json
    from .keys import Keyring

    config = json.loads(path.read_text(encoding="utf-8"))
    return Keyring({k: bytes.fromhex(v) for k, v in config["keys"].items()}, config["active_kid"], config["owners"])


def cmd_audit(args: argparse.Namespace) -> int:
    import json
    from .blackbox import BlackBox

    if not args.outbox.is_file():
        raise ValueError("audit requires an existing journal")
    journal = BlackBox(args.outbox, load_keyring(args.keys))
    try:
        anchor = json.loads(args.anchor.read_text(encoding="utf-8")) if args.anchor else None
        snapshot = journal.snapshot(anchor)
        pending = sum(item["response"] is None for item in snapshot["requests"].values())
        print(f"Verified {snapshot['sequence']} custody events; {pending} pending requests.")
        if args.export_anchor:
            args.export_anchor.parent.mkdir(parents=True, exist_ok=True)
            with args.export_anchor.open("x", encoding="utf-8") as stream:
                json.dump(journal.anchor(), stream, indent=2)
            print("Anchor exported. Retain it independently of the Pi to detect journal rollback.")
    finally:
        journal.close()
    return 0


def cmd_keygen(args: argparse.Namespace) -> int:
    import json
    import os
    from .keys import Keyring

    ring = Keyring.generate(args.kid, args.charger)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation prevents accidental overwrite of deployed secrets.
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(
            {"active_kid": args.kid, "keys": {args.kid: ring.active_key.hex()}, "owners": {args.kid: args.charger}},
            stream,
        )
    print(f"Private configuration created at {args.out}; key material was not printed.")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import asyncio
    from .network import run_service

    ring = load_keyring(args.keys)
    asyncio.run(
        run_service(
            args.role,
            ring,
            host=args.host,
            port=args.port,
            database=args.database,
            upstream=args.upstream,
            cert=args.cert,
            private_key=args.tls_key,
            ca=args.ca,
            client_ca=args.client_ca,
            client_cert=args.client_cert,
            client_key=args.client_key,
            outbox=args.outbox,
            capacity=args.capacity,
            max_connections=args.max_connections,
            response_timeout=args.response_timeout,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    _utf8_stdout()
    args = build_parser().parse_args(argv)
    if not hasattr(args, "write"):
        args.write = None
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
