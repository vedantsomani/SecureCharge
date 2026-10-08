"""Reproducible experiments, raw observations, uncertainty and provenance.

Timings are host measurements, never Raspberry Pi estimates. The random seed
controls bootstrap resampling and algorithm order, not cryptographic nonces.
"""

from __future__ import annotations
import csv
import hashlib
import json
import platform
import random
import ssl
import sqlite3
import statistics
import time
import tracemalloc
from datetime import datetime, timezone
from importlib.metadata import version, PackageNotFoundError
from pathlib import Path
from typing import Any
from . import benchmark
from .backend import SecureCsms
from .clock import FakeClock
from .collision_lab import report as collision_report
from .gateway import MigrationGateway
from .keys import Keyring
from .legacy import add_legacy_integrity
from .messages import example_start, example_stop
from .scenarios import Lab, run_all
from .serialization import canonical_json
from .storage import Store


def environment() -> dict[str, Any]:
    model_path = Path("/proc/device-tree/model")
    model = model_path.read_bytes().decode("utf-8").strip("\x00") if model_path.exists() else "unavailable"
    packages = {}
    for package in (
        "ocpp",
        "jsonschema",
        "websockets",
        "cryptography",
        "matplotlib",
        "numpy",
        "streamlit",
        "pandas",
        "pytest",
        "hypothesis",
        "reportlab",
        "pymupdf",
    ):
        try:
            packages[package] = version(package)
        except PackageNotFoundError:
            packages[package] = "not-installed"
    return {
        "measured_at_utc": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "board_model": model,
        "openssl": ssl.OPENSSL_VERSION,
        "sqlite": sqlite3.sqlite_version,
        "packages": packages,
        "hardware_class": "raspberry-pi" if "Raspberry Pi" in model else "host-desktop-or-server",
    }


def _quantile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[round((len(ordered) - 1) * fraction)]


def summarize(values: list[float], seed: int) -> dict[str, Any]:
    rng = random.Random(seed)
    boot = [statistics.median(rng.choices(values, k=len(values))) for _ in range(1000)]
    return {
        "n": len(values),
        "median_ns": statistics.median(values),
        "p95_ns": _quantile(values, 0.95),
        "p99_ns": _quantile(values, 0.99),
        "median_ci95_ns": [_quantile(boot, 0.025), _quantile(boot, 0.975)],
        "min_ns": min(values),
        "max_ns": max(values),
    }


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _pipeline_sample(store: Store, gateway: MigrationGateway, backend: SecureCsms, index: int) -> dict[str, Any]:
    start = example_start(unique_id=f"research-start-{index}")
    before = time.perf_counter_ns()
    legacy = add_legacy_integrity(start)
    after_legacy = time.perf_counter_ns()
    signed = gateway.process(legacy.to_frame()).message
    after_sign = time.perf_counter_ns()
    wire = signed.to_bytes()
    after_encode = time.perf_counter_ns()
    verdict = backend.receive(wire)
    after_receive = time.perf_counter_ns()
    if not verdict.accepted:
        raise RuntimeError(f"research request failed: {verdict}")
    stop = example_stop(transaction_id=verdict.facts["transaction_id"], unique_id=f"research-stop-{index}")
    if not backend.receive(gateway.process(add_legacy_integrity(stop).to_frame()).message.to_bytes()).accepted:
        raise RuntimeError("research transaction did not close")
    return {
        "sample": index,
        "legacy_checksum_ns": after_legacy - before,
        "gateway_ns": after_sign - after_legacy,
        "wire_encoding_ns": after_encode - after_sign,
        "backend_ns": after_receive - after_encode,
        "total_ns": after_receive - before,
        "ocpp_bytes": len(canonical_json(start.to_frame())),
        "envelope_bytes": len(wire),
    }


def run(directory: str | Path, *, samples: int = 200, seed: int = 18, durable: bool = True) -> dict[str, Any]:
    if type(samples) is not int or not 20 <= samples <= 5000:
        raise ValueError("samples must be between 20 and 5000")
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    if (out / "pipeline.sqlite").exists():
        raise ValueError("choose a new output directory; existing experiment DB is never overwritten")
    env = environment()
    hash_rows = []
    rng = random.Random(seed)
    # Batch amortization reduces timer overhead. Randomized order reduces drift bias.
    for size in (256, 4096, 65536):
        data = bytes((i * 131 + 7) & 255 for i in range(size))
        for fn in benchmark.ALGORITHMS.values():
            for _ in range(20):
                fn(data)
        for sample in range(samples):
            names = list(benchmark.ALGORITHMS)
            rng.shuffle(names)
            for name in names:
                fn = benchmark.ALGORITHMS[name]
                started = time.perf_counter_ns()
                for _ in range(50):
                    fn(data)
                elapsed = (time.perf_counter_ns() - started) / 50
                hash_rows.append({"sample": sample, "algorithm": name, "size_bytes": size, "ns_per_op": elapsed})
    hash_summary = []
    for size in (256, 4096, 65536):
        for name in benchmark.ALGORITHMS:
            values = [r["ns_per_op"] for r in hash_rows if r["algorithm"] == name and r["size_bytes"] == size]
            hash_summary.append({"algorithm": name, "size_bytes": size, **summarize(values, seed)})
    keyring = Keyring.generate()
    clock = FakeClock(1_790_000_900)
    path = out / "pipeline.sqlite" if durable else ":memory:"
    store = Store(path)
    gateway, backend = MigrationGateway(keyring, clock=clock), SecureCsms(keyring, store, clock=clock)
    try:
        for i in range(10):
            _pipeline_sample(store, gateway, backend, -i - 1)
        pipeline = [_pipeline_sample(store, gateway, backend, i) for i in range(samples)]
        # Measure Python allocation separately; tracemalloc does NOT affect latency samples.
        tracemalloc.start()
        tracemalloc.reset_peak()
        _pipeline_sample(store, gateway, backend, samples + 1)
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    finally:
        store.close()
    scenarios = []
    for algorithm in ("md5", "sha1", "sha256", "sha3_256"):
        for r in run_all(Lab(algorithm=algorithm)):
            scenarios.append(
                {
                    "legacy_algorithm": algorithm,
                    "scenario": r.attack.value,
                    "legacy_applicable": r.legacy.applicable,
                    "legacy_accepted": r.legacy.accepted,
                    "legacy_reason": r.legacy.reason,
                    "legacy_fooled": r.legacy.fooled,
                    "secure_accepted": r.secure.accepted,
                    "secure_reason": r.secure.reason,
                    "secure_fooled": r.secure.fooled,
                }
            )
    from .network import loopback
    import asyncio

    result = {
        "artifact_version": "SC2-research-1",
        "seed": seed,
        "environment": env,
        "methods": {
            "samples": samples,
            "warmup": 20,
            "hash_batch_size": 50,
            "bootstrap_resamples": 1000,
            "ci": "percentile bootstrap of median; not an independent-host confidence interval",
            "pipeline_storage": "SQLite WAL file" if durable else "in-memory SQLite",
            "latency_scope": "StartTransaction: modeled checksum + gateway + wire encoding + backend/DB; Stop closes outside timer",
            "allocation_scope": "one extra start+stop; Python allocations only, not RSS or embedded flash",
        },
        "hash_summary": hash_summary,
        "pipeline_summary": {
            k: summarize([r[k] for r in pipeline], seed)
            for k in ("legacy_checksum_ns", "gateway_ns", "wire_encoding_ns", "backend_ns", "total_ns")
        },
        "message_overhead_bytes": pipeline[0]["envelope_bytes"] - pipeline[0]["ocpp_bytes"],
        "python_allocation_peak_bytes": peak,
        "collision": collision_report(),
        "network": asyncio.run(loopback()),
        "claims": {
            "new_cryptographic_primitive": False,
            "new_collision_generated": False,
            "real_vendor_vulnerability_discovered": False,
            "raspberry_pi_measured": "Raspberry Pi" in env["board_model"],
            "schema_valid_ocpp": True,
            "whole_json_collision": False,
        },
    }
    _write_csv(out / "hash_samples.csv", hash_rows)
    _write_csv(out / "pipeline_samples.csv", pipeline)
    _write_csv(out / "scenarios.csv", scenarios)
    (out / "results.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (out / "collision.json").write_text(json.dumps(result["collision"], indent=2), encoding="utf-8")
    from .collision import write_samples

    write_samples(out / "collision-inputs")
    _plots(out, result)
    median = result["pipeline_summary"]["total_ns"]["median_ns"] / 1e6
    p95 = result["pipeline_summary"]["total_ns"]["p95_ns"] / 1e6
    summary = f"""# Measured research results

Hardware class: **{env["hardware_class"]}**. Board: {env["board_model"]}.
Python {env["python"]}; {env["platform"]}. Measurement time: {env["measured_at_utc"]}.

{samples} observations per configuration; seed {seed}. Pipeline storage: {result["methods"]["pipeline_storage"]}.
Start request median **{median:.3f} ms**, p95 **{p95:.3f} ms**. Stop is outside this timer.
Envelope adds **{result["message_overhead_bytes"]} bytes** for this start message.
Python allocation peak for an additional start+stop: {peak} bytes (not RSS/firmware RAM).

All four unkeyed checksum baselines permit recomputation forgery. The collision
substitution uses an unchanged pinned MD5 of decoded MVR-128 records. Both OCPP
messages validate; their JSON digests are different. The SC2 tag rejects substitution.
Actual localhost WebSockets return standard OCPP responses; retry creates one bill.

No Pi hardware measurements are claimed unless board_model identifies a Pi.
This is a single-host experiment, not a deployment-scale or universal security proof.
See raw CSV files and results.json for methods, distributions and scope.
"""
    (out / "RESULTS.md").write_text(summary, encoding="utf-8")
    manifest = {}
    for file in sorted(out.rglob("*")):
        if file.is_file() and file.suffix not in (".sqlite", ".db"):
            manifest[str(file.relative_to(out)).replace("\\", "/")] = hashlib.sha256(file.read_bytes()).hexdigest()
    source = {}
    root = Path(__file__).resolve().parent.parent
    source_files = [
        *sorted((root / "securecharge").glob("*.py")),
        *sorted((root / "scripts").glob("*.py")),
        *sorted((root / "tests").glob("*.py")),
        root / "dashboard.py",
        root / "pyproject.toml",
        root / "requirements.txt",
        root / "requirements-dev.txt",
        root / "requirements-paper.txt",
    ]
    for file in source_files:
        source[str(file.relative_to(root)).replace("\\", "/")] = hashlib.sha256(file.read_bytes()).hexdigest()
    (out / "manifest.json").write_text(
        json.dumps({"artifact_sha256": manifest, "source_sha256": source}, indent=2), encoding="utf-8"
    )
    return result


def _plots(out: Path, result: dict[str, Any]) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    rows = [r for r in result["hash_summary"] if r["size_bytes"] == 256]
    fig, ax = plt.subplots(figsize=(9, 4.5), layout="constrained")
    values = [r["median_ns"] / 1000 for r in rows]
    lo = [(r["median_ns"] - r["median_ci95_ns"][0]) / 1000 for r in rows]
    hi = [(r["median_ci95_ns"][1] - r["median_ns"]) / 1000 for r in rows]
    ax.barh([r["algorithm"] for r in rows], values, xerr=[lo, hi], color="#0d9488")
    ax.set_xlabel("Median microseconds per operation (95% bootstrap interval)")
    ax.set_title("256-byte hash/MAC measurements on the recorded host")
    for suffix in ("svg", "png"):
        fig.savefig(out / f"hash_latency.{suffix}", dpi=180)
    plt.close(fig)
    fig, ax = plt.subplots(figsize=(8, 4.5), layout="constrained")
    pipeline = result["pipeline_summary"]
    labels = ["legacy_checksum_ns", "gateway_ns", "wire_encoding_ns", "backend_ns"]
    ax.bar(
        ["Checksum", "Gateway", "Wire encoding", "Backend + SQLite"],
        [pipeline[k]["median_ns"] / 1e6 for k in labels],
        color=["#64748b", "#0d9488", "#0891b2", "#2563eb"],
    )
    ax.set_ylabel("Median milliseconds")
    ax.set_title("Measured request stages (component medians need not sum to total median)")
    for suffix in ("svg", "png"):
        fig.savefig(out / f"pipeline_latency.{suffix}", dpi=180)
    plt.close(fig)
