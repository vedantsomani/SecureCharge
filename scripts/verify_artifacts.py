"""Verify exported artifact integrity and source-code provenance."""

from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path


def verify(directory: Path, root: Path) -> list[str]:
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    failures = []
    for section, base in (("artifact_sha256", directory), ("source_sha256", root)):
        for name, expected in manifest[section].items():
            file = (base / name).resolve()
            if not file.is_relative_to(base.resolve()):
                failures.append(f"unsafe manifest path: {name}")
            elif not file.is_file() or hashlib.sha256(file.read_bytes()).hexdigest() != expected:
                failures.append(f"changed or missing: {name}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    failures = verify(args.directory, Path(__file__).resolve().parent.parent)
    if failures:
        print("\n".join(failures))
        return 1
    print("Artifact hashes and source provenance verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
