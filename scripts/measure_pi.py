"""Collect real Pi measurements; refuses to label a desktop as Raspberry Pi."""

from __future__ import annotations
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from securecharge.research import environment, run


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=500)
    args = parser.parse_args()
    if environment()["hardware_class"] != "raspberry-pi":
        parser.error("no Raspberry Pi board detected; use python -m securecharge research for host measurements")
    result = run(args.out, samples=args.samples)
    print(result["environment"]["board_model"])
    print(f"Measured results saved to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
