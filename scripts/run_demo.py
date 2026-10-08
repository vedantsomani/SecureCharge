"""One command for local presentation: python scripts/run_demo.py."""

from __future__ import annotations
import argparse
from pathlib import Path
import subprocess
import sys


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-dashboard", action="store_true")
    args = parser.parse_args()
    for command in ("collision-lab", "demo", "network-demo"):
        subprocess.run([sys.executable, "-m", "securecharge", command], cwd=root, check=True)
    if not args.no_dashboard:
        return subprocess.call(
            [sys.executable, "-m", "streamlit", "run", "dashboard.py", "--server.address", "127.0.0.1"], cwd=root
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
